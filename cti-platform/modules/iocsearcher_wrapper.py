"""
Odysafe CTI Platform
Copyright (C) 2026 ODYSAFE CTI Project

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Wrapper pour l'intégration d'iocsearcher
"""
import http.client
import ipaddress
import socket
import time
import os
import tempfile
import logging
from urllib.parse import quote, urljoin, urlsplit
from pathlib import Path
from typing import Any, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Import iocsearcher from pip installation only
IOCSEARCHER_AVAILABLE = False
IOCSEARCHER_SOURCE = None

try:
    from iocsearcher.searcher import Searcher
    from iocsearcher.document import open_document
    IOCSEARCHER_AVAILABLE = True
    IOCSEARCHER_SOURCE = "pip"
    logger.info("Using iocsearcher from pip installation")
except ImportError:
    logger.error("iocsearcher is not available. Please install it via pip: pip install iocsearcher")
    IOCSEARCHER_AVAILABLE = False
    IOCSEARCHER_SOURCE = None


def _extract_matches(
    text: str, target_types: Optional[List[str]], offset: int = 0
) -> List[Tuple[str, str, str, int]]:
    targets = set(target_types) if target_types else None
    return [
        (match.name, match.value, match.raw_value or match.value, offset + match.start_offset)
        for match in Searcher().search_matches(text, targets=targets)
    ]


def read_document_text(file_path: str) -> Optional[str]:
    doc = open_document(file_path)
    if doc is None:
        raise ValueError(f"Unsupported file type: {file_path}")
    # The Word reader expects an options mapping, even for its defaults.
    text, _ = doc.get_text(options={} if doc.is_word else None)
    return text


def extract_iocs(
    file_path: str,
    target_types: Optional[List[str]] = None,
    include_text: bool = False,
) -> Any:
    """
    Extracts IOCs from a file via iocsearcher
    
    Args:
        file_path: Path to file to analyze
        target_types: List of IOC types to extract (None = all)
    
    Returns:
        List of tuples (ioc_type, ioc_value, raw_value, offset)
    """
    if not IOCSEARCHER_AVAILABLE:
        raise RuntimeError("iocsearcher is not available. Please install it.")

    try:
        text = read_document_text(file_path)
        if not text:
            raise ValueError(f"Unable to extract text from file: {file_path}")

        results = _extract_matches(text, target_types)

        logger.info(f"Extraction successful: {len(results)} IOCs found in {file_path}")

    except Exception as e:
        logger.error(f"IOC extraction error: {str(e)}")
        raise

    return (results, text) if include_text else results


def _extract_chunk(chunk_text: str, chunk_offset: int, target_types: Optional[List[str]] = None) -> List[Tuple[str, str, str, int]]:
    """
    Extracts IOCs from a text chunk (helper for parallel processing)
    
    Args:
        chunk_text: Text chunk to analyze
        chunk_offset: Offset of this chunk in the original text
        target_types: List of IOC types to extract (None = all)
    
    Returns:
        List of tuples (ioc_type, ioc_value, raw_value, adjusted_offset)
    """
    if not IOCSEARCHER_AVAILABLE:
        raise RuntimeError("iocsearcher is not available. Please install it.")
    
    return _extract_matches(chunk_text, target_types, offset=chunk_offset)


def extract_from_text(text_content: str, target_types: Optional[List[str]] = None, 
                     use_multithreading: bool = True, num_threads: Optional[int] = None) -> List[Tuple[str, str, str, int]]:
    """
    Extracts IOCs from text (paste)
    Uses multi-threading for large texts to improve performance
    
    Args:
        text_content: Text content to analyze
        target_types: List of IOC types to extract (None = all)
        use_multithreading: Whether to use multi-threading (default: True)
        num_threads: Number of threads to use (default: at most two CPUs)
    
    Returns:
        List of tuples (ioc_type, ioc_value, raw_value, offset)
    """
    if not IOCSEARCHER_AVAILABLE:
        raise RuntimeError("iocsearcher is not available. Please install it.")

    # For small texts, use single-threaded approach (overhead not worth it)
    text_length = len(text_content)
    min_chunk_size = 50000  # 50KB minimum per chunk for multi-threading
    
    if not use_multithreading or text_length < min_chunk_size:
        # Use original single-threaded approach for small texts
        temp_file = None
        try:
            # Create temporary file with .txt suffix
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
                f.write(text_content)
                temp_file = f.name

            # Extract IOCs
            results = extract_iocs(temp_file, target_types=target_types)

        finally:
            # Delete temporary file
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except Exception as e:
                    logger.warning(f"Unable to delete temporary file {temp_file}: {e}")

        return results
    
    # Multi-threaded approach for large texts
    if num_threads is None:
        import multiprocessing
        num_threads = min(2, multiprocessing.cpu_count())
    
    # Calculate chunk size (aim for ~100KB chunks, but at least min_chunk_size)
    chunk_size = max(min_chunk_size, text_length // num_threads)
    
    # Split text into overlapping chunks to avoid missing IOCs at boundaries
    # Use 1000 character overlap to ensure we don't miss IOCs that span chunk boundaries
    overlap = 1000
    chunks = []
    offset = 0
    
    while offset < text_length:
        end = min(offset + chunk_size, text_length)
        chunk_text = text_content[offset:end]
        chunks.append((chunk_text, offset))
        offset = end - overlap if end < text_length else end
    
    logger.info(f"Processing {len(chunks)} chunks with {num_threads} threads")
    
    # Process chunks in parallel
    all_results = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit all chunks
        future_to_chunk = {
            executor.submit(_extract_chunk, chunk_text, chunk_offset, target_types): (chunk_offset, chunk_text)
            for chunk_text, chunk_offset in chunks
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_chunk):
            chunk_offset, chunk_text = future_to_chunk[future]
            try:
                chunk_results = future.result()
                all_results.extend(chunk_results)
            except Exception as e:
                logger.error(f"Error processing chunk at offset {chunk_offset}: {str(e)}")
                # Continue with other chunks even if one fails
    
    # Remove duplicates (same IOC at same offset)
    seen = set()
    unique_results = []
    for result in all_results:
        ioc_type, ioc_value, raw_value, offset = result
        key = (ioc_type, ioc_value, offset)
        if key not in seen:
            seen.add(key)
            unique_results.append(result)
    
    logger.info(f"Extraction successful: {len(unique_results)} unique IOCs found (from {len(all_results)} total matches)")
    
    return unique_results


def _download_public_report(url, output):
    """Fetch only public HTTP(S) URLs and validate every redirect."""
    max_bytes = 25 * 1024 * 1024
    deadline = time.monotonic() + 60
    for _ in range(6):
        parts = urlsplit(url)
        if (parts.scheme not in ('http', 'https') or not parts.hostname
                or parts.username is not None or parts.password is not None):
            raise ValueError('Enter a public HTTP or HTTPS URL.')
        port = 443 if parts.scheme == 'https' else 80
        if parts.port not in (None, port):
            raise ValueError('Enter a public HTTP or HTTPS URL.')
        host = parts.hostname.encode('idna').decode('ascii')
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        for _, _, _, _, address in addresses:
            ip = ipaddress.ip_address(address[0])
            if (not ip.is_global or ip.is_multicast
                    or (ip.version == 6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo
                                            or ip in ipaddress.ip_network('64:ff9b::/96')))):
                raise ValueError('Only public Internet addresses are allowed.')

        # Connect to an address already checked, while preserving the Host header
        # and TLS verification against the original hostname.
        def connect_public(_address, timeout, source_address):
            for family, kind, protocol, _, endpoint in addresses:
                connection = socket.socket(family, kind, protocol)
                try:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('Report download timed out.')
                    connection.settimeout(min(timeout, remaining))
                    connection.connect(endpoint)
                    return connection
                except OSError:
                    connection.close()
            raise OSError('Unable to connect to the report server.')

        connection_type = http.client.HTTPSConnection if parts.scheme == 'https' else http.client.HTTPConnection
        connection = connection_type(host, port, timeout=10)
        connection._create_connection = connect_public
        try:
            path = quote(parts.path or '/', safe="/%:@!$&'()*+,;=-._~")
            if parts.query:
                path += '?' + quote(parts.query, safe="/?%:@!$&'()*+,;=-._~")
            connection.request('GET', path, headers={'User-Agent': 'Mozilla/5.0', 'Accept-Encoding': 'identity'})
            with connection.getresponse() as response:
                if response.status in (301, 302, 303, 307, 308) and response.getheader('Location'):
                    url = urljoin(url, response.getheader('Location'))
                    continue
                if not 200 <= response.status < 300:
                    raise ValueError(f'Report server returned HTTP {response.status}.')
                if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
                    raise ValueError('Unsupported report compression.')
                while chunk := response.read1(65536):
                    if time.monotonic() > deadline:
                        raise TimeoutError('Report download timed out.')
                    if output.tell() + len(chunk) > max_bytes:
                        raise ValueError('Remote report exceeds 25 MiB.')
                    output.write(chunk)
                return response.getheader('Content-Type', '').lower()
        finally:
            connection.close()
    raise ValueError('Too many redirects while downloading the report.')


def extract_from_url(
    url: str,
    target_types: Optional[List[str]] = None,
    include_text: bool = False,
) -> Any:
    """
    Downloads URL content and extracts IOCs
    
    Args:
        url: URL to download
        target_types: List of IOC types to extract (None = all)
    
    Returns:
        List of tuples (ioc_type, ioc_value, raw_value, offset)
    """
    import requests
    from io import BytesIO
    
    if not IOCSEARCHER_AVAILABLE:
        raise RuntimeError("iocsearcher is not available. Please install it.")

    temp_file = None
    try:
        with tempfile.TemporaryFile() as download:
            content_type = _download_public_report(url, download)
            suffix = '.html' if 'html' in content_type else '.pdf' if 'pdf' in content_type else '.txt'
            download.seek(0)
            with tempfile.NamedTemporaryFile(mode='wb', suffix=suffix, delete=False) as f:
                temp_file = f.name
                while chunk := download.read(65536):
                    f.write(chunk)

        # Extract IOCs
        extraction = extract_iocs(
            temp_file,
            target_types=target_types,
            include_text=include_text,
        )

    except (OSError, http.client.HTTPException) as exc:
        raise RuntimeError("Unable to download the remote report.") from exc
    finally:
        # Delete temporary file
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except Exception as e:
                logger.warning(f"Unable to delete temporary file {temp_file}: {e}")

    return extraction

