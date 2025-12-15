"""
Odysafe CTI Platform
Copyright (C) 2025 Bastien GUIDONE

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
import os
import tempfile
import logging
from pathlib import Path
from typing import List, Tuple, Optional
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


def extract_iocs(file_path: str, target_types: Optional[List[str]] = None) -> List[Tuple[str, str, str, int]]:
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

    results = []
    
    try:
        # Open document
        doc = open_document(file_path)
        if doc is None:
            raise ValueError(f"Unsupported file type: {file_path}")

        # Extract text
        text, _ = doc.get_text()
        if not text:
            raise ValueError(f"Unable to extract text from file: {file_path}")

        # Create searcher
        searcher = Searcher()
        
        # Set targets if specified
        targets = set(target_types) if target_types else None

        # Search all matches (with offsets)
        matches = searcher.search_raw(text, targets=targets)
        
        # Format results
        for match in matches:
            ioc_type, ioc_value, offset, raw_value = match
            results.append((ioc_type, ioc_value, raw_value or ioc_value, offset))

        logger.info(f"Extraction successful: {len(results)} IOCs found in {file_path}")

    except Exception as e:
        logger.error(f"IOC extraction error: {str(e)}")
        raise

    return results


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
    
    results = []
    try:
        # Create searcher
        searcher = Searcher()
        
        # Set targets if specified
        targets = set(target_types) if target_types else None
        
        # Search all matches (with offsets)
        matches = searcher.search_raw(chunk_text, targets=targets)
        
        # Format results and adjust offsets
        for match in matches:
            ioc_type, ioc_value, offset, raw_value = match
            # Adjust offset to account for chunk position in original text
            adjusted_offset = chunk_offset + offset
            results.append((ioc_type, ioc_value, raw_value or ioc_value, adjusted_offset))
    except Exception as e:
        logger.error(f"Error extracting from chunk: {str(e)}")
        raise
    
    return results


def extract_from_text(text_content: str, target_types: Optional[List[str]] = None, 
                     use_multithreading: bool = True, num_threads: Optional[int] = None) -> List[Tuple[str, str, str, int]]:
    """
    Extracts IOCs from text (paste)
    Uses multi-threading for large texts to improve performance
    
    Args:
        text_content: Text content to analyze
        target_types: List of IOC types to extract (None = all)
        use_multithreading: Whether to use multi-threading (default: True)
        num_threads: Number of threads to use (default: min(4, CPU count))
    
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
        num_threads = min(4, multiprocessing.cpu_count())
    
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


def extract_from_url(url: str, target_types: Optional[List[str]] = None) -> List[Tuple[str, str, str, int]]:
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
        # Download content
        response = requests.get(url, timeout=30, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        
        # Determine content type
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Create temporary file
        if 'html' in content_type:
            suffix = '.html'
        elif 'pdf' in content_type:
            suffix = '.pdf'
        else:
            suffix = '.txt'
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix=suffix, delete=False) as f:
            f.write(response.content)
            temp_file = f.name

        # Extract IOCs
        results = extract_iocs(temp_file, target_types=target_types)

    except requests.RequestException as e:
        logger.error(f"Error downloading URL {url}: {str(e)}")
        raise RuntimeError(f"Unable to download URL: {str(e)}")
    finally:
        # Delete temporary file
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except Exception as e:
                logger.warning(f"Unable to delete temporary file {temp_file}: {e}")

    return results


def get_supported_ioc_types() -> List[str]:
    """
    Returns list of IOC types supported by iocsearcher
    """
    if not IOCSEARCHER_AVAILABLE:
        return []

    # Main types supported by iocsearcher
    return [
        'url', 'fqdn', 'ip4', 'ip6', 'ip4Net',
        'md5', 'sha1', 'sha256',
        'email', 'phoneNumber',
        'bitcoin', 'ethereum', 'monero', 'litecoin', 'ripple', 'solana',
        'cve', 'onionAddress',
        'facebookHandle', 'twitterHandle', 'githubHandle',
        'ttp', 'arn', 'uuid', 'packageName'
    ]


def get_iocsearcher_status() -> dict:
    """
    Returns status information about iocsearcher availability and source

    Returns:
        dict: Status information with keys 'available', 'source', 'version'
    """
    status = {
        'available': IOCSEARCHER_AVAILABLE,
        'source': IOCSEARCHER_SOURCE,
        'version': None
    }

    if IOCSEARCHER_AVAILABLE:
        try:
            # Try to get version from the searcher module
            if hasattr(Searcher, '__version__'):
                status['version'] = Searcher.__version__
            else:
                # Try to get version from package metadata
                try:
                    import pkg_resources
                    status['version'] = pkg_resources.get_distribution('iocsearcher').version
                except:
                    status['version'] = 'unknown'
        except Exception as e:
            logger.debug(f"Could not determine iocsearcher version: {e}")
            status['version'] = 'unknown'

    return status

