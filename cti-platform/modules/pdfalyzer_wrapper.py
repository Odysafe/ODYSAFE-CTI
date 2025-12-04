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

Wrapper for pdfalyzer integration
"""
import json
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    from pdfalyzer.pdfalyzer import Pdfalyzer
    from pdfalyzer.detection.yaralyzer_helper import get_file_yaralyzer, get_bytes_yaralyzer
    from pdfalyzer.output.pdfalyzer_presenter import PdfalyzerPresenter
    from pdfalyzer.util.adobe_strings import JAVASCRIPT, OPEN_ACTION, ACRO_FORM, FONT_FILE
    from pdfalyzer.util.exceptions import PdfWalkError
    from anytree.search import findall_by_attr
    PDFALYZER_AVAILABLE = True
    PdfalyzerType = Pdfalyzer  # Type hint
except ImportError as e:
    logger.warning(f"pdfalyzer not available: {e}")
    PDFALYZER_AVAILABLE = False
    Pdfalyzer = None  # type: ignore
    PdfWalkError = Exception  # Fallback for type checking
    PdfalyzerType = Any
    findall_by_attr = None  # type: ignore


def analyze_pdf(pdf_path: str, options: Optional[Dict[str, bool]] = None, pdfalyzer_instance: Optional[Any] = None) -> Dict[str, Any]:
    """
    Complete PDF analysis
    
    Args:
        pdf_path: Path to PDF file
        options: Analysis options dict with keys:
            - detect_suspicious: Detect suspicious PDFs
            - extract_iocs: Extract IOCs from PDF
            - generate_structure: Generate PDF structure visualization
            - analyze_fonts: Analyze embedded fonts
            - scan_yara: Run YARA scan
            - search_patterns: Search for binary patterns
        pdfalyzer_instance: Optional existing Pdfalyzer instance to reuse
    
    Returns:
        Dict with analysis results
    """
    if not PDFALYZER_AVAILABLE:
        raise RuntimeError("pdfalyzer is not available. Please install it.")
    
    if options is None:
        options = {
            'detect_suspicious': True,
            'extract_iocs': True,
            'generate_structure': True,
            'analyze_fonts': True,
            'scan_yara': True,
            'search_patterns': False,
            'generate_summary': True,
            'analyze_streams': False,
            'detailed_yara': False
        }
    
    results = {
        'is_suspicious': False,
        'suspicious_reasons': [],
        'yara_matches': [],
        'font_analysis': [],
        'pdf_structure_file': None,
        'binary_patterns': [],
        'modification_history': {},
        'analysis_metadata': {},
        'extracted_iocs': [],
        'pdf_summary': {},
        'streams_analysis': [],
        'yara_detailed': {}
    }
    
    try:
        # Initialize pdfalyzer if not provided
        if pdfalyzer_instance is None:
            pdfalyzer = Pdfalyzer(pdf_path)
        else:
            pdfalyzer = pdfalyzer_instance
        
        # Store metadata
        results['analysis_metadata'] = {
            'pdf_size': pdfalyzer.pdf_size,
            'max_generation': pdfalyzer.max_generation,
            'file_size': len(pdfalyzer.pdf_bytes),
            'hashes': {
                'md5': pdfalyzer.pdf_bytes_info.md5,
                'sha1': pdfalyzer.pdf_bytes_info.sha1,
                'sha256': pdfalyzer.pdf_bytes_info.sha256
            }
        }
        
        # Detect suspicious PDF
        if options.get('detect_suspicious', True):
            is_suspicious, reasons = detect_suspicious_pdf(pdfalyzer)
            results['is_suspicious'] = is_suspicious
            results['suspicious_reasons'] = reasons
        
        # Scan YARA
        if options.get('scan_yara', True):
            results['yara_matches'] = scan_yara(pdf_path)
        
        # Analyze fonts
        if options.get('analyze_fonts', True):
            results['font_analysis'] = analyze_fonts(pdfalyzer)
        
        # Detect modifications
        results['modification_history'] = detect_modifications(pdfalyzer)
        
        # PDF Node Summary (function 1)
        if options.get('generate_summary', True):
            results['pdf_summary'] = get_pdf_summary(pdfalyzer)
        
        # Streams analysis (function 2)
        if options.get('analyze_streams', False):
            results['streams_analysis'] = analyze_streams(pdfalyzer)
        
        # Enhanced YARA results (function 3)
        if options.get('scan_yara', True):
            results['yara_matches'] = scan_yara(pdf_path)
            # Also get detailed YARA results if available
            if options.get('detailed_yara', False):
                results['yara_detailed'] = get_detailed_yara_results(pdfalyzer)
        
        # Extract IOCs
        if options.get('extract_iocs', True):
            results['extracted_iocs'] = extract_pdf_iocs(pdfalyzer)
        
        # Generate structure (if requested)
        if options.get('generate_structure', True):
            # Will be generated later with output_dir
            pass
        
    except PdfWalkError as e:
        # PDF structure parsing error - PDF may be malformed or corrupted
        logger.warning(f"PDF structure parsing error (PdfWalkError): {e}")
        logger.info("Attempting partial analysis without full PDF tree...")
        
        # Mark as suspicious
        results['is_suspicious'] = True
        results['suspicious_reasons'] = ["PDF structure parsing error - PDF may be malformed or corrupted"]
        
        # Try to extract basic metadata from file
        try:
            import hashlib
            from pathlib import Path as PathLib
            
            pdf_file = PathLib(pdf_path)
            if pdf_file.exists():
                file_size = pdf_file.stat().st_size
                with open(pdf_path, 'rb') as f:
                    pdf_bytes = f.read()
                    
                results['analysis_metadata'] = {
                    'file_size': file_size,
                    'hashes': {
                        'md5': hashlib.md5(pdf_bytes).hexdigest(),
                        'sha1': hashlib.sha1(pdf_bytes).hexdigest(),
                        'sha256': hashlib.sha256(pdf_bytes).hexdigest()
                    },
                    'pdf_size': None,
                    'max_generation': None
                }
        except Exception as meta_error:
            logger.warning(f"Could not extract metadata: {meta_error}")
        
        # Try YARA scan on raw file (doesn't require PDF tree)
        if options.get('scan_yara', True):
            try:
                results['yara_matches'] = scan_yara(pdf_path)
            except Exception as yara_error:
                logger.warning(f"YARA scan failed: {yara_error}")
        
        # Set empty values for analyses that require PDF tree
        results['font_analysis'] = []
        results['modification_history'] = {
            'has_modifications': False,
            'max_generation': None,
            'total_objects': None,
            'generations': {}
        }
        results['extracted_iocs'] = []
        results['pdf_structure_file'] = None
        results['pdf_summary'] = {}
        results['streams_analysis'] = []
        results['yara_detailed'] = {}
        
        # Don't raise - return partial analysis
        logger.info("Returning partial analysis due to PDF structure parsing error")
        
    except Exception as e:
        logger.error(f"PDF analysis error: {e}", exc_info=True)
        raise
    
    return results


def detect_suspicious_pdf(pdfalyzer: Any) -> Tuple[bool, List[str]]:
    """
    Detect suspicious/malicious PDF indicators
    
    Args:
        pdfalyzer: Pdfalyzer instance
    
    Returns:
        Tuple of (is_suspicious, list_of_reasons)
    """
    if not PDFALYZER_AVAILABLE or findall_by_attr is None:
        return False, []
    
    reasons = []
    
    try:
        # Check for JavaScript
        js_nodes = findall_by_attr(pdfalyzer.pdf_tree, name='type', value=JAVASCRIPT)
        if js_nodes:
            reasons.append(f"JavaScript detected ({len(js_nodes)} node(s))")
        
        # Check for OpenAction
        open_action_nodes = findall_by_attr(pdfalyzer.pdf_tree, name='type', value=OPEN_ACTION)
        if open_action_nodes:
            reasons.append(f"OpenAction detected ({len(open_action_nodes)} node(s))")
        
        # Check for AcroForm
        acroform_nodes = findall_by_attr(pdfalyzer.pdf_tree, name='type', value=ACRO_FORM)
        if acroform_nodes:
            reasons.append(f"AcroForm detected ({len(acroform_nodes)} node(s))")
        
        # Check for suspicious fonts (Type1/Type2)
        suspicious_fonts = []
        for font_info in pdfalyzer.font_infos:
            if font_info.sub_type and ('Type1' in str(font_info.sub_type) or 'Type2' in str(font_info.sub_type)):
                suspicious_fonts.append(font_info.label)
        
        if suspicious_fonts:
            reasons.append(f"Suspicious fonts detected (Type1/Type2): {', '.join(suspicious_fonts)}")
        
        # Check YARA matches (basic check)
        try:
            yaralyzer = get_file_yaralyzer(pdfalyzer.pdf_path)
            matches = yaralyzer.scan()
            if matches:
                reasons.append(f"YARA rules matched ({len(matches)} match(es))")
        except Exception as e:
            logger.warning(f"YARA scan error in suspicious detection: {e}")
        
    except Exception as e:
        logger.error(f"Error detecting suspicious PDF: {e}")
    
    is_suspicious = len(reasons) > 0
    return is_suspicious, reasons


def extract_pdf_iocs(pdfalyzer: Any) -> List[Tuple[str, str, str, int]]:
    """
    Extract IOCs from PDF streams using iocsearcher
    
    Args:
        pdfalyzer: Pdfalyzer instance
    
    Returns:
        List of tuples (ioc_type, ioc_value, raw_value, offset)
    """
    from modules.iocsearcher_wrapper import extract_from_text, IOCSEARCHER_AVAILABLE
    
    if not IOCSEARCHER_AVAILABLE:
        logger.warning("iocsearcher not available for IOC extraction from PDF")
        return []
    
    all_iocs = []
    
    try:
        # Extract text from all stream nodes
        for stream_node in pdfalyzer.stream_nodes():
            if stream_node.contains_stream() and hasattr(stream_node, 'stream_data'):
                try:
                    stream_data = stream_node.stream_data
                    if stream_data and isinstance(stream_data, bytes) and len(stream_data) > 0:
                        # Try to decode as text
                        try:
                            text = stream_data.decode('utf-8', errors='ignore')
                        except:
                            try:
                                text = stream_data.decode('latin-1', errors='ignore')
                            except:
                                text = ''
                        
                        if text:
                            # Extract IOCs from this stream
                            stream_iocs = extract_from_text(text, use_multithreading=False)
                            all_iocs.extend(stream_iocs)
                except Exception as e:
                    logger.debug(f"Error extracting from stream node {stream_node.idnum}: {e}")
        
        # Also extract from font binaries
        for font_info in pdfalyzer.font_infos:
            if hasattr(font_info, 'binary_scanner') and font_info.binary_scanner:
                try:
                    # Extract backtick-quoted strings from font binary
                    # extract_backtick_quoted_bytes returns Iterator[Tuple[BytesMatch, BytesDecoder]]
                    for bytes_match, bytes_decoder in font_info.binary_scanner.extract_backtick_quoted_bytes():
                        try:
                            # Get the matched bytes - BytesMatch has a 'data' attribute
                            matched_bytes = bytes_match.data if hasattr(bytes_match, 'data') else None
                            if matched_bytes and isinstance(matched_bytes, bytes):
                                text = matched_bytes.decode('utf-8', errors='ignore')
                                if text:
                                    font_iocs = extract_from_text(text, use_multithreading=False)
                                    all_iocs.extend(font_iocs)
                        except Exception as e:
                            logger.debug(f"Error decoding quoted bytes from font {font_info.label}: {e}")
                except Exception as e:
                    logger.debug(f"Error extracting from font {font_info.label}: {e}")
        
        # Remove duplicates (same IOC type and value)
        seen = set()
        unique_iocs = []
        for ioc in all_iocs:
            ioc_type, ioc_value, raw_value, offset = ioc
            key = (ioc_type, ioc_value.lower())
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        
        logger.info(f"Extracted {len(unique_iocs)} unique IOCs from PDF")
        return unique_iocs
        
    except Exception as e:
        logger.error(f"Error extracting IOCs from PDF: {e}")
        return []


def generate_pdf_structure(pdfalyzer: Any, output_dir: Path, format_type: str = 'html') -> Optional[Path]:
    """
    Generate PDF structure visualization in specified format (SVG, HTML, or TXT)
    
    Args:
        pdfalyzer: Pdfalyzer instance
        output_dir: Directory to save output
        format_type: Format to generate ('svg', 'html', or 'txt') - default 'html'
    
    Returns:
        Path to generated file or None
    """
    if not PDFALYZER_AVAILABLE:
        return None
    
    format_type = format_type.lower()
    if format_type not in ['svg', 'html', 'txt']:
        logger.warning(f"Invalid format type '{format_type}', defaulting to 'html'")
        format_type = 'html'
    
    try:
        # Use the global console from yaralyzer (same as pdfalyzer does)
        from yaralyzer.output.rich_console import console
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save original record state
        original_record = console.record
        
        try:
            # Enable recording (same method as pdfalyzer uses in __init__.py line 62)
            console.record = True
            
            # Create presenter (same as pdfalyzer does in __init__.py line 46)
            presenter = PdfalyzerPresenter(pdfalyzer)
            
            # Call methods individually (like pdfalyzer does via output_sections)
            # Do NOT call print_everything() as it includes print_non_tree_relationships()
            # which causes MarkupError with nodes containing [/Cs1] etc.
            logger.debug(f"Calling presenter methods individually to generate PDF structure in {format_type.upper()} format")
            
            # Call document info (optional, like pdfalyzer's --docinfo)
            try:
                presenter.print_document_info()
            except Exception as e:
                logger.debug(f"Error in print_document_info: {e}")
            
            # Call tree view (like pdfalyzer's --tree)
            try:
                presenter.print_tree()
            except Exception as e:
                logger.warning(f"Error in print_tree: {e}")
            
            # Call rich table tree (like pdfalyzer's --rich)
            try:
                presenter.print_rich_table_tree()
            except Exception as e:
                logger.warning(f"Error in print_rich_table_tree: {e}")
            
            # Do NOT call:
            # - presenter.print_non_tree_relationships() - causes MarkupError
            # - presenter.print_font_info() - not needed for structure
            # - presenter.print_summary() - not needed for structure
            
            # Generate file in requested format (like pdfalyzer does)
            output_file = output_dir / f"pdf_structure_{pdfalyzer.pdf_basename}.{format_type}"
            
            # Save in requested format (same as pdfalyzer does in __init__.py lines 67, 70, 73)
            if format_type == 'txt':
                logger.debug(f"Saving TXT to {output_file}")
                console.save_text(str(output_file))
            elif format_type == 'html':
                logger.debug(f"Saving HTML to {output_file}")
                console.save_html(str(output_file))
            elif format_type == 'svg':
                logger.debug(f"Saving SVG to {output_file}")
                console.save_svg(str(output_file))
            
            # Clear buffer (same as pdfalyzer does in __init__.py line 77)
            if hasattr(console, '_record_buffer'):
                del console._record_buffer[:]
            
            # Verify file was created and has content
            if output_file.exists():
                file_size = output_file.stat().st_size
                logger.debug(f"PDF structure {format_type.upper()} file created: {output_file} ({file_size} bytes)")
                
                min_size = 500 if format_type == 'svg' else 1000
                if file_size > min_size:
                    logger.info(f"PDF structure {format_type.upper()} saved successfully to {output_file} ({file_size} bytes)")
                    return output_file
                else:
                    logger.warning(f"PDF structure {format_type.upper()} file too small ({file_size} bytes, expected >{min_size} bytes)")
                    return None
            else:
                logger.error(f"PDF structure {format_type.upper()} file was not created: {output_file}")
                return None
                
        finally:
            # Restore original record state
            console.record = original_record
        
    except Exception as e:
        logger.error(f"Error generating PDF structure: {e}", exc_info=True)
        return None


def analyze_fonts(pdfalyzer: Any) -> List[Dict[str, Any]]:
    """
    Analyze embedded fonts in PDF
    
    Args:
        pdfalyzer: Pdfalyzer instance
    
    Returns:
        List of font analysis dicts
    """
    fonts_data = []
    
    try:
        for font_info in pdfalyzer.font_infos:
            font_data = {
                'id': font_info.idnum,
                'label': font_info.label,
                'sub_type': str(font_info.sub_type) if font_info.sub_type else None,
                'base_font': font_info.base_font,
                'first_char': font_info.first_and_last_char[0] if font_info.first_and_last_char else None,
                'last_char': font_info.first_and_last_char[1] if font_info.first_and_last_char else None,
                'bounding_box': font_info.bounding_box,
                'flags': font_info.flags,
                'has_binary_scanner': font_info.binary_scanner is not None,
                'stream_length': font_info.binary_scanner.stream_length if font_info.binary_scanner else 0,
                'is_suspicious': False
            }
            
            # Mark as suspicious if Type1/Type2
            if font_info.sub_type and ('Type1' in str(font_info.sub_type) or 'Type2' in str(font_info.sub_type)):
                font_data['is_suspicious'] = True
            
            fonts_data.append(font_data)
        
    except Exception as e:
        logger.error(f"Error analyzing fonts: {e}")
    
    return fonts_data


def get_pdf_summary(pdfalyzer: Any) -> Dict[str, Any]:
    """
    Get PDF Node Summary (function 1 - like print_summary)
    
    Args:
        pdfalyzer: Pdfalyzer instance
    
    Returns:
        Dict with PDF statistics (node counts, types, keys)
    """
    try:
        pdf_object_types = defaultdict(int)
        node_labels = defaultdict(int)
        keys_encountered = defaultdict(int)
        node_count = 0
        
        for node in pdfalyzer.node_iterator():
            pdf_object_types[type(node.obj).__name__] += 1
            node_labels[node.label] += 1
            node_count += 1
            
            if isinstance(node.obj, dict):
                for k in node.obj.keys():
                    keys_encountered[k] += 1
        
        return {
            'node_count': node_count,
            'pdf_object_types': dict(pdf_object_types),
            'node_labels': dict(node_labels),
            'keys_encountered': dict(keys_encountered),
            'total_streams': len(list(pdfalyzer.stream_nodes())),
            'total_fonts': len(pdfalyzer.font_infos)
        }
    except Exception as e:
        logger.error(f"Error getting PDF summary: {e}")
        return {}


def analyze_streams(pdfalyzer: Any) -> List[Dict[str, Any]]:
    """
    Analyze binary streams in PDF (function 2 - like print_streams_analysis)
    
    Args:
        pdfalyzer: Pdfalyzer instance
    
    Returns:
        List of stream analysis dicts
    """
    streams_data = []
    
    try:
        from pdfalyzer.binary.binary_scanner import BinaryScanner
        from pdfalyzer.decorators.pdf_tree_node import DECODE_FAILURE_LEN
        
        for node in pdfalyzer.stream_nodes():
            if node.stream_length == DECODE_FAILURE_LEN:
                streams_data.append({
                    'node_id': node.idnum,
                    'label': str(node),
                    'status': 'decode_failure',
                    'stream_length': 0
                })
                continue
            
            if node.stream_length == 0 or node.stream_data is None:
                streams_data.append({
                    'node_id': node.idnum,
                    'label': str(node),
                    'status': 'empty',
                    'stream_length': 0
                })
                continue
            
            node_stream_bytes = node.stream_data
            if not isinstance(node_stream_bytes, bytes):
                node_stream_bytes = node_stream_bytes.encode()
            
            try:
                binary_scanner = BinaryScanner(node_stream_bytes, node)
                
                # Get hashes
                hashes = {
                    'md5': binary_scanner.bytes_info.md5,
                    'sha1': binary_scanner.bytes_info.sha1,
                    'sha256': binary_scanner.bytes_info.sha256
                }
                
                # Check for dangerous instructions
                dangerous_instructions = []
                try:
                    binary_scanner.check_for_dangerous_instructions()
                    # Dangerous instructions are logged, we can't easily extract them
                    # but the check is performed
                except Exception as e:
                    logger.debug(f"Error checking dangerous instructions: {e}")
                
                # Check for BOMs
                boms_found = []
                try:
                    binary_scanner.check_for_boms()
                    # BOMs are logged, similar issue
                except Exception as e:
                    logger.debug(f"Error checking BOMs: {e}")
                
                stream_data = {
                    'node_id': node.idnum,
                    'label': str(node),
                    'status': 'analyzed',
                    'stream_length': node.stream_length,
                    'hashes': hashes,
                    'preview_start': binary_scanner.bytes[:100].hex() if len(binary_scanner.bytes) > 0 else None,
                    'preview_end': binary_scanner.bytes[-100:].hex() if len(binary_scanner.bytes) > 100 else None
                }
                
                streams_data.append(stream_data)
            except Exception as e:
                logger.warning(f"Error analyzing stream {node.idnum}: {e}")
                streams_data.append({
                    'node_id': node.idnum,
                    'label': str(node),
                    'status': 'error',
                    'error': str(e),
                    'stream_length': node.stream_length if hasattr(node, 'stream_length') else 0
                })
    
    except Exception as e:
        logger.error(f"Error analyzing streams: {e}", exc_info=True)
    
    return streams_data


def get_detailed_yara_results(pdfalyzer: Any) -> Dict[str, Any]:
    """
    Get detailed YARA results (function 3 - like print_yara_results)
    
    Args:
        pdfalyzer: Pdfalyzer instance
    
    Returns:
        Dict with detailed YARA scan results including stream scans
    """
    detailed_results = {
        'main_pdf_matches': [],
        'stream_matches': []
    }
    
    try:
        from pdfalyzer.detection.yaralyzer_helper import get_file_yaralyzer, get_bytes_yaralyzer
        from pdfalyzer.decorators.pdf_tree_node import DECODE_FAILURE_LEN
        
        # Scan main PDF
        yaralyzer = get_file_yaralyzer(pdfalyzer.pdf_path)
        main_matches = yaralyzer.scan()
        
        for match in main_matches:
            match_data = {
                'rule_name': match.rule_name,
                'rule_namespace': match.rule_namespace,
                'strings': [],
                'tags': match.tags if hasattr(match, 'tags') else [],
                'metadata': match.meta if hasattr(match, 'meta') else {}
            }
            
            for string_match in match.strings:
                match_data['strings'].append({
                    'identifier': string_match.identifier,
                    'offset': string_match.offset,
                    'data': string_match.data.hex() if isinstance(string_match.data, bytes) else str(string_match.data)
                })
            
            detailed_results['main_pdf_matches'].append(match_data)
        
        # Scan each stream
        for node in pdfalyzer.stream_nodes():
            if node.stream_length == DECODE_FAILURE_LEN:
                continue
            if node.stream_length == 0 or node.stream_data is None:
                continue
            
            try:
                stream_yaralyzer = get_bytes_yaralyzer(node.stream_data, str(node))
                stream_matches = stream_yaralyzer.scan()
                
                if stream_matches:
                    for match in stream_matches:
                        match_data = {
                            'node_id': node.idnum,
                            'node_label': str(node),
                            'rule_name': match.rule_name,
                            'rule_namespace': match.rule_namespace,
                            'strings': [],
                            'tags': match.tags if hasattr(match, 'tags') else [],
                            'metadata': match.meta if hasattr(match, 'meta') else {}
                        }
                        
                        for string_match in match.strings:
                            match_data['strings'].append({
                                'identifier': string_match.identifier,
                                'offset': string_match.offset,
                                'data': string_match.data.hex() if isinstance(string_match.data, bytes) else str(string_match.data)
                            })
                        
                        detailed_results['stream_matches'].append(match_data)
            except Exception as e:
                logger.debug(f"Error scanning stream {node.idnum} with YARA: {e}")
    
    except Exception as e:
        logger.error(f"Error getting detailed YARA results: {e}", exc_info=True)
    
    return detailed_results


def scan_yara(pdf_path: str) -> List[Dict[str, Any]]:
    """
    Scan PDF with YARA rules
    
    Args:
        pdf_path: Path to PDF file
    
    Returns:
        List of YARA match dicts
    """
    matches = []
    
    try:
        yaralyzer = get_file_yaralyzer(pdf_path)
        yara_matches = yaralyzer.scan()
        
        for match in yara_matches:
            match_data = {
                'rule_name': match.rule_name,
                'rule_namespace': match.rule_namespace,
                'strings': [],
                'tags': match.tags if hasattr(match, 'tags') else [],
                'metadata': match.meta if hasattr(match, 'meta') else {}
            }
            
            # Extract string matches
            for string_match in match.strings:
                match_data['strings'].append({
                    'identifier': string_match.identifier,
                    'offset': string_match.offset,
                    'data': string_match.data.hex() if isinstance(string_match.data, bytes) else str(string_match.data)
                })
            
            matches.append(match_data)
        
        logger.info(f"YARA scan found {len(matches)} matches")
        
    except Exception as e:
        logger.error(f"Error scanning PDF with YARA: {e}")
    
    return matches


def search_binary_patterns(pdfalyzer: Any, patterns: List[str]) -> List[Dict[str, Any]]:
    """
    Search for binary patterns in PDF streams
    
    Args:
        pdfalyzer: Pdfalyzer instance
        patterns: List of patterns to search (hex, regex, or strings)
    
    Returns:
        List of pattern match dicts
    """
    results = []
    
    if not PDFALYZER_AVAILABLE:
        return results
    
    try:
        from pdfalyzer.binary.binary_scanner import BinaryScanner
        from yaralyzer.yara.yara_rule_builder import HEX, REGEX
        
        for stream_node in pdfalyzer.stream_nodes():
            if stream_node.contains_stream() and hasattr(stream_node, 'stream_data') and stream_node.stream_data:
                # Create binary scanner for this stream
                scanner = BinaryScanner(stream_node.stream_data, stream_node)
                
                for pattern in patterns:
                    try:
                        # Try as hex pattern (remove spaces)
                        pattern_clean = pattern.replace(' ', '').replace('\n', '').replace('\r', '')
                        if all(c in '0123456789ABCDEFabcdef' for c in pattern_clean) and len(pattern_clean) > 0:
                            # Hex pattern
                            yaralyzer = scanner._pattern_yaralyzer(pattern_clean, HEX)
                        else:
                            # Try as regex or string
                            yaralyzer = scanner._pattern_yaralyzer(pattern, REGEX)
                        
                        yara_matches = yaralyzer.scan()
                        for match in yara_matches:
                            for string_match in match.strings:
                                results.append({
                                    'node_id': stream_node.idnum,
                                    'pattern': pattern,
                                    'offset': string_match.offset,
                                    'data': string_match.data.hex() if isinstance(string_match.data, bytes) else str(string_match.data),
                                    'rule_name': match.rule_name if hasattr(match, 'rule_name') else None
                                })
                    except Exception as e:
                        logger.debug(f"Error searching pattern {pattern} in node {stream_node.idnum}: {e}")
        
    except Exception as e:
        logger.error(f"Error searching binary patterns: {e}", exc_info=True)
    
    return results


def detect_modifications(pdfalyzer: Any) -> Dict[str, Any]:
    """
    Detect PDF modifications (incremental updates)
    
    Args:
        pdfalyzer: Pdfalyzer instance
    
    Returns:
        Dict with modification history info
    """
    history = {
        'has_modifications': False,
        'max_generation': pdfalyzer.max_generation,
        'total_objects': pdfalyzer.pdf_size,
        'generations': {}
    }
    
    try:
        # Check for multiple generations (indicates incremental updates)
        if pdfalyzer.max_generation > 0:
            history['has_modifications'] = True
        
        # Count objects by generation
        for node in pdfalyzer.node_iterator():
            if hasattr(node, 'obj') and hasattr(node.obj, 'generation'):
                gen = node.obj.generation or 0
                if gen not in history['generations']:
                    history['generations'][gen] = 0
                history['generations'][gen] += 1
        
    except Exception as e:
        logger.error(f"Error detecting modifications: {e}")
    
    return history

