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

Wrapper for txt2stix integration
Uses txt2stix Python API directly without going through CLI
"""
import os
import sys
import tempfile
import logging
import uuid
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Find and configure txt2stix BEFORE import
TXT2STIX_PATH = None
TXT2STIX_INCLUDES_PATH = None

try:
    current_file = Path(__file__).resolve()
    project_root = current_file.parent.parent.parent
    repos_dir = project_root / "repos"
    
    # Search for txt2stix in repos
    txt2stix_path = None
    possible_paths = [
        repos_dir / "txt2stix-main",
        repos_dir / "txt2stix",
    ]
    
    # Also search in subdirectories (max 3 levels)
    for root, dirs, files in os.walk(repos_dir):
        depth = root[len(str(repos_dir)):].count(os.sep)
        if depth > 3:
            dirs[:] = []
            continue
        
        if "txt2stix" in root.lower() and "txt2stix" in dirs:
            txt2stix_path = Path(root)
            break
    
    # If not found, try possible paths
    if not txt2stix_path:
        for path in possible_paths:
            if path.exists() and (path / "txt2stix").exists():
                txt2stix_path = path
                break
    
    if txt2stix_path:
        TXT2STIX_PATH = txt2stix_path
        TXT2STIX_INCLUDES_PATH = txt2stix_path / "includes"
        
        # Add to sys.path if found
        if str(txt2stix_path) not in sys.path:
            sys.path.insert(0, str(txt2stix_path))
            logger.info(f"txt2stix path added: {txt2stix_path}")
        
        # Temporarily change working directory so txt2stix finds includes
        # during import (because it uses Path("includes") which is relative)
        original_cwd = os.getcwd()
        try:
            os.chdir(str(txt2stix_path))
            
            # Import txt2stix now that working directory is correct
            from txt2stix.txt2stix import run_txt2stix, extract_all, parse_extractors_globbed
            from txt2stix.bundler import txt2stixBundler, TLP_LEVEL
            from txt2stix.common import UUID_NAMESPACE
            from txt2stix.utils import remove_links
            from txt2stix import extractions, pattern, lookups
            
            # Configure includes path after import
            try:
                from txt2stix import set_include_path
                set_include_path(str(TXT2STIX_INCLUDES_PATH))
            except Exception:
                # Ignore errors when setting include path (optional feature)
                pass
            
            TXT2STIX_AVAILABLE = True
            logger.info(f"txt2stix loaded from: {txt2stix_path}")
        finally:
            # Restore original working directory
            os.chdir(original_cwd)
    else:
        TXT2STIX_AVAILABLE = False
        logger.warning("txt2stix directory not found in repos/")
        
except Exception as e:
    logger.warning(f"Error configuring txt2stix: {e}")
    TXT2STIX_AVAILABLE = False


def format_iocs_for_txt2stix(iocs_list: List[Dict], source_context: str = "") -> str:
    """
    Formats a list of IOCs into text for txt2stix
    txt2stix automatically extracts IOCs from raw text
    
    Args:
        iocs_list: List of dictionaries with 'ioc_type' and 'ioc_value'
        source_context: Source context
    
    Returns:
        Formatted text for txt2stix (simple format, txt2stix will extract IOCs automatically)
    """
    lines = []
    
    if source_context:
        lines.append(f"Threat Intelligence Report")
        lines.append("")
        lines.append(f"Context: {source_context}")
        lines.append("")
        lines.append("Extracted Indicators of Compromise (IOCs):")
        lines.append("")
    
    # Put IOCs in text naturally
    # txt2stix will use its pattern extractors to detect them
    for ioc in iocs_list:
        ioc_value = ioc.get('ioc_value', '')
        if ioc_value:
            # Add IOC to text (txt2stix will detect it automatically)
            lines.append(ioc_value)
    
    # If no context, add simple header
    if not source_context:
        lines.insert(0, "Threat Intelligence Report - Extracted IOCs")
        lines.insert(1, "")
    
    return "\n".join(lines)


def convert_to_stix(iocs_list: List[Dict], source_context: str, report_name: str,
                    relationship_mode: str = 'standard',
                    output_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Converts a list of IOCs to STIX 2.1 bundle via txt2stix Python API
    
    Args:
        iocs_list: List of dictionaries with 'ioc_type' and 'ioc_value'
        source_context: Source context
        report_name: Report name (max 72 chars)
        relationship_mode: 'standard' or 'ai' (default: 'standard')
        output_dir: Output directory (optional)
    
    Returns:
        Path to generated STIX bundle or None on error
    """
    if not TXT2STIX_AVAILABLE:
        raise RuntimeError("txt2stix is not available. Please install it.")

    if not iocs_list:
        logger.warning("Empty IOC list, cannot generate STIX")
        return None

    try:
        # Format IOCs as text
        text_content = format_iocs_for_txt2stix(iocs_list, source_context)
        
        # Prepare output directory
        if output_dir is None:
            from config import OUTPUT_FOLDER
            output_dir = Path(OUTPUT_FOLDER) / "stix"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Use txt2stix Python API directly
        return _convert_via_api(text_content, report_name, source_context, output_dir, relationship_mode)

    except Exception as e:
        logger.error(f"STIX conversion error: {str(e)}", exc_info=True)
        return None


def _create_stix_pattern(ioc_type: str, ioc_value: str) -> Optional[str]:
    """
    Creates a STIX pattern from an IOC type and value
    """
    pattern_map = {
        'ip4': f"[ipv4-addr:value = '{ioc_value}']",
        'ip6': f"[ipv6-addr:value = '{ioc_value}']",
        'fqdn': f"[domain-name:value = '{ioc_value}']",
        'url': f"[url:value = '{ioc_value}']",
        'email': f"[email-addr:value = '{ioc_value}']",
        'md5': f"[file:hashes.'MD5' = '{ioc_value}']",
        'sha1': f"[file:hashes.'SHA-1' = '{ioc_value}']",
        'sha256': f"[file:hashes.'SHA-256' = '{ioc_value}']",
    }
    
    return pattern_map.get(ioc_type.lower())


def _convert_via_api(text_content: str, report_name: str, source_context: str, 
                    output_dir: Path, relationship_mode: str = 'standard') -> Optional[Path]:
    """
    Conversion via txt2stix Python API (without CLI)
    """
    try:
        # Set necessary environment variables
        os.environ.setdefault('INPUT_TOKEN_LIMIT', '100000')
        os.environ.setdefault('CTIBUTLER_BASE_URL', '')
        os.environ.setdefault('VULMATCH_BASE_URL', '')
        
        # Use paths already found during import
        if not TXT2STIX_PATH or not TXT2STIX_INCLUDES_PATH:
            logger.error(f"txt2stix is not properly configured")
            return None
        
        txt2stix_path = TXT2STIX_PATH
        includes_path = TXT2STIX_INCLUDES_PATH
        
        # Configure includes path for txt2stix
        try:
            from txt2stix import set_include_path
            set_include_path(str(includes_path))
        except:
            pass
        
        # Prepare text (remove links if necessary)
        # remove_links(input_text: str, remove_images: bool, remove_anchors: bool)
        preprocessed_text = remove_links(text_content, remove_images=True, remove_anchors=True)
        
        # Parse extractors (pattern_*)
        try:
            # Find extraction path
            if includes_path.exists():
                extractors_path = includes_path / "extractions"
                if extractors_path.exists():
                    all_extractors = extractions.parse_extraction_config(includes_path)
                else:
                    # Use default extractors
                    all_extractors = extractions.parse_extraction_config()
            else:
                all_extractors = extractions.parse_extraction_config()
        except Exception as e:
            logger.warning(f"Error parsing extractors: {e}, using default extractors")
            all_extractors = extractions.parse_extraction_config()
        
        # Parse requested extractors (pattern_*)
        # parse_extractors_globbed takes (type, all_extractors, names)
        # Type is not really used, but must be passed
        try:
            extractors_map = parse_extractors_globbed("pattern", all_extractors, "pattern_*")
        except Exception as e:
            logger.warning(f"Error parsing pattern_* extractors: {e}")
            # Try with all available pattern extractors
            extractors_map = {}
            for name, extractor in all_extractors.items():
                if name.startswith("pattern_"):
                    extractor_type = extractor.type
                    if extractor_type not in extractors_map:
                        extractors_map[extractor_type] = {}
                    extractors_map[extractor_type][name] = extractor
        
        # Create bundler
        # Signature: __init__(name, identity, tlp_level, description, confidence, extractors, labels, report_id=None, created=None, external_references=None, modified=None)
        bundler = txt2stixBundler(
            name=report_name[:72],
            identity=None,  # Will use default identity
            tlp_level="clear",  # TLP_LEVEL.get() accepts a string
            description=text_content,  # Full text as description
            confidence=None,
            extractors=all_extractors,
            labels=[],
            report_id=None,
            created=datetime.now(),
            external_references=[]
        )
        
        # Execute txt2stix
        data = run_txt2stix(
            bundler=bundler,
            preprocessed_text=preprocessed_text,
            extractors_map=extractors_map,
            input_token_limit=int(os.environ.get('INPUT_TOKEN_LIMIT', '100000')),
            relationship_mode=relationship_mode,
            ignore_extraction_boundary=False,
            ai_extract_if_no_incidence=True
        )
        
        # Generate STIX JSON
        stix_json = bundler.to_json()
        
        # Check and fix spec_version if necessary (STIX 2.1)
        try:
            stix_data = json.loads(stix_json)
            if stix_data.get('type') == 'bundle' and not stix_data.get('spec_version'):
                stix_data['spec_version'] = '2.1'
                stix_json = json.dumps(stix_data, indent=4, ensure_ascii=False)
                logger.info("spec_version '2.1' added to STIX bundle")
        except Exception as e:
            logger.warning(f"Unable to check/fix spec_version: {e}")
        
        # Save file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        final_output = output_dir / f"stix_bundle_{timestamp}_{uuid.uuid4().hex[:8]}.json"
        
        with open(final_output, 'w', encoding='utf-8') as f:
            f.write(stix_json)
        
        logger.info(f"STIX bundle generated: {final_output}")
        return final_output
        
    except Exception as e:
        logger.error(f"API conversion error: {str(e)}", exc_info=True)
        return None


def _convert_via_cli(temp_file: str, report_name: str, source_context: str, 
                    output_dir: Path, relationship_mode: str = 'standard') -> Optional[Path]:
    """
    Conversion via txt2stix command line
    txt2stix creates file in ./output/{uuid}/{bundle_id}.json
    """
    try:
        import subprocess
        import json
        import glob
        import shutil
        
        # Find txt2stix directory
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent
        repos_dir = project_root / "repos"
        
        # Search for txt2stix in repos (may be txt2stix-main, txt2stix, etc.)
        txt2stix_path = None
        possible_paths = [
            repos_dir / "txt2stix-main",
            repos_dir / "txt2stix",
        ]
        
        # Also search in subdirectories (max 3 levels)
        for root, dirs, files in os.walk(repos_dir):
            depth = root[len(str(repos_dir)):].count(os.sep)
            if depth > 3:
                dirs[:] = []
                continue
            
            if "txt2stix" in root.lower() and "txt2stix.py" in files:
                txt2stix_path = Path(root)
                break
        
        # If not found, try possible paths
        if not txt2stix_path:
            for path in possible_paths:
                if path.exists() and (path / "txt2stix.py").exists():
                    txt2stix_path = path
                    break
        
        if not txt2stix_path or not (txt2stix_path / "txt2stix.py").exists():
            logger.error(f"txt2stix directory not found. Searched in: {repos_dir}")
            return None
        
        original_cwd = os.getcwd()
        
        try:
            # Change to txt2stix directory (necessary for txt2stix to work correctly)
            os.chdir(txt2stix_path)
            
            # Call txt2stix command line
            # txt2stix requires environment variables, set them with default values
            env = os.environ.copy()
            env.setdefault('INPUT_TOKEN_LIMIT', '100000')
            env.setdefault('CTIBUTLER_BASE_URL', '')
            env.setdefault('VULMATCH_BASE_URL', '')
            
            # Use absolute path for input file
            temp_file_abs = os.path.abspath(temp_file)
            
            # Call txt2stix.py directly from project root
            cmd = [
                'python3', 'txt2stix.py',
                '--input_file', temp_file_abs,
                '--name', report_name[:72],
                '--relationship_mode', relationship_mode,
                '--use_extractions', 'pattern_*',
                '--tlp_level', 'clear'
            ]
            
            logger.info(f"Running txt2stix from {txt2stix_path}: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env, cwd=str(txt2stix_path))
            
            if result.returncode == 0:
                # txt2stix creates file in ./output/{uuid}/{bundle_id}.json
                # Search for generated file in txt2stix directory
                output_pattern = txt2stix_path / "output" / "*" / "*.json"
                generated_files = list(glob.glob(str(output_pattern)))
                
                if generated_files:
                    # Take first file found (normally there's only one)
                    generated_file = Path(generated_files[0])
                    
                    # Copy to final output directory
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    final_output = output_dir / f"stix_bundle_{timestamp}_{uuid.uuid4().hex[:8]}.json"
                    
                    # Read and copy content
                    with open(generated_file, 'r', encoding='utf-8') as src:
                        content = src.read()
                    
                    with open(final_output, 'w', encoding='utf-8') as dst:
                        dst.write(content)
                    
                    logger.info(f"STIX bundle generated: {final_output}")
                    
                    # Clean txt2stix output directory (optional)
                    try:
                        output_dir_txt2stix = txt2stix_path / "output"
                        if output_dir_txt2stix.exists():
                            shutil.rmtree(output_dir_txt2stix, ignore_errors=True)
                    except Exception as e:
                        logger.warning(f"Unable to clean txt2stix output directory: {e}")
                    
                    return final_output
                else:
                    logger.error("No STIX file generated by txt2stix")
                    # Check logs
                    if result.stdout:
                        logger.debug(f"txt2stix output: {result.stdout}")
                    if result.stderr:
                        logger.error(f"txt2stix error: {result.stderr}")
                    return None
            else:
                logger.error(f"txt2stix CLI error (code {result.returncode})")
                if result.stdout:
                    logger.error(f"Output: {result.stdout}")
                if result.stderr:
                    logger.error(f"Error: {result.stderr}")
                return None
        finally:
            # Return to original directory
            os.chdir(original_cwd)
                
    except subprocess.TimeoutExpired:
        logger.error("Timeout during txt2stix CLI call")
        return None
    except Exception as e:
        logger.error(f"CLI call error: {str(e)}", exc_info=True)
        return None


def convert_with_relationships(iocs_list: List[Dict], source_context: str, 
                              report_name: str, relationship_mode: str = 'standard',
                              output_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Converts with relationship management (wrapper around convert_to_stix)
    """
    return convert_to_stix(
        iocs_list=iocs_list,
        source_context=source_context,
        report_name=report_name,
        relationship_mode=relationship_mode,
        output_dir=output_dir
    )

