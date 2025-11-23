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

Simplified CTI pipeline: IOCs → STIX
Converts IOCs to STIX 2.1 bundle via txt2stix
"""
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)


class CTIPipeline:
    """
    Centralized pipeline for CTI report generation
    """
    
    def __init__(self):
        self.temp_dirs = []  # For cleanup
        
    def __del__(self):
        """Clean up temporary directories"""
        for temp_dir in self.temp_dirs:
            try:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                # Ignore errors when cleaning up temp directories
                pass
    
    def create_narrative_text(self, iocs_list: List[Dict], source_context: str = "") -> str:
        """
        Creates a narrative text from IOCs and context
        This text will be used by txt2stix
        
        Args:
            iocs_list: List of dictionaries with 'ioc_type' and 'ioc_value'
            source_context: Source context
            
        Returns:
            Formatted narrative text
        """
        lines = []
        
        # Header
        lines.append("CYBER THREAT INTELLIGENCE REPORT")
        lines.append("")
        
        # Context
        if source_context:
            lines.append("Context:")
            lines.append(source_context)
            lines.append("")
        
        # IOCs organized by type - natural format for txt2stix
        if iocs_list:
            lines.append("Extracted Indicators of Compromise (IOCs):")
            lines.append("")
            
            # Group by type
            iocs_by_type = {}
            for ioc in iocs_list:
                ioc_type = ioc.get('ioc_type', 'unknown')
                ioc_value = ioc.get('ioc_value', '')
                if ioc_value:
                    if ioc_type not in iocs_by_type:
                        iocs_by_type[ioc_type] = []
                    iocs_by_type[ioc_type].append(ioc_value)
            
            # Add IOCs by type - simple format for automatic extraction
            for ioc_type, values in sorted(iocs_by_type.items()):
                lines.append(f"{ioc_type.upper()}:")
                for value in values:
                    # Simple format: just the value (txt2stix will extract it automatically)
                    lines.append(value)
                lines.append("")
        
        return "\n".join(lines)
    
    def convert_to_stix(self, iocs_list: List[Dict], narrative_text: str, report_name: str, 
                       output_dir: Optional[Path] = None) -> Optional[Path]:
        """
        Converts IOCs to STIX 2.1 bundle via txt2stix
        
        Args:
            iocs_list: List of IOCs to convert (with 'ioc_type' and 'ioc_value')
            narrative_text: Narrative text for context
            report_name: Report name
            output_dir: Output directory
            
        Returns:
            Path to generated STIX bundle or None
        """
        try:
            from modules.txt2stix_wrapper import convert_to_stix as txt2stix_convert
            
            # Check that we have IOCs
            if not iocs_list:
                logger.warning("No IOCs provided for STIX conversion")
                return None
            
            logger.info(f"Converting {len(iocs_list)} IOCs to STIX...")
            
            # Use txt2stix to convert directly with IOC list
            stix_file = txt2stix_convert(
                iocs_list=iocs_list,
                source_context=narrative_text,
                report_name=report_name[:72],
                output_dir=output_dir
            )
            
            if stix_file and Path(stix_file).exists():
                logger.info(f"STIX bundle generated: {stix_file}")
                return Path(stix_file)
            else:
                logger.error("STIX bundle generation failed")
                return None
                
        except Exception as e:
            logger.error(f"STIX conversion error: {e}", exc_info=True)
            return None
    
    
    def run_complete_pipeline(self, iocs_list: List[Dict], source_context: str,
                             report_name: str,
                             progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Executes simplified pipeline: IOCs → STIX
        
        Args:
            iocs_list: List of IOCs
            source_context: Source context
            report_name: Report name
            progress_callback: Callback function(percentage, message) for tracking
            
        Returns:
            Dictionary with results:
            {
                'success': bool,
                'stix_file': Path or None,
                'errors': List[str]
            }
        """
        results = {
            'success': False,
            'stix_file': None,
            'errors': []
        }
        
        try:
            # Prepare output directory
            from config import OUTPUT_FOLDER
            output_dir = Path(OUTPUT_FOLDER)
            stix_dir = output_dir / "stix"
            stix_dir.mkdir(parents=True, exist_ok=True)
            
            # Step 1: Create narrative text
            if progress_callback:
                progress_callback(20, "Creating narrative text...")
            
            narrative_text = self.create_narrative_text(iocs_list, source_context)
            
            if not narrative_text or len(narrative_text.strip()) < 10:
                results['errors'].append("Narrative text too short or empty")
                return results
            
            logger.info(f"Narrative text created ({len(narrative_text)} characters)")
            
            # Step 2: Convert to STIX
            if progress_callback:
                progress_callback(50, "Converting to STIX 2.1...")
            
            # Check that we have IOCs
            if not iocs_list:
                results['errors'].append("No IOCs to convert")
                return results
            
            stix_file = self.convert_to_stix(iocs_list, narrative_text, report_name, stix_dir)
            
            if not stix_file:
                results['errors'].append("STIX conversion failed")
                return results
            
            results['stix_file'] = stix_file
            results['success'] = True
            logger.info(f"STIX bundle generated: {stix_file}")
            
            if progress_callback:
                progress_callback(100, "Pipeline completed")
            
        except Exception as e:
            logger.error(f"CTI pipeline error: {e}", exc_info=True)
            results['errors'].append(f"General error: {str(e)}")
        
        return results

