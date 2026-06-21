"""
Odysafe CTI Platform
Copyright (C) 2026 Bastien GUIDONE

MITRE ATT&CK STIX2 JSON Parser
Parses enterprise-attack.json STIX bundle
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

MITRE_JSON_PATH = Path(__file__).parent.parent.parent / "docs" / "enterprise-attack.json"


class MitreStixParser:
    """Parse MITRE ATT&CK STIX2 JSON bundle"""
    
    def __init__(self, file_path: Path = None):
        self.file_path = file_path or MITRE_JSON_PATH
        self.bundle = None
        self.objects_by_id = {}
        self.objects_by_type = {}
        
    def load(self) -> bool:
        """Load STIX2 bundle using official library"""
        try:
            if not self.file_path.exists():
                logger.warning(f"MITRE JSON file not found: {self.file_path}")
                return False
            
            with open(self.file_path, 'r', encoding='utf-8') as f:
                self.bundle = json.load(f)
            
            # Index objects by ID and type
            for obj in self.bundle.get('objects', []):
                self.objects_by_id[obj['id']] = obj
                obj_type = obj['type']
                if obj_type not in self.objects_by_type:
                    self.objects_by_type[obj_type] = []
                self.objects_by_type[obj_type].append(obj)
            
            logger.info(f"Loaded MITRE bundle: {len(self.objects_by_id)} objects")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load MITRE JSON: {e}")
            return False
    
    def _get_mitre_id(self, obj: Dict) -> Optional[str]:
        """Extract MITRE ATT&CK ID (T1234, G1234, etc.) from object"""
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        return None
    
    def _get_url(self, obj: Dict) -> Optional[str]:
        """Extract URL from external references"""
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('url')
        return None
    
    def get_version(self) -> str:
        """Get ATT&CK version from bundle"""
        matrices = self.objects_by_type.get('x-mitre-matrix', [])
        for matrix in matrices:
            for ref in matrix.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    return ref.get('external_id', 'unknown')
        return 'unknown'
    
    def get_matrix(self) -> Optional[Dict]:
        """Get Enterprise matrix with tactic order"""
        matrices = self.objects_by_type.get('x-mitre-matrix', [])
        for matrix in matrices:
            if 'enterprise' in matrix.get('name', '').lower():
                return {
                    'id': matrix['id'],
                    'name': matrix['name'],
                    'tactic_refs': matrix.get('tactic_refs', [])
                }
        # Fallback to first matrix
        if matrices:
            m = matrices[0]
            return {
                'id': m['id'],
                'name': m.get('name', ''),
                'tactic_refs': m.get('tactic_refs', [])
            }
        return None
    
    def get_tactics(self) -> List[Dict]:
        """Get all 14 tactics in matrix order"""
        tactics = []
        matrix = self.get_matrix()
        tactic_refs = matrix.get('tactic_refs', []) if matrix else []
        
        for ref in tactic_refs:
            obj = self.objects_by_id.get(ref)
            if not obj or obj.get('type') != 'x-mitre-tactic':
                continue
            
            tactic_data = {
                'id': self._get_mitre_id(obj),
                'stix_id': obj['id'],
                'name': obj.get('name', ''),
                'shortname': obj.get('x_mitre_shortname', ''),
                'description': obj.get('description', ''),
                'url': self._get_url(obj)
            }
            tactics.append(tactic_data)
        
        return tactics
    
    def get_techniques(self) -> List[Dict]:
        """Get all techniques and sub-techniques"""
        techniques = []
        attack_patterns = self.objects_by_type.get('attack-pattern', [])
        
        for obj in attack_patterns:
            tech_id = self._get_mitre_id(obj)
            if not tech_id:
                continue
            
            # Determine if sub-technique (has dot in ID like T1059.001)
            is_sub = '.' in tech_id
            parent_id = tech_id.split('.')[0] if is_sub else None
            
            # Get tactics from kill chain phases
            tactics = []
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(phase.get('phase_name', ''))
            
            tech_data = {
                'id': tech_id,
                'stix_id': obj['id'],
                'name': obj.get('name', ''),
                'description': obj.get('description', ''),
                'url': self._get_url(obj),
                'is_subtechnique': is_sub,
                'parent_id': parent_id,
                'deprecated': obj.get('x_mitre_deprecated', False),
                'tactics': tactics,
                'platforms': obj.get('x_mitre_platforms', []),
                'is_trending': obj.get('x_mitre_is_trending', False)
            }
            techniques.append(tech_data)
        
        return techniques
    
    def get_subtechniques_for_technique(self, parent_id: str) -> List[Dict]:
        """Get sub-techniques for a given parent technique (e.g., T1059 -> [T1059.001, T1059.002...])"""
        all_techniques = self.get_techniques()
        return [t for t in all_techniques if t.get('parent_id') == parent_id and not t.get('deprecated')]
    
    def get_groups(self) -> List[Dict]:
        """Get threat actor groups (intrusion-sets)"""
        groups = []
        intrusion_sets = self.objects_by_type.get('intrusion-set', [])
        
        for obj in intrusion_sets:
            group_id = self._get_mitre_id(obj)
            if not group_id:
                continue
            
            group_data = {
                'id': group_id,
                'stix_id': obj['id'],
                'name': obj.get('name', ''),
                'aliases': obj.get('aliases', []),
                'description': obj.get('description', ''),
                'url': self._get_url(obj),
                'goals': obj.get('goals', [])
            }
            groups.append(group_data)
        
        return groups
    
    def get_software(self) -> List[Dict]:
        """Get malware and tools"""
        software = []
        
        for obj_type in ['malware', 'tool']:
            for obj in self.objects_by_type.get(obj_type, []):
                sw_id = self._get_mitre_id(obj)
                if not sw_id:
                    continue
                
                sw_data = {
                    'id': sw_id,
                    'stix_id': obj['id'],
                    'type': obj_type,
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'labels': obj.get('labels', []),
                    'url': self._get_url(obj),
                    'platforms': obj.get('x_mitre_platforms', [])
                }
                software.append(sw_data)
        
        return software
    
    def get_mitigations(self) -> List[Dict]:
        """Get mitigations (course-of-action)"""
        mitigations = []
        coa = self.objects_by_type.get('course-of-action', [])
        
        for obj in coa:
            mit_id = self._get_mitre_id(obj)
            if not mit_id:
                continue
            
            mit_data = {
                'id': mit_id,
                'stix_id': obj['id'],
                'name': obj.get('name', ''),
                'description': obj.get('description', ''),
                'url': self._get_url(obj)
            }
            mitigations.append(mit_data)
        
        return mitigations
    
    def get_relationships(self, source_id: str = None, target_id: str = None, rel_type: str = None) -> List[Dict]:
        """Get relationships"""
        relationships = []
        
        for obj in self.objects_by_type.get('relationship', []):
            if rel_type and obj.get('relationship_type') != rel_type:
                continue
            if source_id and obj.get('source_ref') != source_id:
                continue
            if target_id and obj.get('target_ref') != target_id:
                continue
            
            source_obj = self.objects_by_id.get(obj.get('source_ref'))
            target_obj = self.objects_by_id.get(obj.get('target_ref'))
            
            rel_data = {
                'id': obj['id'],
                'type': obj.get('relationship_type'),
                'source_stix': obj.get('source_ref'),
                'target_stix': obj.get('target_ref'),
                'source_name': source_obj.get('name') if source_obj else '',
                'source_id': self._get_mitre_id(source_obj) if source_obj else None,
                'target_name': target_obj.get('name') if target_obj else '',
                'target_id': self._get_mitre_id(target_obj) if target_obj else None,
                'description': obj.get('description', '')
            }
            relationships.append(rel_data)
        
        return relationships
    
    def get_technique_by_id(self, tech_id: str) -> Optional[Dict]:
        """Get technique by MITRE ID (e.g., T1078)"""
        all_techniques = self.get_techniques()
        tech_id_upper = tech_id.upper()
        return next((t for t in all_techniques if t['id'] == tech_id_upper), None)
    
    def get_techniques_for_tactic(self, tactic_shortname: str) -> List[Dict]:
        """Get main techniques for a tactic (excluding sub-techniques)"""
        all_techniques = self.get_techniques()
        return [
            t for t in all_techniques 
            if tactic_shortname in t.get('tactics', []) 
            and not t.get('is_subtechnique') 
            and not t.get('deprecated')
        ]
    
    def get_techniques_for_group(self, group_stix_id: str) -> List[Dict]:
        """Get techniques used by a specific group"""
        logger.info(f"Getting techniques for group with STIX ID: {group_stix_id}")
        
        # Get all 'uses' relationships where this group is the source
        relationships = self.get_relationships(source_id=group_stix_id, rel_type='uses')
        logger.info(f"Found {len(relationships)} 'uses' relationships for group")
        
        # Extract target technique IDs (only those starting with 'T')
        technique_ids = [r['target_stix'] for r in relationships if r['target_id'] and r['target_id'].startswith('T')]
        logger.info(f"Extracted {len(technique_ids)} technique IDs: {technique_ids[:5]}...")  # Log first 5
        
        if not technique_ids:
            # Try alternative: some bundles may use different relationship patterns
            # Check all relationships without filtering by type
            all_rels = self.get_relationships(source_id=group_stix_id)
            logger.info(f"Total relationships for group: {len(all_rels)}")
            for r in all_rels[:5]:  # Log first 5
                logger.info(f"  Relationship: {r['type']} -> {r.get('target_id', 'N/A')}")
        
        all_techniques = self.get_techniques()
        matched = [t for t in all_techniques if t['stix_id'] in technique_ids]
        logger.info(f"Matched {len(matched)} techniques from {len(all_techniques)} total techniques")
        
        return matched
    
    def get_mitigations_for_technique(self, technique_stix_id: str) -> List[Dict]:
        """Get mitigations for a specific technique"""
        relationships = self.get_relationships(target_id=technique_stix_id, rel_type='mitigates')
        mitigation_ids = [r['source_stix'] for r in relationships]
        
        all_mitigations = self.get_mitigations()
        return [m for m in all_mitigations if m['stix_id'] in mitigation_ids]
    
    def get_groups_for_technique(self, technique_stix_id: str) -> List[Dict]:
        """Get groups that use a specific technique"""
        relationships = self.get_relationships(target_id=technique_stix_id, rel_type='uses')
        group_ids = [r['source_stix'] for r in relationships if r['source_id'] and r['source_id'].startswith('G')]
        
        all_groups = self.get_groups()
        return [g for g in all_groups if g['stix_id'] in group_ids]
    
    def get_matrix_view(self) -> Dict:
        """Get matrix with 3 levels: Tactics -> Techniques -> Sub-techniques"""
        tactics = self.get_tactics()
        
        matrix_tactics = []
        for tactic in tactics:
            # Get main techniques for this tactic
            techniques = self.get_techniques_for_tactic(tactic['shortname'])
            
            # Add sub-techniques to each technique
            techniques_with_subs = []
            for tech in techniques:
                tech_data = tech.copy()
                tech_data['subtechniques'] = self.get_subtechniques_for_technique(tech['id'])
                techniques_with_subs.append(tech_data)
            
            matrix_tactics.append({
                'tactic': tactic,
                'techniques': sorted(techniques_with_subs, key=lambda x: x['id'])
            })
        
        return {
            'name': 'MITRE ATT&CK Enterprise',
            'version': self.get_version(),
            'tactics': matrix_tactics
        }
    
    def search(self, query: str) -> Dict[str, List]:
        """Search across all objects"""
        query = query.lower()
        results = {
            'techniques': [],
            'groups': [],
            'software': [],
            'mitigations': []
        }
        
        # Search techniques
        for tech in self.get_techniques():
            if query in tech['id'].lower() or query in tech['name'].lower() or query in tech.get('description', '').lower():
                results['techniques'].append(tech)
        
        # Search groups
        for group in self.get_groups():
            search_text = f"{group['id']} {group['name']} {' '.join(group.get('aliases', []))}".lower()
            if query in search_text or query in group.get('description', '').lower():
                results['groups'].append(group)
        
        # Search software
        for sw in self.get_software():
            if query in sw['id'].lower() or query in sw['name'].lower():
                results['software'].append(sw)
        
        # Search mitigations
        for mit in self.get_mitigations():
            if query in mit['id'].lower() or query in mit['name'].lower():
                results['mitigations'].append(mit)
        
        return results
    
    def get_stats(self) -> Dict:
        """Get counts of all object types"""
        return {
            'tactics': len(self.get_tactics()),
            'techniques': len([t for t in self.get_techniques() if not t.get('is_subtechnique')]),
            'subtechniques': len([t for t in self.get_techniques() if t.get('is_subtechnique')]),
            'groups': len(self.get_groups()),
            'software': len(self.get_software()),
            'mitigations': len(self.get_mitigations()),
            'relationships': len(self.objects_by_type.get('relationship', [])),
            'version': self.get_version()
        }


def mitre_json_exists() -> bool:
    """Check if MITRE JSON file exists"""
    return MITRE_JSON_PATH.exists()


def get_mitre_json_path() -> Path:
    """Get path to MITRE JSON file"""
    return MITRE_JSON_PATH
