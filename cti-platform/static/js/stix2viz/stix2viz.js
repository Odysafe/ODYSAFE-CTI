/**
 * STIX 2.x Visualization Module
 * Based on cti-stix-visualization by OASIS TC Open Repository
 * Adapted for Odysafe CTI Platform
 * 
 * This module provides graph visualization capabilities for STIX 2.x content
 * using vis.js network library.
 */

(function(global) {
    'use strict';

    /**
     * Convert STIX type to icon URL (PNG image)
     * @param {string} stixType - STIX type (e.g., "attack-pattern")
     * @param {string} iconPath - Base path for icons (optional)
     * @returns {string} - Icon URL
     */
    function stixTypeToIconURL(stixType, iconPath = null) {
        // Convert type (e.g., "attack-pattern") to filename format (e.g., "attack_pattern")
        const iconFileName = "stix2_" + stixType.replace(/-/g, "_") + "_icon_tiny_round_v1.png";
        
        if (iconPath === null || iconPath === undefined) {
            // Use global icon path if available
            if (typeof STIX_ICONS_BASE_PATH !== 'undefined') {
                const basePath = STIX_ICONS_BASE_PATH.endsWith('/') ? STIX_ICONS_BASE_PATH.slice(0, -1) : STIX_ICONS_BASE_PATH;
                return basePath + "/" + iconFileName;
            }
            return iconFileName;
        } else {
            const basePath = iconPath.endsWith('/') ? iconPath.slice(0, -1) : iconPath;
            return basePath + "/" + iconFileName;
        }
    }

    /**
     * Get default icon URL (fallback icon)
     * @param {string} iconPath - Base path for icons (optional)
     * @returns {string} - Default icon URL
     */
    function getDefaultIconURL(iconPath = null) {
        const defaultIcon = "stix2_custom_object_icon_tiny_round_v1.svg";
        if (iconPath === null || iconPath === undefined) {
            if (typeof STIX_ICONS_BASE_PATH !== 'undefined') {
                return STIX_ICONS_BASE_PATH + "/" + defaultIcon;
            }
            return defaultIcon;
        } else {
            return iconPath + "/" + defaultIcon;
        }
    }

    // STIX type icons mapping (kept for backward compatibility, but now returns URLs)
    // This is now a function that returns icon URLs instead of emojis
    function getStixIconURL(stixType) {
        return stixTypeToIconURL(stixType);
    }

    // STIX type colors (Standardized semantic coding - Professional scheme)
    // Threat Actors/Intrusion Set: Red
    // Malware/Attack Pattern: Orange
    // Tool/Infrastructure: Blue
    // Indicator/Observable: Green/Cyan
    // Vulnerability: Purple
    // Campaign: Yellow/Orange
    // Location: Brown
    // Course of Action: Light Green
    const STIX_COLORS = {
        'threat-actor': '#FF4444',      // Bright red
        'intrusion-set': '#FF6666',     // Light red
        'campaign': '#FFA500',          // Orange
        'malware': '#FF8C00',           // Orange-red
        'tool': '#1E90FF',              // Blue
        'attack-pattern': '#FF69B4',    // Pink/Violet
        'vulnerability': '#9932CC',     // Purple
        'indicator': '#32CD32',         // Lime green
        'observed-data': '#00CED1',     // Cyan
        'infrastructure': '#00BFFF',    // Sky blue
        'course-of-action': '#90EE90',  // Light green
        'identity': '#D3D3D3',          // Gray
        'location': '#8B4513',          // Brown
        'url': '#1E90FF',               // Blue (infrastructure)
        'domain-name': '#00CED1',      // Cyan
        'file': '#CCCCCC',              // Standard gray
        'marking-definition': '#D3D3D3', // Light gray
        'grouping': '#3498db',
        'incident': '#e67e22',
        'malware-analysis': '#d35400',
        'note': '#7f8c8d',
        'opinion': '#27ae60',
        'report': '#34495e',
        'artifact': '#bdc3c7',
        'autonomous-system': '#00BFFF',  // Sky blue (infrastructure)
        'directory': '#CCCCCC',          // Gray
        'email-addr': '#9b59b6',
        'email-message': '#8e44ad',
        'ipv4-addr': '#00CED1',          // Cyan (network)
        'ipv6-addr': '#00CED1',          // Cyan (network)
        'mac-addr': '#00CED1',           // Cyan (network)
        'mutex': '#e67e22',
        'network-traffic': '#00BFFF',    // Sky blue (infrastructure)
        'process': '#32CD32',            // Green (observable)
        'software': '#1E90FF',           // Blue (tool/infrastructure)
        'user-account': '#D3D3D3',       // Gray (identity)
        'windows-registry-key': '#CCCCCC', // Gray
        'x509-certificate': '#00CED1',   // Cyan
        'relationship': '#7f8c8d',
        'sighting': '#e67e22',
        'extension-definition': '#CCCCCC',
        'language-content': '#CCCCCC',
        'default': '#8B5CF6'
    };

    // Logical category grouping (5 categories as per standard)
    const STIX_CATEGORIES = {
        'ttps': ['attack-pattern', 'malware', 'tool'],
        'threat-actors': ['intrusion-set', 'threat-actor', 'campaign'],
        'evidence': ['observed-data', 'indicator'],
        'infrastructure': ['infrastructure', 'malware-analysis'],
        'context': ['vulnerability', 'course-of-action', 'identity', 'location']
    };
    
    // Get category for a STIX type
    function getCategoryForType(type) {
        for (const [category, types] of Object.entries(STIX_CATEGORIES)) {
            if (types.includes(type)) {
                return category;
            }
        }
        return 'other';
    }
    
    // Edge direction remapping for intuitive flow
    const EDGE_REMAP = {
        'attributed-to': true,  // Invert: Malware → attributed-to → Threat Actor
        'indicates': true,      // Invert: IoC → indicates → Malware
        'uses': false,          // Keep: Threat Actor → uses → Tool
        'targets': false,       // Keep: Threat Actor → targets → Victim
        'mitigates': false      // Keep: Course of Action → mitigates → Attack Pattern
    };

    // Relationship visual styles: use color and dash pattern instead of text labels
    const RELATIONSHIP_STYLES = {
        'indicates': { color: '#32CD32', dashes: false },      // Green, solid line
        'uses': { color: '#FF8C00', dashes: false },            // Orange, solid line
        'targets': { color: '#FF4444', dashes: false },         // Red, solid line
        'mitigates': { color: '#90EE90', dashes: true },        // Light green, dashed
        'attributed-to': { color: '#FF69B4', dashes: false },   // Pink, solid line
        'related-to': { color: '#D3D3D3', dashes: false },      // Gray, solid line
        'variant-of': { color: '#9932CC', dashes: true },       // Purple, dashed
        'duplicate-of': { color: '#7f8c8d', dashes: true }     // Dark gray, dashed
    };

    // Embedded relationships to visualize
    const EMBEDDED_RELATIONSHIPS = {
        'domain-name': [['resolves_to_refs', 'resolves-to', true]],
        'ipv4-addr': [['resolves_to_refs', 'resolves-to', true]],
        'ipv6-addr': [['resolves_to_refs', 'resolves-to', true]],
        'email-addr': [['belongs_to_ref', 'belongs-to', true]],
        'email-message': [
            ['from_ref', 'from', true],
            ['sender_ref', 'sender', true],
            ['to_refs', 'to', true],
            ['cc_refs', 'cc', true],
            ['bcc_refs', 'bcc', true],
            ['raw_email_ref', 'raw-email', true]
        ],
        'file': [
            ['contains_refs', 'contains', true],
            ['content_ref', 'content', true],
            ['parent_directory_ref', 'parent-directory', true]
        ],
        'grouping': [['object_refs', 'refers-to', true]],
        'malware': [['sample_refs', 'sample-of', true]],
        'malware-analysis': [['analysis_sco_refs', 'analysis-of', true]],
        'network-traffic': [
            ['src_ref', 'src', true],
            ['dst_ref', 'dst', true],
            ['src_payload_ref', 'src-payload', true],
            ['dst_payload_ref', 'dst-payload', true],
            ['encapsulates_refs', 'encapsulates', true],
            ['encapsulated_by_ref', 'encapsulated-by', true]
        ],
        'note': [['object_refs', 'refers-to', true]],
        'observed-data': [['object_refs', 'observed', true]],
        'opinion': [['object_refs', 'refers-to', true]],
        'process': [
            ['opened_connection_refs', 'opened-connection', true],
            ['creator_user_ref', 'creator', true],
            ['image_ref', 'image', true],
            ['parent_ref', 'parent', true]
        ],
        'sighting': [
            ['sighting_of_ref', 'sighting-of', true],
            ['observed_data_refs', 'observed-data', true],
            ['where_sighted_refs', 'where-sighted', true]
        ],
        'windows-registry-key': [['creator_user_ref', 'creator', true]],
        'report': [['object_refs', 'refers-to', true]]
    };

    // Timeline timestamps by type
    const TIMELINE_TIMESTAMPS = {
        'attack-pattern': ['modified', 'created'],
        'campaign': ['last_seen', 'first_seen', 'modified', 'created'],
        'course-of-action': ['modified', 'created'],
        'identity': ['modified', 'created'],
        'incident': ['modified', 'created'],
        'indicator': ['valid_until', 'valid_from', 'modified', 'created'],
        'infrastructure': ['last_seen', 'first_seen', 'modified', 'created'],
        'intrusion-set': ['last_seen', 'first_seen', 'modified', 'created'],
        'location': ['modified', 'created'],
        'malware': ['last_seen', 'first_seen', 'modified', 'created'],
        'malware-analysis': ['modified', 'created'],
        'note': ['modified', 'created'],
        'observed-data': ['last_observed', 'first_observed', 'modified', 'created'],
        'opinion': ['modified', 'created'],
        'report': ['published', 'modified', 'created'],
        'threat-actor': ['last_seen', 'first_seen', 'modified', 'created'],
        'tool': ['modified', 'created'],
        'vulnerability': ['modified', 'created'],
        'relationship': ['start_time', 'modified', 'created'],
        'sighting': ['last_seen', 'first_seen', 'modified', 'created']
    };

    /**
     * Parse STIX content from various formats
     * @param {string|object|array} content - STIX content
     * @returns {object} - Normalized STIX bundle
     */
    function parseStixContent(content) {
        let data = content;
        
        // Parse JSON string if needed
        if (typeof content === 'string') {
            try {
                data = JSON.parse(content);
            } catch (e) {
                throw new Error('Invalid JSON: ' + e.message);
            }
        }
        
        // Handle different input formats
        if (Array.isArray(data)) {
            return { type: 'bundle', objects: data };
        } else if (data.type === 'bundle' && data.objects) {
            return data;
        } else if (data.type && data.id) {
            // Single STIX object
            return { type: 'bundle', objects: [data] };
        }
        
        throw new Error('Invalid STIX content format');
    }

    /**
     * Get display label for a STIX object
     * @param {object} obj - STIX object
     * @param {object} config - Configuration
     * @returns {string} - Display label
     */
    function getDisplayLabel(obj, config = {}) {
        // Check for user-defined label
        if (config.userLabels && config.userLabels[obj.id]) {
            return config.userLabels[obj.id];
        }
        
        // Check for type-specific display property
        const typeConfig = config[obj.type];
        if (typeConfig && typeConfig.displayProperty && obj[typeConfig.displayProperty]) {
            return obj[typeConfig.displayProperty];
        }
        
        // Default display properties
        if (obj.name) return obj.name;
        if (obj.value) return obj.value;
        if (obj.pattern) return obj.pattern.substring(0, 50) + (obj.pattern.length > 50 ? '...' : '');
        if (obj.source_ref && obj.target_ref) {
            return obj.relationship_type || 'relationship';
        }
        
        // Fallback to type and ID
        return obj.type + '\n' + (obj.id ? obj.id.split('--')[1].substring(0, 8) : 'unknown');
    }

    /**
     * Get timestamp for a STIX object for timeline filtering
     * @param {object} obj - STIX object
     * @returns {Date|null} - Timestamp or null
     */
    function getTimestamp(obj) {
        const props = TIMELINE_TIMESTAMPS[obj.type] || ['modified', 'created'];
        for (const prop of props) {
            if (obj[prop]) {
                const date = new Date(obj[prop]);
                if (!isNaN(date.getTime())) {
                    return date;
                }
            }
        }
        return null;
    }

    /**
     * Create graph data from STIX content
     * @param {string|object} stixContent - STIX content
     * @param {object} config - Configuration options
     * @returns {object} - Graph data { nodes, edges, stixIdToObject, stats }
     */
    function makeGraphData(stixContent, config = {}) {
        const bundle = parseStixContent(stixContent);
        const nodes = [];
        const edges = [];
        const stixIdToObject = new Map();
        const typeCount = {};
        
        // Apply filters if specified
        let objects = bundle.objects || [];
        if (config.include) {
            objects = objects.filter(obj => matchesCriteria(obj, config.include));
        }
        if (config.exclude) {
            objects = objects.filter(obj => !matchesCriteria(obj, config.exclude));
        }
        
        // First pass: create nodes and build ID map, count relationships
        const relationshipCount = new Map();
        for (const obj of objects) {
            if (obj.type === 'relationship' && obj.source_ref && obj.target_ref) {
                relationshipCount.set(obj.source_ref, (relationshipCount.get(obj.source_ref) || 0) + 1);
                relationshipCount.set(obj.target_ref, (relationshipCount.get(obj.target_ref) || 0) + 1);
            }
        }
        
        // Get icon path once before creating nodes
        const iconPath = typeof STIX_ICONS_BASE_PATH !== 'undefined' ? STIX_ICONS_BASE_PATH : null;
        const defaultIconURL = getDefaultIconURL(iconPath);
        
        for (const obj of objects) {
            if (!obj.id) continue;
            
            stixIdToObject.set(obj.id, obj);
            
            // Count by type
            typeCount[obj.type] = (typeCount[obj.type] || 0) + 1;
            
            // Skip relationship objects for nodes (they become edges)
            if (obj.type === 'relationship') continue;
            
            const label = getDisplayLabel(obj, config);
            const timestamp = getTimestamp(obj);
            const category = getCategoryForType(obj.type);
            
            // Get relationship count for metadata (not used for sizing)
            const relCount = relationshipCount.get(obj.id) || 0;
            
            // Get confidence score for metadata
            const confidence = obj.confidence || 100;
            
            // Get icon URL for this node type
            const iconURL = stixTypeToIconURL(obj.type, iconPath);
            
            // Variable node sizing based on category importance
            // Threat actors (most important): 150% size
            // TTPs (medium importance): 100% size (default)
            // Indicators/IoCs (less important): 70% size
            let nodeSize = 30; // Default size for circularImage
            if (category === 'threat-actors') {
                nodeSize = 45; // 150% of default
            } else if (category === 'ttps') {
                nodeSize = 30; // 100% of default
            } else if (category === 'evidence' || category === 'infrastructure') {
                nodeSize = 21; // 70% of default
            }
            
            nodes.push({
                id: obj.id,
                label: label,
                // title: createTooltip(obj), // Disabled - using custom tooltip instead
                font: { color: '#fff', size: 12 },
                group: obj.type,  // Keep group for consistency
                shape: "circularImage",  // Force shape directly on node
                image: iconURL,  // Force image directly on node
                brokenImage: defaultIconURL,  // Fallback icon
                margin: 10,
                size: nodeSize,  // Variable size based on category importance
                stixType: obj.type,
                stixCategory: category,
                stixObject: obj,
                timestamp: timestamp,
                relationshipCount: relCount,
                confidence: confidence
            });
        }
        
        // Second pass: create edges from relationships
        // Find max confidence for edge width normalization
        let maxEdgeConfidence = 100;
        for (const obj of objects) {
            if (obj.type === 'relationship' && obj.confidence) {
                maxEdgeConfidence = Math.max(maxEdgeConfidence, obj.confidence);
            }
        }
        
        for (const obj of objects) {
            if (obj.type === 'relationship' && obj.source_ref && obj.target_ref) {
                // Only create edge if both endpoints exist
                if (stixIdToObject.has(obj.source_ref) && stixIdToObject.has(obj.target_ref)) {
                    const timestamp = getTimestamp(obj);
                    const relType = obj.relationship_type || 'related-to';
                    
                    // Edge direction remapping for intuitive flow
                    let from = obj.source_ref;
                    let to = obj.target_ref;
                    if (EDGE_REMAP[relType] === true) {
                        // Invert direction
                        from = obj.target_ref;
                        to = obj.source_ref;
                    }
                    
                    // Visual emphasis: width proportional to confidence
                    const confidence = obj.confidence || 50;
                    const widthRatio = confidence / maxEdgeConfidence;
                    const edgeWidth = Math.max(1, Math.min(5, 1 + widthRatio * 4));
                    
                    // Detect cross-layer edges (transversal)
                    const fromNode = nodes.find(n => n.id === from);
                    const toNode = nodes.find(n => n.id === to);
                    const fromLevel = fromNode?.level !== undefined ? fromNode.level : 0;
                    const toLevel = toNode?.level !== undefined ? toNode.level : 0;
                    const levelDiff = Math.abs(fromLevel - toLevel);
                    const isTransversal = levelDiff > 1;  // Cross-layer if skips more than one level
                    
                    // Create tooltip for edge
                    const edgeTooltip = `${relType}\nFrom: ${stixIdToObject.get(from)?.name || from}\nTo: ${stixIdToObject.get(to)?.name || to}\nConfidence: ${confidence}%`;
                    
                    // Edge styling: use relationship-specific colors and styles
                    // Hide labels by default to reduce visual clutter, show on hover
                    // Use dashes for low confidence edges (confidence < 50) to indicate uncertainty
                    const relStyle = RELATIONSHIP_STYLES[relType] || { color: '#888', dashes: false };
                    const edgeOpacity = confidence > 80 ? 1.0 : (confidence > 50 ? 0.6 : 0.25);
                    const edgeColor = relStyle.color || (confidence > 80 ? '#888' : (confidence > 50 ? '#666' : '#444'));
                    // Use dashes for low confidence (< 50) or if relationship style requires it, or if transversal
                    const useDashes = confidence < 50 || relStyle.dashes || isTransversal;
                    
                    edges.push({
                        id: obj.id,
                        from: from,
                        to: to,
                        label: '',  // Hide label by default, show on hover
                        arrows: 'to',
                        color: { 
                            color: edgeColor, 
                            highlight: '#8B5CF6', 
                            hover: '#8B5CF6',
                            opacity: edgeOpacity
                        },
                        font: { 
                            color: '#fff', 
                            size: 12, 
                            align: 'middle',
                            strokeWidth: 2,
                            strokeColor: '#000'
                        },
                        labelHighlightBold: true,
                        width: edgeWidth,
                        dashes: useDashes,
                        // title: edgeTooltip, // Disabled - using custom tooltip instead
                        smooth: { type: 'curvedCW', roundness: 0.2 },
                        stixObject: obj,
                        timestamp: timestamp,
                        confidence: confidence,
                        isTransversal: isTransversal,
                        fromLevel: fromLevel,
                        toLevel: toLevel,
                        relationshipType: relType  // Store for hover display
                    });
                }
            }
            
            // Create edges from embedded relationships
            const embeddedRels = EMBEDDED_RELATIONSHIPS[obj.type] || [];
            for (const [propPath, edgeLabel, direction] of embeddedRels) {
                const refs = getPropertyByPath(obj, propPath);
                if (!refs) continue;
                
                const refArray = Array.isArray(refs) ? refs : [refs];
                for (const ref of refArray) {
                    if (stixIdToObject.has(ref)) {
                        const from = direction ? obj.id : ref;
                        const to = direction ? ref : obj.id;
                        
                        // Check for duplicate
                        const exists = edges.some(e => e.from === from && e.to === to && e.relationshipType === edgeLabel);
                        if (!exists) {
                            const relStyle = RELATIONSHIP_STYLES[edgeLabel] || { color: '#888', dashes: false };
                            edges.push({
                                id: `embedded-${obj.id}-${ref}-${edgeLabel}`,
                                from: from,
                                to: to,
                                label: '',  // Hide label by default
                                relationshipType: edgeLabel,  // Store for hover display
                                arrows: 'to',
                                color: { 
                                    color: relStyle.color || '#666', 
                                    highlight: '#8B5CF6', 
                                    hover: '#8B5CF6',
                                    opacity: 0.8
                                },
                                font: { 
                                    color: '#fff', 
                                    size: 12, 
                                    align: 'middle',
                                    strokeWidth: 2,
                                    strokeColor: '#000'
                                },
                                labelHighlightBold: true,
                                width: 2,
                                dashes: relStyle.dashes !== undefined ? relStyle.dashes : true,
                                smooth: { type: 'curvedCW', roundness: 0.1 }
                            });
                        }
                    }
                }
            }
        }
        
        return {
            nodes: nodes,
            edges: edges,
            stixIdToObject: stixIdToObject,
            stats: {
                totalObjects: objects.length,
                nodeCount: nodes.length,
                edgeCount: edges.length,
                typeCount: typeCount
            }
        };
    }

    /**
     * Get property value by dot-notation path
     */
    function getPropertyByPath(obj, path) {
        const parts = path.split('.');
        let current = obj;
        for (const part of parts) {
            if (current === null || current === undefined) return undefined;
            current = current[part];
        }
        return current;
    }

    /**
     * Check if object matches filter criteria (MongoDB-like syntax)
     */
    function matchesCriteria(obj, criteria) {
        if (!criteria || typeof criteria !== 'object') return true;
        
        for (const [key, value] of Object.entries(criteria)) {
            if (key === '$and') {
                if (!Array.isArray(value)) return false;
                if (!value.every(c => matchesCriteria(obj, c))) return false;
            } else if (key === '$or') {
                if (!Array.isArray(value)) return false;
                if (!value.some(c => matchesCriteria(obj, c))) return false;
            } else if (key === '$not') {
                if (matchesCriteria(obj, value)) return false;
            } else {
                const objValue = getPropertyByPath(obj, key);
                if (!matchValue(objValue, value)) return false;
            }
        }
        return true;
    }

    /**
     * Match a single value against criteria
     */
    function matchValue(objValue, criteria) {
        if (criteria === null || criteria === undefined) {
            return objValue === criteria;
        }
        
        if (typeof criteria !== 'object') {
            return objValue === criteria;
        }
        
        for (const [op, val] of Object.entries(criteria)) {
            switch (op) {
                case '$eq': if (objValue !== val) return false; break;
                case '$ne': if (objValue === val) return false; break;
                case '$gt': if (!(objValue > val)) return false; break;
                case '$gte': if (!(objValue >= val)) return false; break;
                case '$lt': if (!(objValue < val)) return false; break;
                case '$lte': if (!(objValue <= val)) return false; break;
                case '$in': if (!Array.isArray(val) || !val.includes(objValue)) return false; break;
                case '$nin': if (Array.isArray(val) && val.includes(objValue)) return false; break;
                case '$exists': 
                    if (val && objValue === undefined) return false;
                    if (!val && objValue !== undefined) return false;
                    break;
                default:
                    // Treat as equality check
                    if (objValue !== criteria) return false;
            }
        }
        return true;
    }

    /**
     * Create tooltip text for a STIX object (plain text for better display)
     */
    function createTooltip(obj) {
        const parts = [];
        
        // Type and ID
        parts.push(`${obj.type.toUpperCase()}`);
        parts.push(`ID: ${obj.id.substring(0, 20)}${obj.id.length > 20 ? '...' : ''}`);
        
        // Name or value
        if (obj.name) {
            parts.push(`Name: ${obj.name.substring(0, 50)}${obj.name.length > 50 ? '...' : ''}`);
        } else if (obj.value) {
            parts.push(`Value: ${obj.value.substring(0, 50)}${obj.value.length > 50 ? '...' : ''}`);
        }
        
        // Description (truncated)
        if (obj.description) {
            const desc = obj.description.replace(/\n/g, ' ').substring(0, 100);
            parts.push(`Description: ${desc}${obj.description.length > 100 ? '...' : ''}`);
        }
        
        // Pattern (for indicators)
        if (obj.pattern) {
            parts.push(`Pattern: ${obj.pattern.substring(0, 60)}${obj.pattern.length > 60 ? '...' : ''}`);
        }
        
        // Confidence score
        if (obj.confidence !== undefined) {
            parts.push(`Confidence: ${obj.confidence}%`);
        }
        
        // Created/Modified dates
        if (obj.created) {
            parts.push(`Created: ${new Date(obj.created).toLocaleDateString()}`);
        }
        if (obj.modified) {
            parts.push(`Modified: ${new Date(obj.modified).toLocaleDateString()}`);
        }
        
        // Labels (for malware, threat actors)
        if (obj.labels && Array.isArray(obj.labels) && obj.labels.length > 0) {
            parts.push(`Labels: ${obj.labels.slice(0, 3).join(', ')}${obj.labels.length > 3 ? '...' : ''}`);
        }
        
        // Kill chain phases
        if (obj.kill_chain_phases && Array.isArray(obj.kill_chain_phases) && obj.kill_chain_phases.length > 0) {
            const phases = obj.kill_chain_phases.map(kc => kc.phase_name || kc.kill_chain_name).join(', ');
            parts.push(`Kill Chain: ${phases.substring(0, 40)}${phases.length > 40 ? '...' : ''}`);
        }
        
        return parts.join('\n');
    }

    /**
     * Escape HTML special characters
     */
    function escapeHtml(text) {
        if (!text) return '';
        return String(text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    /**
     * Create graph view in a DOM element
     * @param {HTMLElement} container - Container element
     * @param {array} nodes - Node data
     * @param {array} edges - Edge data  
     * @param {Map} stixIdToObject - STIX ID to object map
     * @param {object} config - Configuration
     * @returns {object} - Network instance and control methods
     */
    function makeGraphView(container, nodes, edges, stixIdToObject, config = {}) {
        // Check if vis.js is available
        if (typeof vis === 'undefined') {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #e74c3c;">Error: vis.js library not loaded</div>';
            return null;
        }
        
        // Create DataSets
        const nodesDataSet = new vis.DataSet(nodes);
        const edgesDataSet = new vis.DataSet(edges);
        
        // Determine if clustering should be enabled (more intelligent clustering)
        // Only cluster when really necessary for performance
        const shouldCluster = (nodes.length > 500 || edges.length > 1000) && config.enableClustering !== false;
        const edgeRouting = config.edgeRouting || 'curved'; // 'curved' or 'orthogonal'
        const useHierarchical = config.hierarchical !== false && nodes.length > 20 && !shouldCluster; // Enable for medium graphs, disable if clustering
        
        // Create groups for each STIX type with PNG icons
        const iconPath = typeof STIX_ICONS_BASE_PATH !== 'undefined' ? STIX_ICONS_BASE_PATH : null;
        const defaultIconURL = getDefaultIconURL(iconPath);
        const groups = {};
        const uniqueTypes = new Set(nodes.map(n => n.stixType));
        uniqueTypes.forEach(stixType => {
            const iconURL = stixTypeToIconURL(stixType, iconPath);
            groups[stixType] = {
                shape: "circularImage",
                image: iconURL,
                brokenImage: defaultIconURL
            };
        });
        
        // Define hierarchical levels based on STIX categories
        // Layer 0: Threat Actors, Layer 1: Campaigns, Layer 2: Malware/Tools, Layer 3: IoCs/Infrastructure
        const getHierarchicalLevel = (node) => {
            const category = node.stixCategory || 'other';
            if (category === 'threat-actors') return 0;
            if (node.stixType === 'campaign') return 1;
            if (category === 'ttps') return 2;
            if (category === 'evidence' || category === 'infrastructure') return 3;
            return 4; // Context and others
        };
        
        // Apply hierarchical levels to nodes (always, for cross-layer edge detection)
        nodes.forEach(node => {
            node.level = getHierarchicalLevel(node);
        });
        
        // Network options
        const options = {
            groups: groups,  // Use icon-based groups
            nodes: {
                margin: 10,
                font: { color: '#fff', size: 12 },
                borderWidth: 2,
                shadow: false,  // Disable shadow for better performance
                // Note: No scaling configuration - uses default uniform size
                // This matches the original cti-stix-visualization behavior
                // Simplified hover/selection state for better performance
                chosen: {
                    node: function(values, id, selected, hovering) {
                        if (selected || hovering) {
                            values.borderWidth = 3;  // Reduced border width
                            values.borderColor = '#8B5CF6';
                        } else {
                            values.borderWidth = 2;  // Default border width
                        }
                    }
                }
            },
            edges: {
                smooth: edgeRouting === 'orthogonal' ? {
                    type: 'straight',
                    roundness: 0
                } : {
                    type: 'curvedCW',
                    roundness: 0.2
                },
                arrows: { to: { enabled: true, scaleFactor: 0.8 } },
                font: { 
                    size: 12, 
                    align: 'middle',
                    color: '#fff',
                    strokeWidth: 2,
                    strokeColor: '#000'
                },
                labelHighlightBold: true,
                shadow: false  // Disable shadow for better performance
            },
            physics: useHierarchical ? {
                enabled: false  // Disable physics for hierarchical layout
            } : {
                enabled: true,
                solver: 'forceAtlas2Based',
                forceAtlas2Based: {
                    gravitationalConstant: -30,  // Reduced for better performance
                    centralGravity: 0.005,       // Reduced central gravity
                    springLength: 100,           // Shorter springs for tighter layout
                    springConstant: 0.05,        // Reduced spring constant
                    damping: 0.6,                // Increased damping for faster stabilization
                    avoidOverlap: 0.3            // Reduced overlap avoidance
                },
                stabilization: {
                    enabled: true,
                    iterations: 100,             // Reduced iterations for faster stabilization
                    updateInterval: 50           // Increased update interval to reduce CPU usage
                },
                timestep: 0.3,                  // Smaller timestep for smoother but faster simulation
                adaptiveTimestep: true          // Enable adaptive timestep for better performance
            },
            interaction: {
                hover: true,
                tooltipDelay: 0, // Disabled - using custom tooltip instead
                hideEdgesOnDrag: true,
                navigationButtons: true,
                keyboard: true,
                hoverConnectedEdges: true
            },
            layout: {
                improvedLayout: !useHierarchical,
                hierarchical: useHierarchical ? {
                    enabled: true,
                    direction: 'UD',  // Up-Down
                    sortMethod: 'hubsize',  // Changed from 'directed' for better results
                    levelSeparation: 320,  // Increased for better vertical spacing
                    nodeSpacing: 200,  // Increased horizontal spacing to reduce saturation
                    treeSpacing: 280,  // Increased spacing between trees for better layout
                    blockShifting: true,
                    edgeMinimization: true,
                    parentCentralization: true,
                    shakeTowards: 'leaves'  // Push leaves towards bottom
                } : false
            }
        };
        
        // Create network
        const network = new vis.Network(container, { nodes: nodesDataSet, edges: edgesDataSet }, options);
        
        // Disable vis.js default tooltips completely
        // Remove any tooltips created by vis.js
        const removeVisTooltips = () => {
            // Remove tooltips by class
            const visTooltips = document.querySelectorAll('.vis-tooltip');
            visTooltips.forEach(tooltip => tooltip.remove());
            
            // Remove tooltips by checking if they're created by vis.js
            const allDivs = document.querySelectorAll('div');
            allDivs.forEach(div => {
                if (div.style && div.style.position === 'absolute' && 
                    div.style.zIndex && parseInt(div.style.zIndex) > 1000 &&
                    div.textContent && div !== tooltip) {
                    // Check if it looks like a vis.js tooltip (white background, positioned absolutely)
                    const bgColor = window.getComputedStyle(div).backgroundColor;
                    if (bgColor && (bgColor.includes('rgb(255') || bgColor.includes('rgba(255'))) {
                        div.remove();
                    }
                }
            });
        };
        
        // Remove tooltips periodically and on events
        setInterval(removeVisTooltips, 100);
        network.on('hoverNode', removeVisTooltips);
        network.on('hoverEdge', removeVisTooltips);
        network.on('blurNode', removeVisTooltips);
        network.on('blurEdge', removeVisTooltips);
        
        // Track original edge opacities and labels for restoration
        const originalEdgeOpacities = new Map();
        const originalEdgeLabels = new Map();
        edgesDataSet.forEach(edge => {
            originalEdgeOpacities.set(edge.id, edge.color.opacity || 1.0);
            originalEdgeLabels.set(edge.id, edge.label || '');
        });
        
        // Track original node labels and opacities for zoom-based visibility and focus halo
        const originalNodeLabels = new Map();
        const originalNodeOpacities = new Map();
        nodesDataSet.forEach(node => {
            originalNodeLabels.set(node.id, node.label || '');
            originalNodeOpacities.set(node.id, 1.0); // Nodes are fully opaque by default
        });
        
        // Handle node selection: emphasize connected nodes and edges, de-emphasize others (focus halo)
        network.on('selectNode', function(params) {
            if (params.nodes.length === 0) return;

            const selectedNodeId = params.nodes[0];
            const connectedNodeIds = new Set([selectedNodeId]); // Include selected node
            const connectedEdgeIds = new Set();

            // Find all nodes and edges connected to selected node (optimized)
            const edgesToProcess = [];
            edgesDataSet.forEach(edge => {
                if (edge.from === selectedNodeId || edge.to === selectedNodeId) {
                    connectedEdgeIds.add(edge.id);
                    edgesToProcess.push(edge);
                    if (edge.from === selectedNodeId) connectedNodeIds.add(edge.to);
                    if (edge.to === selectedNodeId) connectedNodeIds.add(edge.from);
                }
            });

            // Batch node updates for better performance
            const nodeUpdates = [];
            const totalNodes = nodesDataSet.length;
            if (totalNodes > 1000) {
                // For very large graphs, only update visible nodes for performance
                const visibleNodes = network.getView().nodes || [];
                nodesDataSet.forEach(node => {
                    if (visibleNodes.includes(node.id)) {
                        const isConnected = connectedNodeIds.has(node.id);
                        const originalOpacity = originalNodeOpacities.get(node.id) || 1.0;
                        nodeUpdates.push({
                            id: node.id,
                            opacity: isConnected ? originalOpacity : 0.3  // Less aggressive dimming
                        });
                    }
                });
            } else {
                // For smaller graphs, update all nodes
                nodesDataSet.forEach(node => {
                    const isConnected = connectedNodeIds.has(node.id);
                    const originalOpacity = originalNodeOpacities.get(node.id) || 1.0;
                    nodeUpdates.push({
                        id: node.id,
                        opacity: isConnected ? originalOpacity : 0.3  // Less aggressive dimming
                    });
                });
            }

            // Batch edge updates for better performance
            const edgeUpdates = [];
            edgesToProcess.forEach(edge => {
                const originalOpacity = originalEdgeOpacities.get(edge.id) || 1.0;
                edgeUpdates.push({
                    id: edge.id,
                    color: {
                        ...edge.color,
                        opacity: Math.min(1.0, originalOpacity * 1.1)  // Reduced emphasis
                    },
                    width: (edge.width || 2) + 1  // Reduced width increase
                });
            });

            // De-emphasize non-connected edges (batch operation)
            const nonConnectedEdges = [];
            edgesDataSet.forEach(edge => {
                if (!connectedEdgeIds.has(edge.id)) {
                    nonConnectedEdges.push({
                        id: edge.id,
                        color: {
                            ...edge.color,
                            opacity: 0.2  // Less aggressive dimming
                        }
                    });
                }
            });

            // Apply updates in batches
            if (nodeUpdates.length > 0) {
                nodesDataSet.update(nodeUpdates);
            }
            if (edgeUpdates.length > 0) {
                edgesDataSet.update(edgeUpdates);
            }
            if (nonConnectedEdges.length > 0 && nonConnectedEdges.length < 500) {  // Limit for performance
                edgesDataSet.update(nonConnectedEdges);
            }
        });
        
        // Debounce function for performance optimization
        function debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func.apply(this, args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }

        // Handle node hover: emphasize connected edges, de-emphasize others (debounced)
        const debouncedHoverNode = debounce(function(params) {
            if (!params.node) return;

            const hoveredNodeId = params.node;
            const connectedEdgeIds = new Set();

            // Find all edges connected to hovered node
            edgesDataSet.forEach(edge => {
                if (edge.from === hoveredNodeId || edge.to === hoveredNodeId) {
                    connectedEdgeIds.add(edge.id);
                }
            });

            // Update edge opacities: emphasize connected, de-emphasize others
            const updates = [];
            edgesDataSet.forEach(edge => {
                const isConnected = connectedEdgeIds.has(edge.id);
                const originalOpacity = originalEdgeOpacities.get(edge.id) || 1.0;

                if (isConnected) {
                    updates.push({
                        id: edge.id,
                        color: {
                            ...edge.color,
                            opacity: Math.min(1.0, originalOpacity * 1.1)
                        }
                    });
                } else {
                    updates.push({
                        id: edge.id,
                        color: {
                            ...edge.color,
                            opacity: 0.2
                        }
                    });
                }
            });

            if (updates.length > 0) {
                edgesDataSet.update(updates);
            }
        }, 50); // 50ms debounce for smooth but responsive interaction

        network.on('hoverNode', debouncedHoverNode);
        
        // Handle node blur: restore all edge opacities
        network.on('blurNode', function() {
            const updates = [];
            edgesDataSet.forEach(edge => {
                const originalOpacity = originalEdgeOpacities.get(edge.id) || 1.0;
                updates.push({
                    id: edge.id,
                    color: {
                        ...edge.color,
                        opacity: originalOpacity
                    }
                });
            });
            if (updates.length > 0) {
                edgesDataSet.update(updates);
            }
        });
        
        // Handle edge hover: show relationship type label (debounced)
        const debouncedHoverEdge = debounce(function(params) {
            if (params.edge) {
                const edge = edgesDataSet.get(params.edge);
                if (edge && edge.relationshipType) {
                    edgesDataSet.update({
                        id: params.edge,
                        label: edge.relationshipType
                    });
                }
            }
        }, 100); // 100ms debounce for edge hover

        network.on('hoverEdge', debouncedHoverEdge);

        // Handle edge blur: hide relationship type label (debounced)
        const debouncedBlurEdge = debounce(function(params) {
            if (params.edge) {
                edgesDataSet.update({
                    id: params.edge,
                    label: ''
                });
            }
        }, 100); // 100ms debounce for edge blur

        network.on('blurEdge', debouncedBlurEdge);
        
        // Handle zoom: hide node labels when zoomed out too far
        let zoomTimeout;
        network.on('zoom', function(params) {
            // Debounce zoom events for performance - increased delay
            clearTimeout(zoomTimeout);
            zoomTimeout = setTimeout(function() {
                const scale = params.scale || 1.0;
                const updates = [];

                // Hide labels if zoom scale < 0.7 (zoomed out) - increased threshold
                const shouldShowLabels = scale >= 0.7;

                nodesDataSet.forEach(node => {
                    const originalLabel = originalNodeLabels.get(node.id) || '';
                    updates.push({
                        id: node.id,
                        label: shouldShowLabels ? originalLabel : ''
                    });
                });

                if (updates.length > 0) {
                    nodesDataSet.update(updates);
                }
            }, 200); // Increased debounce delay for better performance
        });
        
        // Handle node deselection: restore all node and edge opacities
        network.on('deselectNode', function() {
            const nodeUpdates = [];
            nodesDataSet.forEach(node => {
                const originalOpacity = originalNodeOpacities.get(node.id) || 1.0;
                nodeUpdates.push({
                    id: node.id,
                    opacity: originalOpacity
                });
            });
            
            const edgeUpdates = [];
            edgesDataSet.forEach(edge => {
                const originalOpacity = originalEdgeOpacities.get(edge.id) || 1.0;
                const originalWidth = edge.width || 2;
                
                edgeUpdates.push({
                    id: edge.id,
                    color: {
                        ...edge.color,
                        opacity: originalOpacity
                    },
                    width: originalWidth
                });
            });
            
            if (nodeUpdates.length > 0) {
                nodesDataSet.update(nodeUpdates);
            }
            if (edgeUpdates.length > 0) {
                edgesDataSet.update(edgeUpdates);
            }
            
            if (updates.length > 0) {
                edgesDataSet.update(updates);
            }
        });
        
        // Create or reuse custom tooltip element
        let tooltip = document.getElementById('stix-custom-tooltip');
        if (!tooltip) {
            tooltip = document.createElement('div');
            tooltip.id = 'stix-custom-tooltip';
            tooltip.style.cssText = 'position: fixed; background: rgba(30, 27, 46, 0.98); border: 2px solid #8B5CF6; border-radius: 8px; padding: 12px; font-size: 12px; color: #fff; max-width: 400px; z-index: 9999; pointer-events: none; display: none; box-shadow: 0 4px 12px rgba(0,0,0,0.3); font-family: monospace; line-height: 1.6;';
            document.body.appendChild(tooltip);
        }
        
        // Custom tooltip on hover
        let tooltipTimeout = null;
        network.on('hoverNode', function(params) {
            clearTimeout(tooltipTimeout);
            const nodeId = params.node;
            const node = nodesDataSet.get(nodeId);
            if (!node || !node.stixObject) return;
            
            const obj = node.stixObject;
            let tooltipContent = '';
            
            // Type and ID
            tooltipContent += `<div style="font-weight: bold; color: #8B5CF6; margin-bottom: 8px; font-size: 14px;">${escapeHtml(obj.type.toUpperCase())}</div>`;
            tooltipContent += `<div style="margin-bottom: 4px; color: #aaa;">ID: <span style="color: #fff;">${escapeHtml(obj.id.substring(0, 30))}${obj.id.length > 30 ? '...' : ''}</span></div>`;
            
            // Name or value
            if (obj.name) {
                tooltipContent += `<div style="margin-bottom: 4px;"><strong style="color: #8B5CF6;">Name:</strong> <span style="color: #fff;">${escapeHtml(obj.name)}</span></div>`;
            } else if (obj.value) {
                tooltipContent += `<div style="margin-bottom: 4px;"><strong style="color: #8B5CF6;">Value:</strong> <span style="color: #fff;">${escapeHtml(obj.value)}</span></div>`;
            }
            
            // Description
            if (obj.description) {
                const desc = escapeHtml(obj.description.replace(/\n/g, ' ').substring(0, 150));
                tooltipContent += `<div style="margin-bottom: 4px; color: #ccc;">${desc}${obj.description.length > 150 ? '...' : ''}</div>`;
            }
            
            // Pattern (for indicators)
            if (obj.pattern) {
                tooltipContent += `<div style="margin-bottom: 4px;"><strong style="color: #8B5CF6;">Pattern:</strong> <code style="background: rgba(139, 92, 246, 0.2); padding: 2px 4px; border-radius: 3px;">${escapeHtml(obj.pattern.substring(0, 80))}${obj.pattern.length > 80 ? '...' : ''}</code></div>`;
            }
            
            // Confidence score
            if (obj.confidence !== undefined) {
                const confColor = obj.confidence >= 80 ? '#32CD32' : (obj.confidence >= 50 ? '#FFA500' : '#FF4444');
                tooltipContent += `<div style="margin-bottom: 4px;"><strong style="color: #8B5CF6;">Confidence:</strong> <span style="color: ${confColor};">${obj.confidence}%</span></div>`;
            }
            
            // Labels
            if (obj.labels && Array.isArray(obj.labels) && obj.labels.length > 0) {
                tooltipContent += `<div style="margin-bottom: 4px;"><strong style="color: #8B5CF6;">Labels:</strong> <span style="color: #fff;">${escapeHtml(obj.labels.slice(0, 5).join(', '))}${obj.labels.length > 5 ? '...' : ''}</span></div>`;
            }
            
            // Kill chain phases
            if (obj.kill_chain_phases && Array.isArray(obj.kill_chain_phases) && obj.kill_chain_phases.length > 0) {
                const phases = obj.kill_chain_phases.map(kc => kc.phase_name || kc.kill_chain_name).join(', ');
                tooltipContent += `<div style="margin-bottom: 4px;"><strong style="color: #8B5CF6;">Kill Chain:</strong> <span style="color: #fff;">${escapeHtml(phases)}</span></div>`;
            }
            
            // External references (sources)
            if (obj.external_references && Array.isArray(obj.external_references) && obj.external_references.length > 0) {
                const sources = obj.external_references
                    .filter(ref => ref.source_name)
                    .map(ref => ref.source_name)
                    .slice(0, 5);
                if (sources.length > 0) {
                    tooltipContent += `<div style="margin-bottom: 4px;"><strong style="color: #8B5CF6;">Sources:</strong> <span style="color: #fff;">${escapeHtml(sources.join(', '))}${obj.external_references.length > 5 ? '...' : ''}</span></div>`;
                }
            }
            
            // Location information (for location objects or objects with location properties)
            if (obj.type === 'location' && obj.country) {
                tooltipContent += `<div style="margin-bottom: 4px;"><strong style="color: #8B5CF6;">Country:</strong> <span style="color: #fff;">${escapeHtml(obj.country)}</span></div>`;
            }
            if (obj.type === 'autonomous-system' && obj.number) {
                tooltipContent += `<div style="margin-bottom: 4px;"><strong style="color: #8B5CF6;">ASN:</strong> <span style="color: #fff;">AS${obj.number}</span></div>`;
            }
            if (obj.type === 'ipv4-addr' || obj.type === 'ipv6-addr') {
                // Try to extract country from extensions or external references
                const countryRef = obj.external_references?.find(ref => ref.source_name === 'geolocation' || ref.source_name === 'maxmind');
                if (countryRef && countryRef.external_id) {
                    tooltipContent += `<div style="margin-bottom: 4px;"><strong style="color: #8B5CF6;">Location:</strong> <span style="color: #fff;">${escapeHtml(countryRef.external_id)}</span></div>`;
                }
            }
            
            // Dates
            if (obj.created) {
                tooltipContent += `<div style="margin-bottom: 4px; color: #aaa; font-size: 11px;">Created: ${new Date(obj.created).toLocaleString()}</div>`;
            }
            if (obj.modified) {
                tooltipContent += `<div style="margin-bottom: 4px; color: #aaa; font-size: 11px;">Modified: ${new Date(obj.modified).toLocaleString()}</div>`;
            }
            
            // First seen / Last seen (for temporal context)
            if (obj.first_seen) {
                tooltipContent += `<div style="margin-bottom: 4px; color: #aaa; font-size: 11px;">First Seen: ${new Date(obj.first_seen).toLocaleString()}</div>`;
            }
            if (obj.last_seen) {
                tooltipContent += `<div style="margin-bottom: 4px; color: #aaa; font-size: 11px;">Last Seen: ${new Date(obj.last_seen).toLocaleString()}</div>`;
            }
            
            // Relationship count
            if (node.relationshipCount !== undefined) {
                tooltipContent += `<div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(139, 92, 246, 0.3); color: #aaa; font-size: 11px;">Relationships: ${node.relationshipCount}</div>`;
            }
            
            tooltip.innerHTML = tooltipContent;
            tooltip.style.display = 'block';
            
            // Update tooltip position
            try {
                const canvasPosition = network.getPositions([nodeId])[nodeId];
                const canvasBounds = container.getBoundingClientRect();
                const point = network.canvasToDOM({ x: canvasPosition.x, y: canvasPosition.y });
                
                tooltip.style.left = (canvasBounds.left + point.x + 20) + 'px';
                tooltip.style.top = (canvasBounds.top + point.y - 10) + 'px';
            } catch (e) {
                // Fallback positioning
                const rect = container.getBoundingClientRect();
                tooltip.style.left = (rect.left + rect.width / 2) + 'px';
                tooltip.style.top = (rect.top + 20) + 'px';
            }
        });
        
        network.on('blurNode', function() {
            tooltipTimeout = setTimeout(() => {
                tooltip.style.display = 'none';
            }, 100);
        });
        
        // Hide tooltip when mouse leaves
        container.addEventListener('mouseleave', function() {
            tooltip.style.display = 'none';
        });
        
        // Store tooltip reference for cleanup
        network.tooltipElement = tooltip;
        
        // Enable clustering for IoCs by context (after network creation) - only when necessary
        if (shouldCluster && !useHierarchical) {
            // Only cluster if we have many IoCs to avoid performance overhead
            const iocNodes = nodes.filter(n => n.stixType === 'indicator' || n.stixType === 'observed-data');
            if (iocNodes.length > 50) {  // Only cluster if we have many IoCs
                const iocClusters = new Map();

                // Group IoCs by common source/target relationships (limit processing for performance)
                iocNodes.slice(0, 200).forEach(ioc => {  // Limit to first 200 IoCs for performance
                    const relatedIds = new Set();
                    edges.forEach(edge => {
                        if (edge.from === ioc.id) relatedIds.add(edge.to);
                        if (edge.to === ioc.id) relatedIds.add(edge.from);
                    });
                    const clusterKey = Array.from(relatedIds).sort().join(',');
                    if (!iocClusters.has(clusterKey)) {
                        iocClusters.set(clusterKey, []);
                    }
                    iocClusters.get(clusterKey).push(ioc.id);
                });

                // Apply clustering for groups with more than 5 IoCs (increased threshold)
                iocClusters.forEach((iocIds, clusterKey) => {
                    if (iocIds.length > 5) {
                        try {
                            network.cluster({
                                joinCondition: function(nodeOptions) {
                                    return iocIds.includes(nodeOptions.id);
                                },
                                processProperties: function(clusterOptions, childNodes) {
                                    clusterOptions.label = `IoCs (${childNodes.length})`;
                                    clusterOptions.color = {
                                        background: STIX_COLORS.indicator || STIX_COLORS.default,
                                        border: STIX_COLORS.indicator || STIX_COLORS.default,
                                        highlight: {
                                            background: STIX_COLORS.indicator || STIX_COLORS.default,
                                            border: '#fff'
                                        }
                                    };
                                    clusterOptions.font = { size: 12, color: '#fff' };  // Reduced font size
                                    clusterOptions.shape = 'circularImage';
                                    clusterOptions.image = stixTypeToIconURL('indicator', iconPath);
                                    clusterOptions.brokenImage = defaultIconURL;
                                    clusterOptions.borderWidth = 2;  // Reduced border width
                                    return clusterOptions;
                                },
                                clusterNodeProperties: {
                                    borderWidth: 2,  // Reduced border width
                                    shape: 'circularImage',
                                    font: { size: 12, color: '#fff' }  // Reduced font size
                                }
                            });
                        } catch (error) {
                            console.warn('Failed to cluster IoCs:', error);
                        }
                    }
                });
            }
        }
        
        // Hidden types tracking
        const hiddenTypes = new Set();
        const hiddenRelTypes = new Set();
        
        // Return control object
        return {
            network: network,
            nodesDataSet: nodesDataSet,
            edgesDataSet: edgesDataSet,
            stixIdToObject: stixIdToObject,
            graphData: { nodes: nodes, edges: edges },  // Expose graph data for relationship count access
            
            // Show/hide nodes by type
            toggleType: function(type, visible) {
                if (visible) {
                    hiddenTypes.delete(type);
                } else {
                    hiddenTypes.add(type);
                }
                
                const updates = [];
                nodesDataSet.forEach(node => {
                    if (node.stixType === type) {
                        updates.push({ id: node.id, hidden: !visible });
                    }
                });
                nodesDataSet.update(updates);
            },
            
            // Show/hide edges by relationship type
            toggleRelationshipType: function(relType, visible) {
                if (visible) {
                    hiddenRelTypes.delete(relType);
                } else {
                    hiddenRelTypes.add(relType);
                }
                
                const updates = [];
                edgesDataSet.forEach(edge => {
                    if (edge.label === relType) {
                        updates.push({ id: edge.id, hidden: !visible });
                    }
                });
                edgesDataSet.update(updates);
            },
            
            // Search nodes by text (enhanced full-text search)
            searchNodes: function(query) {
                const queryLower = query.toLowerCase();
                const matches = [];
                
                nodesDataSet.forEach(node => {
                    const obj = stixIdToObject.get(node.id);
                    if (!obj) return;
                    
                    // Enhanced search: include all text fields
                    const searchFields = [
                        obj.id,
                        obj.type,
                        obj.name || '',
                        obj.value || '',
                        obj.description || '',
                        obj.pattern || '',
                        // Additional fields for full-text search
                        (obj.labels || []).join(' '),
                        (obj.aliases || []).join(' '),
                        (obj.external_references || []).map(ref => ref.source_name || ref.external_id || '').join(' '),
                        (obj.kill_chain_phases || []).map(kc => kc.phase_name || '').join(' '),
                        (obj.x_mitre_aliases || []).join(' '),
                        obj.x_mitre_id || '',
                        // Notes and opinions
                        (obj.object_refs || []).join(' '),
                        obj.abstract || '',
                        obj.content || ''
                    ];
                    
                    const searchText = searchFields.join(' ').toLowerCase();
                    
                    if (searchText.includes(queryLower)) {
                        matches.push(node.id);
                    }
                });
                
                return matches;
            },
            
            // Toggle category visibility
            toggleCategory: function(category, visible) {
                const categoryTypes = STIX_CATEGORIES[category] || [];
                const updates = [];
                nodesDataSet.forEach(node => {
                    if (categoryTypes.includes(node.stixType)) {
                        updates.push({ id: node.id, hidden: !visible });
                    }
                });
                nodesDataSet.update(updates);
            },
            
            // Filter by source/venue
            filterBySource: function(sourcePattern, visible) {
                const updates = [];
                nodesDataSet.forEach(node => {
                    const obj = stixIdToObject.get(node.id);
                    if (!obj) return;
                    
                    // Check external_references for source
                    const hasSource = (obj.external_references || []).some(ref => {
                        const sourceName = (ref.source_name || '').toLowerCase();
                        return sourceName.includes(sourcePattern.toLowerCase());
                    });
                    
                    if (hasSource) {
                        updates.push({ id: node.id, hidden: !visible });
                    }
                });
                nodesDataSet.update(updates);
            },
            
            // Highlight nodes
            highlightNodes: function(nodeIds) {
                const updates = [];
                nodesDataSet.forEach(node => {
                    const isHighlighted = nodeIds.includes(node.id);
                    updates.push({
                        id: node.id,
                        borderWidth: isHighlighted ? 4 : 2,
                        borderColor: isHighlighted ? '#FFD700' : '#8B5CF6'
                    });
                });
                nodesDataSet.update(updates);
            },
            
            // Find path between two nodes (improved: returns all paths)
            findPath: function(fromId, toId, maxPaths = 10) {
                const allPaths = [];
                const visited = new Set();
                const queue = [[fromId, [fromId]]];
                
                while (queue.length > 0 && allPaths.length < maxPaths) {
                    const [currentId, path] = queue.shift();
                    
                    if (currentId === toId) {
                        allPaths.push([...path]);
                        continue;
                    }
                    
                    // Allow revisiting nodes for finding all paths (but limit depth)
                    if (path.length > 10) continue; // Prevent infinite loops
                    
                    const pathKey = path.join('->');
                    if (visited.has(pathKey)) continue;
                    visited.add(pathKey);
                    
                    // Find all edges from and to this node
                    edgesDataSet.forEach(edge => {
                        if (edge.hidden) return;
                        
                        if (edge.from === currentId && !path.includes(edge.to)) {
                            queue.push([edge.to, [...path, edge.to]]);
                        } else if (edge.to === currentId && !path.includes(edge.from)) {
                            queue.push([edge.from, [...path, edge.from]]);
                        }
                    });
                }
                
                // Return shortest path first, or all paths if multiple
                if (allPaths.length === 0) return null;
                if (allPaths.length === 1) return allPaths[0];
                return allPaths.sort((a, b) => a.length - b.length); // Sort by length
            },
            
            // Expand/contract node: show/hide only direct connections
            expandNode: function(nodeId, expand = true) {
                const updates = [];
                const node = nodesDataSet.get(nodeId);
                if (!node) return;
                
                // Find direct connections
                const connectedNodeIds = new Set();
                edgesDataSet.forEach(edge => {
                    if (edge.hidden) return;
                    if (edge.from === nodeId) connectedNodeIds.add(edge.to);
                    if (edge.to === nodeId) connectedNodeIds.add(edge.from);
                });
                
                // Show/hide connected nodes
                nodesDataSet.forEach(n => {
                    if (connectedNodeIds.has(n.id)) {
                        updates.push({ id: n.id, hidden: !expand });
                    }
                });
                nodesDataSet.update(updates);
            },
            
            // Expand node with filters: show only connections matching type and relation filters
            expandNodeWithFilters: function(nodeId, typeFilters = [], relationFilters = []) {
                const updates = [];
                const node = nodesDataSet.get(nodeId);
                if (!node) return { added: 0, filtered: 0 };
                
                // Find direct connections with their edges
                const connectedNodes = new Map(); // nodeId -> { node, edges: [edgeIds] }
                edgesDataSet.forEach(edge => {
                    if (edge.hidden) return;
                    
                    let targetNodeId = null;
                    if (edge.from === nodeId) {
                        targetNodeId = edge.to;
                    } else if (edge.to === nodeId) {
                        targetNodeId = edge.from;
                    }
                    
                    if (targetNodeId) {
                        if (!connectedNodes.has(targetNodeId)) {
                            const targetNode = nodesDataSet.get(targetNodeId);
                            if (targetNode) {
                                connectedNodes.set(targetNodeId, {
                                    node: targetNode,
                                    edges: []
                                });
                            }
                        }
                        if (connectedNodes.has(targetNodeId)) {
                            connectedNodes.get(targetNodeId).edges.push(edge.id);
                        }
                    }
                });
                
                let added = 0;
                let filtered = 0;
                
                // Filter and show matching nodes
                connectedNodes.forEach((data, connectedNodeId) => {
                    const connectedNode = data.node;
                    const connectedEdges = data.edges;
                    
                    // Check if node type matches filter
                    const typeMatches = typeFilters.length === 0 || typeFilters.includes(connectedNode.stixType);
                    
                    // Check if any edge relation type matches filter
                    let relationMatches = relationFilters.length === 0;
                    if (!relationMatches && connectedEdges.length > 0) {
                        for (const edgeId of connectedEdges) {
                            const edge = edgesDataSet.get(edgeId);
                            if (edge && edge.relationshipType) {
                                if (relationFilters.includes(edge.relationshipType)) {
                                    relationMatches = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if (typeMatches && relationMatches) {
                        updates.push({ id: connectedNodeId, hidden: false });
                        added++;
                    } else {
                        filtered++;
                    }
                });
                
                if (updates.length > 0) {
                    nodesDataSet.update(updates);
                }
                
                return { added, filtered };
            },
            
            // Get available types and relations for a node (for filter popup)
            getNodeConnectionInfo: function(nodeId) {
                const node = nodesDataSet.get(nodeId);
                if (!node) return { types: [], relations: [] };
                
                const types = new Set();
                const relations = new Set();
                
                edgesDataSet.forEach(edge => {
                    if (edge.hidden) return;
                    
                    let targetNodeId = null;
                    if (edge.from === nodeId) {
                        targetNodeId = edge.to;
                    } else if (edge.to === nodeId) {
                        targetNodeId = edge.from;
                    }
                    
                    if (targetNodeId) {
                        const targetNode = nodesDataSet.get(targetNodeId);
                        if (targetNode) {
                            types.add(targetNode.stixType);
                        }
                        if (edge.relationshipType) {
                            relations.add(edge.relationshipType);
                        }
                    }
                });
                
                return {
                    types: Array.from(types).sort(),
                    relations: Array.from(relations).sort()
                };
            },
            
            // Collapse node: hide all direct connections
            collapseNode: function(nodeId) {
                const updates = [];
                const node = nodesDataSet.get(nodeId);
                if (!node) return;
                
                // Find direct connections
                const connectedNodeIds = new Set();
                edgesDataSet.forEach(edge => {
                    if (edge.hidden) return;
                    if (edge.from === nodeId) connectedNodeIds.add(edge.to);
                    if (edge.to === nodeId) connectedNodeIds.add(edge.from);
                });
                
                // Hide connected nodes
                nodesDataSet.forEach(n => {
                    if (connectedNodeIds.has(n.id)) {
                        updates.push({ id: n.id, hidden: true });
                    }
                });
                nodesDataSet.update(updates);
            },
            
            // Save current view state
            saveViewState: function() {
                const state = {
                    hiddenTypes: Array.from(hiddenTypes),
                    hiddenRelTypes: Array.from(hiddenRelTypes),
                    viewPosition: network.getViewPosition(),
                    scale: network.getScale(),
                    selectedNodes: network.getSelectedNodes(),
                    timestamp: Date.now()
                };
                return JSON.stringify(state);
            },
            
            // Load view state
            loadViewState: function(stateJson) {
                try {
                    const state = JSON.parse(stateJson);
                    
                    // Restore hidden types
                    if (state.hiddenTypes) {
                        state.hiddenTypes.forEach(type => {
                            this.toggleType(type, false);
                        });
                    }
                    
                    // Restore hidden relationship types
                    if (state.hiddenRelTypes) {
                        state.hiddenRelTypes.forEach(relType => {
                            this.toggleRelationshipType(relType, false);
                        });
                    }
                    
                    // Restore view position and scale
                    if (state.viewPosition && state.scale) {
                        network.moveTo({
                            position: state.viewPosition,
                            scale: state.scale,
                            animation: true
                        });
                    }
                    
                    // Restore selected nodes
                    if (state.selectedNodes && state.selectedNodes.length > 0) {
                        network.selectNodes(state.selectedNodes);
                    }
                } catch (error) {
                    console.error('Failed to load view state:', error);
                }
            },
            
            // Export graph as PNG/SVG
            exportGraph: function(format = 'png') {
                try {
                    if (format === 'png') {
                        // Get the canvas element from vis-network
                        const canvas = container.querySelector('canvas');
                        if (!canvas) {
                            throw new Error('Canvas not found');
                        }
                        
                        try {
                            // Try using vis.js getBase64 method first
                            const base64 = network.getBase64({
                                format: 'png',
                                quality: 1.0,
                                multiplier: 2
                            });
                            if (base64 && base64.trim() !== '') {
                                return 'data:image/png;base64,' + base64;
                            }
                        } catch (base64Error) {
                            console.warn('getBase64 failed, using canvas fallback:', base64Error);
                        }
                        
                        // Fallback: use canvas toDataURL directly
                        // Create a new canvas with higher resolution
                        const scale = 2;
                        const exportCanvas = document.createElement('canvas');
                        exportCanvas.width = canvas.width * scale;
                        exportCanvas.height = canvas.height * scale;
                        const ctx = exportCanvas.getContext('2d');
                        
                        // Fill with white background
                        ctx.fillStyle = '#1E1B2E';
                        ctx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);
                        
                        // Draw the original canvas scaled up
                        ctx.drawImage(canvas, 0, 0, exportCanvas.width, exportCanvas.height);
                        
                        return exportCanvas.toDataURL('image/png');
                    } else if (format === 'svg') {
                        // For SVG, convert canvas to SVG with embedded PNG
                        const canvas = container.querySelector('canvas');
                        if (canvas) {
                            const canvasDataURL = canvas.toDataURL('image/png');
                            const svgContent = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${canvas.width}" height="${canvas.height}">
  <image x="0" y="0" width="${canvas.width}" height="${canvas.height}" xlink:href="${canvasDataURL}"/>
</svg>`;
                            const svgBlob = new Blob([svgContent], { type: 'image/svg+xml;charset=utf-8' });
                            return URL.createObjectURL(svgBlob);
                        }
                        // Fallback: return PNG
                        const base64 = network.getBase64({
                            format: 'png',
                            quality: 1.0,
                            multiplier: 2
                        });
                        return 'data:image/png;base64,' + base64;
                    }
                } catch (error) {
                    console.error('Export error:', error);
                    return null;
                }
                return null;
            },
            
            // Get filtered STIX bundle
            getFilteredBundle: function() {
                const visibleNodeIds = new Set();
                nodesDataSet.forEach(node => {
                    if (!node.hidden) {
                        visibleNodeIds.add(node.id);
                    }
                });
                
                const visibleEdgeIds = new Set();
                edgesDataSet.forEach(edge => {
                    if (!edge.hidden && visibleNodeIds.has(edge.from) && visibleNodeIds.has(edge.to)) {
                        visibleEdgeIds.add(edge.id);
                    }
                });
                
                const objects = [];
                visibleNodeIds.forEach(id => {
                    const obj = stixIdToObject.get(id);
                    if (obj) objects.push(obj);
                });
                
                visibleEdgeIds.forEach(id => {
                    const edge = edgesDataSet.get(id);
                    if (edge && edge.stixObject) {
                        objects.push(edge.stixObject);
                    }
                });
                
                return {
                    type: 'bundle',
                    id: 'bundle--' + Date.now(),
                    objects: objects
                };
            },
            
            // Filter by timeline (gray out inactive nodes instead of hiding them)
            filterByTimeline: function(date, cumulative = true) {
                const targetDate = new Date(date);
                
                const nodeUpdates = [];
                nodesDataSet.forEach(node => {
                    if (hiddenTypes.has(node.stixType)) {
                        nodeUpdates.push({ id: node.id, hidden: true });
                        return;
                    }
                    
                    if (!node.timestamp) {
                        // Nodes without timestamp: show normally
                        nodeUpdates.push({ 
                            id: node.id, 
                            hidden: false,
                            opacity: 1.0
                        });
                        return;
                    }
                    
                    let isActive;
                    if (cumulative) {
                        isActive = node.timestamp <= targetDate;
                    } else {
                        isActive = node.timestamp.toDateString() === targetDate.toDateString();
                    }
                    
                    // Gray out inactive nodes instead of hiding them
                    nodeUpdates.push({ 
                        id: node.id, 
                        hidden: false,
                        opacity: isActive ? 1.0 : 0.2  // Low opacity for inactive nodes
                    });
                });
                nodesDataSet.update(nodeUpdates);
            },
            
            // Reset all filters (restore visibility and opacity)
            resetFilters: function() {
                hiddenTypes.clear();
                const updates = [];
                nodesDataSet.forEach(node => {
                    const originalOpacity = originalNodeOpacities.get(node.id) || 1.0;
                    updates.push({ 
                        id: node.id, 
                        hidden: false,
                        opacity: originalOpacity
                    });
                });
                nodesDataSet.update(updates);
            },
            
            // Get selected node
            getSelectedNode: function() {
                const selected = network.getSelectedNodes();
                if (selected.length > 0) {
                    const node = nodesDataSet.get(selected[0]);
                    return node ? node.stixObject : null;
                }
                return null;
            },
            
            // Fit to all nodes
            fit: function() {
                network.fit();
            },
            
            // Destroy the network
            destroy: function() {
                // Clean up tooltip
                if (network.tooltipElement && network.tooltipElement.parentNode) {
                    network.tooltipElement.parentNode.removeChild(network.tooltipElement);
                }
                network.destroy();
            },
            
            // Event handlers
            on: function(event, callback) {
                network.on(event, callback);
            },
            
            off: function(event, callback) {
                network.off(event, callback);
            }
        };
    }

    /**
     * Create legend data for the graph
     * @param {object} stats - Stats from makeGraphData
     * @returns {object} - Legend data with nodes and relationships
     */
    function makeLegendData(stats) {
        const legend = {
            nodes: [],
            relationships: []
        };
        const iconPath = typeof STIX_ICONS_BASE_PATH !== 'undefined' ? STIX_ICONS_BASE_PATH : null;
        
        // Node types legend
        for (const [type, count] of Object.entries(stats.typeCount)) {
            if (type === 'relationship') continue; // Skip relationships in node legend
            legend.nodes.push({
                type: type,
                icon: stixTypeToIconURL(type, iconPath),  // Return icon URL instead of emoji
                iconUrl: stixTypeToIconURL(type, iconPath),  // Explicit URL field
                color: STIX_COLORS[type] || STIX_COLORS.default,
                count: count
            });
        }
        // Sort by count descending
        legend.nodes.sort((a, b) => b.count - a.count);
        
        // Relationship types legend (for edge colors)
        // Add common relationship types to legend with their visual styles
        const commonRelationships = ['indicates', 'uses', 'targets', 'mitigates', 'attributed-to', 'related-to'];
        for (const relType of commonRelationships) {
            if (RELATIONSHIP_STYLES[relType]) {
                const style = RELATIONSHIP_STYLES[relType];
                legend.relationships.push({
                    type: relType,
                    color: style.color,
                    dashes: style.dashes,
                    description: getRelationshipDescription(relType)
                });
            }
        }
        
        return legend;
    }
    
    /**
     * Get human-readable description for relationship type
     * @param {string} relType - Relationship type
     * @returns {string} - Description
     */
    function getRelationshipDescription(relType) {
        const descriptions = {
            'indicates': 'Indicates relationship',
            'uses': 'Uses relationship',
            'targets': 'Targets relationship',
            'mitigates': 'Mitigates relationship',
            'attributed-to': 'Attributed to relationship',
            'related-to': 'Related to relationship',
            'variant-of': 'Variant of relationship',
            'duplicate-of': 'Duplicate of relationship'
        };
        return descriptions[relType] || relType;
    }

    // Export module
    const stix2viz = {
        makeGraphData: makeGraphData,
        makeGraphView: makeGraphView,
        makeLegendData: makeLegendData,
        parseStixContent: parseStixContent,
        stixTypeToIconURL: stixTypeToIconURL,
        getStixIconURL: getStixIconURL,
        STIX_COLORS: STIX_COLORS,
        escapeHtml: escapeHtml
    };

    // Export for different module systems
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = stix2viz;
    } else if (typeof define === 'function' && define.amd) {
        define([], function() { return stix2viz; });
    } else {
        global.stix2viz = stix2viz;
    }

})(typeof window !== 'undefined' ? window : this);

