# Log Analyzer - Technical Explanation

## Overview

The Log Analyzer module automatically maps security log events to MITRE ATT&CK techniques using pattern-based matching. This document explains how the confidence score is calculated, how logs are matched to MITRE techniques, and how events are assigned to tactics.

---

## 1. How Log Matching Works

### Pattern Dictionary (`TECHNIQUE_PATTERNS`)

The matching engine uses a dictionary of 60+ regular expression patterns that map keywords to specific MITRE ATT&CK techniques. Each pattern entry contains:

- **Regex pattern**: A case-insensitive regular expression to search for in the log
- **Tactic**: The MITRE ATT&CK tactic category (e.g., Execution, Persistence)
- **Technique ID**: The MITRE technique identifier (e.g., T1059)
- **Technique Name**: Human-readable name of the technique
- **Subtechnique**: Specific sub-technique if applicable (e.g., PowerShell T1059.001)

### Example Pattern Structure:
```python
r'powershell|ps\.exe|pwsh': {
    'tactic': 'Execution',
    'technique_id': 'T1059',
    'technique_name': 'Command and Scripting Interpreter',
    'subtechnique': 'PowerShell (T1059.001)',
}
```

### Supported Tactics

The pattern library covers all 12 MITRE ATT&CK tactics:

1. **Initial Access** - Phishing, exploitation, supply chain
2. **Execution** - PowerShell, CMD, WMI, Python, VBA
3. **Persistence** - Registry Run Keys, Scheduled Tasks, Services
4. **Privilege Escalation** - UAC bypass, Sudo abuse, Kerberoasting
5. **Defense Evasion** - Process injection, obfuscation, rootkits
6. **Credential Access** - LSASS memory, credential dumping, brute force
7. **Discovery** - Account enumeration, process discovery, network scanning
8. **Lateral Movement** - RDP, SSH, SMB, remote services
9. **Collection** - Clipboard data, archives, screen capture
10. **Exfiltration** - DNS tunneling, alternative protocols
11. **Command and Control** - DNS C2, HTTP/HTTPS, IRC
12. **Impact** - Ransomware, data destruction, DDoS

---

## 2. How Confidence is Calculated

The confidence score is calculated using a two-step formula:

### Formula:
```
confidence = 0.9 * TACTIC_SEVERITY[tactic]
```

### Base Confidence: 0.9 (90%)
All successful pattern matches start with a base confidence of 0.9.

### Tactic Severity Modifier (`TACTIC_SEVERITY`)

Each MITRE tactic has an associated severity weight that adjusts the base confidence:

| Tactic | Severity | Max Confidence |
|--------|----------|----------------|
| Initial Access | 1.00 | 90.0% |
| Execution | 0.95 | 85.5% |
| Persistence | 0.90 | 81.0% |
| Privilege Escalation | 0.95 | 85.5% |
| Defense Evasion | 0.90 | 81.0% |
| Credential Access | 0.95 | 85.5% |
| Discovery | 0.85 | 76.5% |
| Lateral Movement | 0.90 | 81.0% |
| Collection | 0.85 | 76.5% |
| Exfiltration | 0.95 | 85.5% |
| Command and Control | 0.90 | 81.0% |
| Impact | 0.95 | 85.5% |

### Confidence Calculation Example:

For a log entry: `User executed powershell.exe with encoded command`

1. Pattern `r'powershell|ps\.exe|pwsh'` matches
2. Tactic is **Execution** with severity 0.95
3. Confidence = 0.9 * 0.95 = **85.5%**

For a log entry: `Phishing email with malicious attachment received`

1. Pattern `r'phish|spear.*phish|email.*attach'` matches
2. Tactic is **Initial Access** with severity 1.00
3. Confidence = 0.9 * 1.00 = **90.0%**

---

## 3. How Events Are Assigned

### Step 1: Log Parsing

The system accepts three log formats:

- **CSV**: Column headers automatically detected, common fields mapped
- **JSON**: Structured event objects processed directly
- **TXT/LOG**: Lines parsed using regex to extract timestamp, source, and description

### Step 2: Field Extraction

For each log event, the system extracts:

- **timestamp**: When the event occurred (ISO format preferred)
- **source**: Originating system (e.g., firewall, sysmon, web-server)
- **description**: The actual log message/event details

Field extraction tries multiple common field names:
- Timestamp: `timestamp`, `time`, `datetime`, `event_time`, `created`, `date`, `ts`
- Source: `source`, `hostname`, `host`, `computer`, `device`, `source_address`
- Description: `description`, `message`, `event`, `details`, `event_description`, `msg`, `log`

### Step 3: MITRE Matching

The `find_technique()` method:

1. Takes the **description** field from the log event
2. Searches through all compiled regex patterns
3. Returns the **best match** (highest confidence) if multiple patterns match
4. Returns `None` if no patterns match

### Step 4: Data Storage

Each processed event is stored with:

```
- incident_id: Unique incident identifier
- event_index: Position in the original log
- timestamp: When the event occurred
- source: System that generated the event
- description: Original log message
- raw_data: Complete original event data
- mitre_tactic: Assigned MITRE tactic (or null)
- mitre_technique_id: MITRE technique ID (e.g., T1059)
- mitre_technique_name: Human-readable technique name
- mitre_subtechnique: Subtechnique details
- confidence: Match confidence percentage (0-100)
- matched_keywords: List of matched pattern text
```

### Step 5: Timeline Building

Events are grouped by MITRE tactic in chronological order following the Cyber Kill Chain:

1. Initial Access
2. Execution
3. Persistence
4. Privilege Escalation
5. Defense Evasion
6. Credential Access
7. Discovery
8. Lateral Movement
9. Collection
10. Exfiltration
11. Command and Control
12. Impact

This creates a visual timeline showing the attacker's progression through the kill chain.

---

## 4. Technique Aggregation

The system counts and aggregates techniques per incident:

```
technique_counts = {
    'T1059': {
        'id': 'T1059',
        'tactic': 'Execution',
        'name': 'Command and Scripting Interpreter',
        'count': 3  # Occurred 3 times in the log
    },
    'T1547': {
        'id': 'T1547',
        'tactic': 'Persistence',
        'name': 'Boot or Logon Autostart Execution',
        'count': 2
    }
}
```

---

## 5. Output Formats

### JSON Export
Contains complete incident data:
- Incident metadata
- All events with full MITRE mapping
- Technique counts and statistics
- Export timestamp

### CSV Export
Contains tabular data:
- event_index
- timestamp
- source
- description
- mitre_tactic
- mitre_technique_id
- mitre_technique_name
- confidence

---

## 6. Pattern Matching Examples

| Log Description | Pattern | Tactic | Technique | Confidence |
|-----------------|---------|--------|-------------|------------|
| `powershell.exe executed` | `powershell\|ps\.exe\|pwsh` | Execution | T1059 | 85.5% |
| `Registry Run key modified` | `registry.*run\|run key` | Persistence | T1547 | 81.0% |
| `LSASS memory accessed` | `lsass\|mimikatz\|sekurlsa` | Credential Access | T1003 | 85.5% |
| `RDP connection from 10.0.0.5` | `rdp\|remote.*desktop\|mstsc` | Lateral Movement | T1021 | 81.0% |
| `Data compressed to archive.zip` | `archive.*collected\|compress.*data` | Collection | T1560 | 76.5% |
| `DNS tunneling detected` | `dns.*tunnel\|dns.*exfil` | Exfiltration | T1048 | 85.5% |

---

## Summary

The Log Analyzer uses a **regex-based pattern matching** approach where:

1. **Input**: Log files (CSV, JSON, TXT) are parsed into individual events
2. **Matching**: Event descriptions are searched against 60+ regex patterns
3. **Confidence**: Calculated as `0.9 * tactic_severity` (ranges from 76.5% to 90%)
4. **Assignment**: Best matching technique is assigned to each event
5. **Output**: Timeline visualization, technique counts, and exportable reports

The system prioritizes **precision over recall** - it only reports high-confidence matches to reduce false positives in security analysis workflows.
