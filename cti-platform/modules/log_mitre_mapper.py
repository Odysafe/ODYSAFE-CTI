"""
ODYSAFE CTI Platform
Log Analysis to MITRE ATT&CK Mapper
Maps security event descriptions to MITRE ATT&CK techniques
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class MitreMatch:
    tactic: str
    technique_id: str
    technique_name: str
    subtechnique: Optional[str]
    confidence: float
    matched_keywords: List[str]


class LogMitreMapper:
    """Maps security log events to MITRE ATT&CK framework using pattern matching."""
    
    TECHNIQUE_PATTERNS = {
        # EXECUTION
        r'powershell|ps\.exe|pwsh': {
            'tactic': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'subtechnique': 'PowerShell (T1059.001)',
        },
        r'cmd\.exe|command prompt': {
            'tactic': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'subtechnique': 'Windows Command Shell (T1059.003)',
        },
        r'bash|sh|shell|/bin/': {
            'tactic': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'subtechnique': 'Unix Shell (T1059.004)',
        },
        r'wmic|windows management instrumentation': {
            'tactic': 'Execution',
            'technique_id': 'T1047',
            'technique_name': 'Windows Management Instrumentation',
            'subtechnique': None,
        },
        r'python|python3|\.py': {
            'tactic': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'subtechnique': 'Python (T1059.006)',
        },
        r'vba|visual basic|macro': {
            'tactic': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'subtechnique': 'Visual Basic (T1059.005)',
        },
        
        # PERSISTENCE
        r'registry.*run|run key|hklm.*run|autoruns': {
            'tactic': 'Persistence',
            'technique_id': 'T1547',
            'technique_name': 'Boot or Logon Autostart Execution',
            'subtechnique': 'Registry Run Keys (T1547.001)',
        },
        r'scheduled task|schtasks|at\.exe|cron': {
            'tactic': 'Persistence',
            'technique_id': 'T1053',
            'technique_name': 'Scheduled Task/Job',
            'subtechnique': None,
        },
        r'service.*created|service.*installed|new.*service|systemctl enable': {
            'tactic': 'Persistence',
            'technique_id': 'T1543',
            'technique_name': 'Create or Modify System Process',
            'subtechnique': 'Windows Service (T1543.003)',
        },
        r'startup folder|startup.*path|appdata.*roaming.*microsoft.*windows.*start menu.*programs.*startup': {
            'tactic': 'Persistence',
            'technique_id': 'T1547',
            'technique_name': 'Boot or Logon Autostart Execution',
            'subtechnique': 'Startup Folder (T1547.001)',
        },
        r'winlogon|userinit|shell.*registry': {
            'tactic': 'Persistence',
            'technique_id': 'T1547',
            'technique_name': 'Boot or Logon Autostart Execution',
            'subtechnique': 'Winlogon Helper DLL (T1547.004)',
        },
        
        # PRIVILEGE ESCALATION
        r'uac bypass|admin.*prompt|elevated|privilege.*escalation': {
            'tactic': 'Privilege Escalation',
            'technique_id': 'T1548',
            'technique_name': 'Abuse Elevation Control Mechanism',
            'subtechnique': None,
        },
        r'sudo|sudoers|sudo -l': {
            'tactic': 'Privilege Escalation',
            'technique_id': 'T1548',
            'technique_name': 'Abuse Elevation Control Mechanism',
            'subtechnique': 'Sudo Caching (T1548.003)',
        },
        r'suid|setuid|chmod.*4755': {
            'tactic': 'Privilege Escalation',
            'technique_id': 'T1548',
            'technique_name': 'Abuse Elevation Control Mechanism',
            'subtechnique': 'Setuid and Setgid (T1548.001)',
        },
        r'kerberoasting|kerberos.*ticket|tgt|tgs': {
            'tactic': 'Privilege Escalation',
            'technique_id': 'T1558',
            'technique_name': 'Steal or Forge Kerberos Tickets',
            'subtechnique': 'Kerberoasting (T1558.003)',
        },
        
        # DEFENSE EVASION
        r'disable.*defender|disable.*av|disable.*security|windows defender.*off|mpcmdrun.*removedefinitions': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1562',
            'technique_name': 'Impair Defenses',
            'subtechnique': 'Disable or Modify Tools (T1562.001)',
        },
        r'delete.*event log|clear.*log|wevtutil.*cl|clear.*history': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1070',
            'technique_name': 'Indicator Removal',
            'subtechnique': 'Clear Windows Event Logs (T1070.001)',
        },
        r'masquerading|fake.*process|spoofed.*name': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1036',
            'technique_name': 'Masquerading',
            'subtechnique': None,
        },
        r'obfuscated|encoded|base64|xor.*encryption': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1027',
            'technique_name': 'Obfuscated Files or Information',
            'subtechnique': None,
        },
        r'process.*hollow|process.*doppel|process.*injection': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1055',
            'technique_name': 'Process Injection',
            'subtechnique': 'Process Hollowing (T1055.012)',
        },
        r'amsi.*bypass|antimalware.*script.*interface': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1562',
            'technique_name': 'Impair Defenses',
            'subtechnique': 'Disable or Modify Tools (T1562.001)',
        },
        
        # CREDENTIAL ACCESS
        r'mimikatz|lsass|password dump|credential dump|ntds\.dit|sekurlsa': {
            'tactic': 'Credential Access',
            'technique_id': 'T1003',
            'technique_name': 'OS Credential Dumping',
            'subtechnique': 'LSASS Memory (T1003.001)',
        },
        r'sam.*database|security.*account.*manager|sam\.bak': {
            'tactic': 'Credential Access',
            'technique_id': 'T1003',
            'technique_name': 'OS Credential Dumping',
            'subtechnique': 'SAM Database (T1003.002)',
        },
        r'keylog|key.*capture|password.*capture|keystroke': {
            'tactic': 'Credential Access',
            'technique_id': 'T1056',
            'technique_name': 'Input Capture',
            'subtechnique': 'Keylogging (T1056.001)',
        },
        r'brute.*force|password.*spray|credential.*stuffing': {
            'tactic': 'Credential Access',
            'technique_id': 'T1110',
            'technique_name': 'Brute Force',
            'subtechnique': 'Password Spraying (T1110.003)',
        },
        r'hash.*dump|ntlm.*hash|lmhash': {
            'tactic': 'Credential Access',
            'technique_id': 'T1003',
            'technique_name': 'OS Credential Dumping',
            'subtechnique': 'NTDS (T1003.003)',
        },
        
        # DISCOVERY
        r'dir\s|ls\s|file.*enumeration|folder.*enumeration|directory.*listing|list.*directory': {
            'tactic': 'Discovery',
            'technique_id': 'T1083',
            'technique_name': 'File and Directory Discovery',
            'subtechnique': None,
        },
        r'ipconfig|ifconfig|network.*discovery|arp|route.*print|netstat': {
            'tactic': 'Discovery',
            'technique_id': 'T1016',
            'technique_name': 'System Network Configuration Discovery',
            'subtechnique': None,
        },
        r'tasklist|get-process|wmi.*process|pslist|ps aux': {
            'tactic': 'Discovery',
            'technique_id': 'T1057',
            'technique_name': 'Process Discovery',
            'subtechnique': None,
        },
        r'whoami|id|getcurrent|user.*discovery': {
            'tactic': 'Discovery',
            'technique_id': 'T1033',
            'technique_name': 'System Owner/User Discovery',
            'subtechnique': None,
        },
        r'systeminfo|uname|ver|get-wmiobject.*win32_computersystem': {
            'tactic': 'Discovery',
            'technique_id': 'T1082',
            'technique_name': 'System Information Discovery',
            'subtechnique': None,
        },
        r'query.*user|quser|net.*user': {
            'tactic': 'Discovery',
            'technique_id': 'T1087',
            'technique_name': 'Account Discovery',
            'subtechnique': 'Local Account (T1087.001)',
        },
        r'domain.*trust|nltest|net.*view.*domain': {
            'tactic': 'Discovery',
            'technique_id': 'T1482',
            'technique_name': 'Domain Trust Discovery',
            'subtechnique': None,
        },
        r'security.*log|audit.*log|event.*viewer': {
            'tactic': 'Discovery',
            'technique_id': 'T1654',
            'technique_name': 'Log Enumeration',
            'subtechnique': None,
        },
        
        # LATERAL MOVEMENT
        r'psexec|wmiexec|dcom|pass.*the.*hash|pth|smbexec': {
            'tactic': 'Lateral Movement',
            'technique_id': 'T1021',
            'technique_name': 'Remote Services',
            'subtechnique': None,
        },
        r'rdp|remote.*desktop|mstsc|tsclient': {
            'tactic': 'Lateral Movement',
            'technique_id': 'T1021',
            'technique_name': 'Remote Services',
            'subtechnique': 'Remote Desktop Protocol (T1021.001)',
        },
        r'winrm|remote.*powershell|enter-pssession': {
            'tactic': 'Lateral Movement',
            'technique_id': 'T1021',
            'technique_name': 'Remote Services',
            'subtechnique': 'Windows Remote Management (T1021.006)',
        },
        r'ssh.*login|scp|sftp.*transfer': {
            'tactic': 'Lateral Movement',
            'technique_id': 'T1021',
            'technique_name': 'Remote Services',
            'subtechnique': 'SSH (T1021.004)',
        },
        
        # COLLECTION
        r'clipboard.*data|clipboard.*access': {
            'tactic': 'Collection',
            'technique_id': 'T1115',
            'technique_name': 'Clipboard Data',
            'subtechnique': None,
        },
        r'archive.*collected|compress.*data|zip.*password|7z.*compress': {
            'tactic': 'Collection',
            'technique_id': 'T1560',
            'technique_name': 'Archive Collected Data',
            'subtechnique': None,
        },
        r'screen.*capture|screenshot': {
            'tactic': 'Collection',
            'technique_id': 'T1113',
            'technique_name': 'Screen Capture',
            'subtechnique': None,
        },
        r'email.*collection|outlook.*pst|thunderbird': {
            'tactic': 'Collection',
            'technique_id': 'T1114',
            'technique_name': 'Email Collection',
            'subtechnique': None,
        },
        
        # EXFILTRATION
        r'data.*copied|usb.*drive|removable.*media|file.*transfer': {
            'tactic': 'Exfiltration',
            'technique_id': 'T1020',
            'technique_name': 'Automated Exfiltration',
            'subtechnique': None,
        },
        r'dns.*tunnel|dns.*exfil|dns.*query.*unusual|iodine|dnscat': {
            'tactic': 'Exfiltration',
            'technique_id': 'T1048',
            'technique_name': 'Exfiltration Over Alternative Protocol',
            'subtechnique': 'Exfiltration Over DNS (T1048.003)',
        },
        r'https.*exfil|ssl.*tunnel|covert.*channel': {
            'tactic': 'Exfiltration',
            'technique_id': 'T1048',
            'technique_name': 'Exfiltration Over Alternative Protocol',
            'subtechnique': None,
        },
        
        # COMMAND AND CONTROL
        r'beacon|heartbeat|c2.*check|check.*in': {
            'tactic': 'Command and Control',
            'technique_id': 'T1071',
            'technique_name': 'Application Layer Protocol',
            'subtechnique': None,
        },
        r'dns.*query|dns.*request|dga|domain.*generation': {
            'tactic': 'Command and Control',
            'technique_id': 'T1071',
            'technique_name': 'Application Layer Protocol',
            'subtechnique': 'DNS (T1071.004)',
        },
        r'http.*post|https.*post|web.*shell': {
            'tactic': 'Command and Control',
            'technique_id': 'T1071',
            'technique_name': 'Application Layer Protocol',
            'subtechnique': 'Web Protocols (T1071.001)',
        },
        r'irc.*command|irc.*bot|irc.*channel': {
            'tactic': 'Command and Control',
            'technique_id': 'T1071',
            'technique_name': 'Application Layer Protocol',
            'subtechnique': 'IRC (T1071.005)',
        },
        r'encrypted.*channel|tls.*tunnel|ssl.*encrypt': {
            'tactic': 'Command and Control',
            'technique_id': 'T1573',
            'technique_name': 'Encrypted Channel',
            'subtechnique': 'Symmetric Cryptography (T1573.001)',
        },
        
        # INITIAL ACCESS
        r'phish|spear.*phish|email.*attach|malicious.*attachment': {
            'tactic': 'Initial Access',
            'technique_id': 'T1566',
            'technique_name': 'Phishing',
            'subtechnique': 'Spearphishing Attachment (T1566.001)',
        },
        r'phish.*link|malicious.*url|click.*link': {
            'tactic': 'Initial Access',
            'technique_id': 'T1566',
            'technique_name': 'Phishing',
            'subtechnique': 'Spearphishing Link (T1566.002)',
        },
        r'exploit.*public.*facing|vulnerability.*exploit|cve.*exploit': {
            'tactic': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'subtechnique': None,
        },
        r'external.*remote.*service|vpn.*access|rdp.*external': {
            'tactic': 'Initial Access',
            'technique_id': 'T1133',
            'technique_name': 'External Remote Services',
            'subtechnique': None,
        },
        r'supply.*chain|compromised.*software|trusted.*relationship': {
            'tactic': 'Initial Access',
            'technique_id': 'T1195',
            'technique_name': 'Supply Chain Compromise',
            'subtechnique': None,
        },
        
        # IMPACT
        r'ransomware|encrypt.*file|decrypt.*ransom|payment.*bitcoin': {
            'tactic': 'Impact',
            'technique_id': 'T1486',
            'technique_name': 'Data Encrypted for Impact',
            'subtechnique': None,
        },
        r'data.*destruct|wiper|delete.*data|secure.*erase': {
            'tactic': 'Impact',
            'technique_id': 'T1485',
            'technique_name': 'Data Destruction',
            'subtechnique': None,
        },
        r'ddos|denial.*service|flood.*traffic|botnet.*attack': {
            'tactic': 'Impact',
            'technique_id': 'T1498',
            'technique_name': 'Network Denial of Service',
            'subtechnique': None,
        },
        r'defacement|website.*deface|homepage.*modified': {
            'tactic': 'Impact',
            'technique_id': 'T1491',
            'technique_name': 'Defacement',
            'subtechnique': None,
        },
        r'data.*manipulation|false.*data|integrity.*compromise': {
            'tactic': 'Impact',
            'technique_id': 'T1565',
            'technique_name': 'Data Manipulation',
            'subtechnique': None,
        },

        # IMPACT -- additional / critical fixes
        r'vssadmin.*(delete|shadows)|wbadmin.*(delete|catalog)|bcdedit.*recoveryenabled.*no': {
            'tactic': 'Impact',
            'technique_id': 'T1490',
            'technique_name': 'Inhibit System Recovery',
            'subtechnique': None,
        },
        r'net\s+stop.*service|sc\s+stop|kill.*process.*security': {
            'tactic': 'Impact',
            'technique_id': 'T1489',
            'technique_name': 'Service Stop',
            'subtechnique': None,
        },
        r'defacement|index\.html.*replaced|webpage.*modified': {
            'tactic': 'Impact',
            'technique_id': 'T1491',
            'technique_name': 'Defacement',
            'subtechnique': None,
        },
        r'\.locked|\.encrypted|ransom.*note|your_files_are_encrypted': {
            'tactic': 'Impact',
            'technique_id': 'T1486',
            'technique_name': 'Data Encrypted for Impact',
            'subtechnique': None,
        },

        # INITIAL ACCESS -- additional
        r'sql\s?injection|path\s?traversal|directory\s?traversal': {
            'tactic': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'subtechnique': None,
        },
        r'macro\s?enabled|\.docm|\.xlsm|malicious.*macro': {
            'tactic': 'Initial Access',
            'technique_id': 'T1566',
            'technique_name': 'Phishing',
            'subtechnique': 'Spearphishing Attachment (T1566.001)',
        },
        r'login.*outside.*hours|logon.*unusual.*time|authentication.*unexpected': {
            'tactic': 'Initial Access',
            'technique_id': 'T1078',
            'technique_name': 'Valid Accounts',
            'subtechnique': None,
        },

        # EXECUTION -- additional
        r'user.*executed|double.click.*attachment|opened.*document': {
            'tactic': 'Execution',
            'technique_id': 'T1204',
            'technique_name': 'User Execution',
            'subtechnique': None,
        },
        r'exploit.*office|exploit.*pdf|exploit.*browser|heap\s?spray': {
            'tactic': 'Execution',
            'technique_id': 'T1203',
            'technique_name': 'Exploitation for Client Execution',
            'subtechnique': None,
        },

        # PERSISTENCE -- additional
        r'net\s+user.*\/add|useradd|new.*local.*admin|added.*account': {
            'tactic': 'Persistence',
            'technique_id': 'T1098',
            'technique_name': 'Account Manipulation',
            'subtechnique': None,
        },
        r'extension.*install|browser.*plugin.*added': {
            'tactic': 'Persistence',
            'technique_id': 'T1176',
            'technique_name': 'Browser Extensions',
            'subtechnique': None,
        },

        # PRIVILEGE ESCALATION -- additional
        r'exploit.*kernel|kernel.*exploit|local.*privilege.*escalation|dirtycow|dirty\s?cow': {
            'tactic': 'Privilege Escalation',
            'technique_id': 'T1068',
            'technique_name': 'Exploitation for Privilege Escalation',
            'subtechnique': None,
        },

        # DEFENSE EVASION -- additional
        r'Set-MpPreference.*Disable|DisableRealtimeMonitoring': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1562',
            'technique_name': 'Impair Defenses',
            'subtechnique': 'Disable or Modify Tools (T1562.001)',
        },
        r'Clear-EventLog|del.*\.evtx': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1070',
            'technique_name': 'Indicator Removal',
            'subtechnique': 'Clear Windows Event Logs (T1070.001)',
        },
        r'explorer\.exe.*appdata|lsass.*temp|svchost.*appdata': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1036',
            'technique_name': 'Masquerading',
            'subtechnique': None,
        },
        r'certutil.*-decode|-encodedcommand': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1027',
            'technique_name': 'Obfuscated Files or Information',
            'subtechnique': None,
        },

        # CREDENTIAL ACCESS -- additional
        r'password.*spray|multiple.*accounts.*failed': {
            'tactic': 'Credential Access',
            'technique_id': 'T1110',
            'technique_name': 'Brute Force',
            'subtechnique': 'Password Spraying (T1110.003)',
        },
        r'password.*file|credentials.*plaintext|unattend\.xml|sysprep.*password': {
            'tactic': 'Credential Access',
            'technique_id': 'T1552',
            'technique_name': 'Unsecured Credentials',
            'subtechnique': None,
        },
        r'credential.*manager|windows.*vault|keychainaccess': {
            'tactic': 'Credential Access',
            'technique_id': 'T1555',
            'technique_name': 'Credentials from Password Stores',
            'subtechnique': None,
        },

        # DISCOVERY -- additional
        r'nmap|masscan|netscan|port\s?scan': {
            'tactic': 'Discovery',
            'technique_id': 'T1046',
            'technique_name': 'Network Service Scanning',
            'subtechnique': None,
        },
        r'nltest.*domain_trusts|Get-ADDomain|domain.*enum': {
            'tactic': 'Discovery',
            'technique_id': 'T1482',
            'technique_name': 'Domain Trust Discovery',
            'subtechnique': None,
        },
        r'dir\s+/s|ls\s+-la|find.*sensitive|Get-ChildItem': {
            'tactic': 'Discovery',
            'technique_id': 'T1083',
            'technique_name': 'File and Directory Discovery',
            'subtechnique': None,
        },

        # LATERAL MOVEMENT -- additional
        r'pass.the.ticket|overpass.the.hash|pth\b': {
            'tactic': 'Lateral Movement',
            'technique_id': 'T1550',
            'technique_name': 'Use Alternate Authentication Material',
            'subtechnique': None,
        },
        r'rdp.*lateral|rdesktop|mstsc.*\/v:': {
            'tactic': 'Lateral Movement',
            'technique_id': 'T1563',
            'technique_name': 'Remote Service Session Hijacking',
            'subtechnique': None,
        },

        # COLLECTION -- additional
        r'BitBlt|PrintWindow|screen\s?capture': {
            'tactic': 'Collection',
            'technique_id': 'T1113',
            'technique_name': 'Screen Capture',
            'subtechnique': None,
        },
        r'SetWindowsHookEx|GetAsyncKeyState': {
            'tactic': 'Collection',
            'technique_id': 'T1056',
            'technique_name': 'Input Capture',
            'subtechnique': 'Keylogging (T1056.001)',
        },
        r'robocopy.*documents|xcopy.*confidential|copy.*sensitive': {
            'tactic': 'Collection',
            'technique_id': 'T1005',
            'technique_name': 'Data from Local System',
            'subtechnique': None,
        },

        # COMMAND AND CONTROL -- additional
        r'C2.*callback|implant.*checkin': {
            'tactic': 'Command and Control',
            'technique_id': 'T1071',
            'technique_name': 'Application Layer Protocol',
            'subtechnique': None,
        },
        r'tor.*exit|proxy.*anonymize|socks5.*tunnel': {
            'tactic': 'Command and Control',
            'technique_id': 'T1090',
            'technique_name': 'Proxy',
            'subtechnique': None,
        },
        r'base64.*http|encoded.*uri|xor.*request': {
            'tactic': 'Command and Control',
            'technique_id': 'T1132',
            'technique_name': 'Data Encoding',
            'subtechnique': None,
        },

        # EXFILTRATION -- additional
        r'large.*outbound|transfer.*mb.*external|exfil.*c2': {
            'tactic': 'Exfiltration',
            'technique_id': 'T1041',
            'technique_name': 'Exfiltration Over C2 Channel',
            'subtechnique': None,
        },
        r'high.*entropy.*subdomain': {
            'tactic': 'Exfiltration',
            'technique_id': 'T1048',
            'technique_name': 'Exfiltration Over Alternative Protocol',
            'subtechnique': 'Exfiltration Over DNS (T1048.003)',
        },
        r'upload.*google.*drive|upload.*dropbox|upload.*pastebin': {
            'tactic': 'Exfiltration',
            'technique_id': 'T1567',
            'technique_name': 'Exfiltration to Cloud Storage',
            'subtechnique': None,
        },
    }
    
    TACTIC_SEVERITY = {
        'Initial Access': 1.0,
        'Execution': 0.95,
        'Persistence': 0.90,
        'Privilege Escalation': 0.95,
        'Defense Evasion': 0.90,
        'Credential Access': 0.95,
        'Discovery': 0.85,
        'Lateral Movement': 0.90,
        'Collection': 0.85,
        'Exfiltration': 0.95,
        'Command and Control': 0.90,
        'Impact': 0.95,
    }
    
    TACTIC_COLORS = {
        'Initial Access': ('#FEF3C7', '#D97706'),
        'Execution': ('#FEE2E2', '#DC2626'),
        'Persistence': ('#FEF9C3', '#CA8A04'),
        'Privilege Escalation': ('#FFF7ED', '#EA580C'),
        'Defense Evasion': ('#F3E8FF', '#9333EA'),
        'Credential Access': ('#FFE4E6', '#E11D48'),
        'Discovery': ('#E0F2FE', '#0284C7'),
        'Lateral Movement': ('#ECFDF5', '#059669'),
        'Collection': ('#F0FDF4', '#16A34A'),
        'Exfiltration': ('#FDF2F8', '#DB2777'),
        'Command and Control': ('#FFFBEB', '#B45309'),
        'Impact': ('#FFF1F2', '#BE123C'),
    }
    
    def __init__(self):
        self.patterns_compiled = {}
        for pattern_str, info in self.TECHNIQUE_PATTERNS.items():
            self.patterns_compiled[pattern_str] = {
                'regex': re.compile(pattern_str, re.IGNORECASE),
                'info': info
            }

    def _calculate_context_confidence(self, pattern_str: str, event_description: str, base_confidence: float) -> float:
        """Adjust confidence score based on contextual signals in the description."""
        desc_lower = event_description.lower()
        
        # PowerShell contextual scoring (T1059.001)
        if 'powershell' in pattern_str or 'ps.exe' in pattern_str:
            score = 0
            if any(x in desc_lower for x in ['powershell', 'pwsh', 'ps.exe']):
                score += 1
            if any(x in desc_lower for x in ['-enc', '-encodedcommand', '-encoded', 'encodedcommand']):
                score += 2
            if any(x in desc_lower for x in ['-nop', '-noprofile', 'bypass', '-ep', '-executionpolicy', 'noprofile']):
                score += 2
            if any(x in desc_lower for x in ['downloadstring', 'downloadfile', 'invoke-webrequest', 'iwr', 'iex', 'invoke-expression']):
                score += 2
            
            if score >= 3:
                return base_confidence
            elif score >= 1:
                return base_confidence * 0.7
                
        # Mimikatz -- always force High Priority when the keyword is present (T1003)
        if 'mimikatz' in desc_lower:
            return base_confidence

        # LSASS / credential dump contextual scoring (T1003.001)
        elif 'lsass' in pattern_str or 'mimikatz' in pattern_str:
            score = 0
            if any(x in desc_lower for x in ['sekurlsa', 'lsass']):
                score += 1
            if any(x in desc_lower for x in ['dump', 'minidump', 'procdump', 'lsass.dmp', 'dbghelp']):
                score += 2
            if 'rundll32' in desc_lower:
                score += 1

            if score >= 3:
                return base_confidence
            elif score >= 1:
                return base_confidence * 0.7

        # WMIC contextual scoring (T1047)
        elif 'wmic' in pattern_str:
            score = 0
            if 'wmic' in desc_lower or 'wmi' in desc_lower:
                score += 1
            if any(x in desc_lower for x in ['process call create', 'shadowcopy delete', 'shadowcopy', 'process create']):
                score += 2
            if 'delete' in desc_lower or 'create' in desc_lower:
                score += 1
                
            if score >= 3:
                return base_confidence
            elif score >= 1:
                return base_confidence * 0.7

        # Registry Autostart contextual scoring (T1547.001)
        elif 'registry' in pattern_str and 'run' in pattern_str:
            score = 0
            if any(x in desc_lower for x in ['registry', 'reg', 'hklm', 'hkcu']):
                score += 1
            if any(x in desc_lower for x in ['runkey', 'run key', 'run', 'active setup']):
                score += 2
            if any(x in desc_lower for x in ['add', 'write', 'set-itemproperty', 'reg add']):
                score += 1
                
            if score >= 3:
                return base_confidence
            elif score >= 1:
                return base_confidence * 0.7

        return base_confidence

    def find_technique(self, event_description: str) -> Optional[MitreMatch]:
        """Find the best matching MITRE technique from an event description."""
        if not event_description:
            return None
            
        best_match = None
        best_confidence = 0
        matched_keywords = []
        
        for pattern_str, compiled_info in self.patterns_compiled.items():
            regex = compiled_info['regex']
            info = compiled_info['info']
            
            match = regex.search(event_description)
            if match:
                tactic_modifier = self.TACTIC_SEVERITY.get(info['tactic'], 0.85)
                confidence = self._calculate_context_confidence(pattern_str, event_description, 0.9 * tactic_modifier)
                
                matched_text = match.group(0)
                matched_keywords.append(matched_text)
                
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = {
                        'tactic': info['tactic'],
                        'technique_id': info['technique_id'],
                        'technique_name': info['technique_name'],
                        'subtechnique': info['subtechnique'],
                        'matched_keywords': [matched_text],
                    }
        
        if best_match:
            return MitreMatch(
                tactic=best_match['tactic'],
                technique_id=best_match['technique_id'],
                technique_name=best_match['technique_name'],
                subtechnique=best_match['subtechnique'],
                confidence=min(best_confidence, 1.0),
                matched_keywords=best_match['matched_keywords']
            )
        
        return None
    
    def find_all_techniques(self, event_description: str) -> List[MitreMatch]:
        """Find all matching MITRE techniques from an event description."""
        if not event_description:
            return []
            
        matches = []
        matched_patterns = set()
        
        for pattern_str, compiled_info in self.patterns_compiled.items():
            if pattern_str in matched_patterns:
                continue
                
            regex = compiled_info['regex']
            info = compiled_info['info']
            
            for match in regex.finditer(event_description):
                tactic_modifier = self.TACTIC_SEVERITY.get(info['tactic'], 0.85)
                confidence = self._calculate_context_confidence(pattern_str, event_description, 0.9 * tactic_modifier)
                
                matches.append(MitreMatch(
                    tactic=info['tactic'],
                    technique_id=info['technique_id'],
                    technique_name=info['technique_name'],
                    subtechnique=info['subtechnique'],
                    confidence=min(confidence, 1.0),
                    matched_keywords=[match.group(0)]
                ))
                matched_patterns.add(pattern_str)
                break
        
        return sorted(matches, key=lambda x: x.confidence, reverse=True)
    
    def get_tactic_color(self, tactic: str) -> tuple:
        """Get color scheme for a tactic."""
        return self.TACTIC_COLORS.get(tactic, ('#F8FAFC', '#334155'))
