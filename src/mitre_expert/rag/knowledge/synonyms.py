"""
MITRE-specific synonyms and query expansion mappings.

These mappings are used to expand user queries with related terms,
improving recall for semantic search.
"""

from typing import Dict, List

# Synonym mappings for common attack techniques and tools
MITRE_SYNONYMS: Dict[str, List[str]] = {
    # Scripting/Execution
    "powershell": ["T1059.001", "command scripting interpreter", "script execution", "pwsh"],
    "cmd": ["T1059.003", "windows command shell", "command prompt", "cmd.exe"],
    "bash": ["T1059.004", "unix shell", "linux shell", "/bin/bash"],
    "python": ["T1059.006", "scripting", "script interpreter"],
    "wmi": ["T1047", "windows management instrumentation", "wmic"],

    # Credential Access
    "mimikatz": ["T1003", "credential dumping", "LSASS", "password extraction", "sekurlsa"],
    "credential": ["T1003", "password", "hash", "NTLM", "Kerberos", "authentication"],
    "lsass": ["T1003.001", "local security authority", "credential dumping"],
    "sam": ["T1003.002", "security account manager", "registry hive"],
    "ntds": ["T1003.003", "active directory", "domain controller"],
    "kerberos": ["T1558", "golden ticket", "silver ticket", "kerberoasting"],
    "dcsync": ["T1003.006", "domain replication"],

    # Process Injection
    "injection": ["T1055", "process injection", "DLL injection", "memory injection"],

    # Persistence
    "persistence": ["T1547", "boot", "autostart", "registry", "scheduled task"],

    # Command & Control
    "c2": ["command and control", "beacon", "callback", "C&C", "implant"],
    "cobalt strike": ["T1059.001", "beacon", "malleable c2"],

    # Exfiltration
    "exfil": ["exfiltration", "data theft", "data transfer", "upload"],

    # Privilege Escalation
    "privilege": ["T1548", "elevation", "escalation", "admin", "root", "UAC"],

    # Defense Evasion
    "defense evasion": ["T1027", "obfuscation", "encoding", "packing", "bypass"],

    # Initial Access
    "phishing": ["T1566", "spearphishing", "email", "attachment", "link"],

    # Impact
    "ransomware": ["T1486", "encryption", "data encrypted", "crypto"],

    # Lateral Movement
    "rdp": ["T1021.001", "remote desktop", "mstsc", "terminal services"],
    "smb": ["T1021.002", "windows admin shares", "net use", "psexec"],
    "ssh": ["T1021.004", "secure shell", "openssh"],
    "winrm": ["T1021.006", "windows remote management", "powershell remoting"],
    "psexec": ["T1021.002", "T1569.002", "remote service"],

    # Telemetry/Detection
    "sysmon": ["WinEventLog:Sysmon", "event id 1", "process creation"],
    "security log": ["WinEventLog:Security", "event id 4688", "event id 4624"],
    "auditd": ["linux audit", "syscall", "execve"],

    # Action keywords
    "detect": ["detection", "hunt", "monitor", "alert", "identify"],
    "mitigate": ["mitigation", "prevent", "block", "remediate", "defense"],
    "hunt": ["threat hunting", "proactive", "search", "investigate"],
}


# Tactic-specific expansions for broad queries about tactics
TACTIC_EXPANSIONS: Dict[str, List[str]] = {
    "lateral movement": [
        "T1021", "T1570", "remote services", "SMB", "RDP", "WinRM", "SSH",
        "pass the hash", "pass the ticket", "remote execution", "pivot",
        "psexec", "wmic", "lateral tool transfer"
    ],
    "credential access": [
        "T1003", "T1558", "T1555", "credential dumping", "LSASS", "mimikatz",
        "password spray", "brute force", "kerberoasting", "DCSync"
    ],
    "privilege escalation": [
        "T1548", "T1134", "T1068", "UAC bypass", "token manipulation",
        "sudo", "setuid", "exploit", "elevation"
    ],
    "defense evasion": [
        "T1027", "T1070", "T1562", "obfuscation", "indicator removal",
        "disable security", "timestomp", "masquerading"
    ],
    "initial access": [
        "T1566", "T1190", "T1133", "phishing", "exploit public-facing",
        "external remote services", "supply chain"
    ],
    "execution": [
        "T1059", "T1204", "T1053", "command line", "scripting", "PowerShell",
        "user execution", "scheduled task", "WMI"
    ],
    "persistence": [
        "T1547", "T1053", "T1136", "boot or logon", "scheduled task",
        "create account", "registry run keys", "startup folder"
    ],
    "command and control": [
        "T1071", "T1095", "T1573", "application layer protocol",
        "encrypted channel", "proxy", "web service"
    ],
    "exfiltration": [
        "T1041", "T1048", "T1567", "exfiltration over C2",
        "alternative protocol", "web service"
    ],
    "discovery": [
        "T1082", "T1083", "T1057", "system information", "file and directory",
        "process discovery", "network share"
    ],
    "collection": [
        "T1560", "T1123", "T1119", "archive collected data", "audio capture",
        "automated collection", "clipboard data"
    ],
    "impact": [
        "T1486", "T1485", "T1490", "data encrypted", "data destruction",
        "inhibit system recovery", "service stop"
    ],
    "reconnaissance": [
        "T1595", "T1592", "T1589", "active scanning", "gather victim info",
        "search open websites", "phishing for information"
    ],
    "resource development": [
        "T1583", "T1584", "T1585", "acquire infrastructure",
        "compromise infrastructure", "establish accounts"
    ],
}
