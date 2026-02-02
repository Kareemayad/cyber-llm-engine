# src/mitre_expert/models/technique_resolver.py
"""
Enhanced Deterministic Technique Resolver for MITRE ATT&CK.

IMPROVEMENTS:
1. Massively expanded alias dictionary (tools, malware, event IDs, Sysmon)
2. Better fuzzy matching with configurable thresholds
3. Context-aware scoring (boosts for detection/mitigation queries)
4. Sub-technique aware resolution
5. Caching for performance
6. Multi-technique extraction from complex text

Extracts technique IDs from text using:
1. Regex pattern matching (T1234, T1234.001)
2. Exact name matching (normalized)
3. Alias matching (tools, malware, event IDs)
4. Fuzzy name matching (optional rapidfuzz)
5. Context-aware boosting
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from mitre_expert.config import (
    MITRE_KNOWLEDGE_PACK_PATH,
    MITRE_CHUNKS_PATH,
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

KNOWLEDGE_PACK_PATH = MITRE_KNOWLEDGE_PACK_PATH
CHUNKS_PATH = MITRE_CHUNKS_PATH

# Regex patterns
TECHID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
MITIGATION_ID_RE = re.compile(r"\b(M\d{4})\b", re.IGNORECASE)
_CHUNKID_TECH_PREFIX_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)_", re.IGNORECASE)


# ---------------------------------------------------------------------------
# EXPANDED Technique Aliases (Comprehensive coverage)
# ---------------------------------------------------------------------------

TECHNIQUE_ALIASES: Dict[str, List[str]] = {
    # =========================================================================
    # CREDENTIAL ACCESS (TA0006)
    # =========================================================================
    "credential dumping": ["T1003"],
    "lsass": ["T1003.001"],
    "lsass.exe": ["T1003.001"],
    "lsass memory": ["T1003.001"],
    "mimikatz": ["T1003.001", "T1558.003"],
    "sekurlsa": ["T1003.001"],
    "logonpasswords": ["T1003.001"],
    "pass the hash": ["T1550.002"],
    "pth": ["T1550.002"],
    "pass the ticket": ["T1550.003"],
    "ptt": ["T1550.003"],
    "overpass the hash": ["T1550.002"],
    "kerberoasting": ["T1558.003"],
    "kerberoast": ["T1558.003"],
    "asreproasting": ["T1558.004"],
    "asreproast": ["T1558.004"],
    "golden ticket": ["T1558.001"],
    "silver ticket": ["T1558.002"],
    "dcsync": ["T1003.006"],
    "dc sync": ["T1003.006"],
    "ntds.dit": ["T1003.003"],
    "ntds": ["T1003.003"],
    "sam database": ["T1003.002"],
    "sam hive": ["T1003.002"],
    "cached credentials": ["T1003.005"],
    "cached domain credentials": ["T1003.005"],
    "lsa secrets": ["T1003.004"],
    "security account manager": ["T1003.002"],
    "credential manager": ["T1555.004"],
    "windows credential manager": ["T1555.004"],
    "keychain": ["T1555.001"],
    "browser credentials": ["T1555.003"],
    "browser passwords": ["T1555.003"],
    "password spray": ["T1110.003"],
    "password spraying": ["T1110.003"],
    "brute force": ["T1110"],
    "credential stuffing": ["T1110.004"],
    "rubeus": ["T1558"],
    "lazagne": ["T1555"],
    "pypykatz": ["T1003.001"],
    "procdump": ["T1003.001"],
    "comsvcs.dll": ["T1003.001"],
    "minidump": ["T1003.001"],
    
    # =========================================================================
    # EXECUTION (TA0002)
    # =========================================================================
    "powershell": ["T1059.001"],
    "powershell.exe": ["T1059.001"],
    "pwsh": ["T1059.001"],
    "invoke-expression": ["T1059.001"],
    "iex": ["T1059.001"],
    "invoke-command": ["T1059.001"],
    "downloadstring": ["T1059.001", "T1105"],
    "encodedcommand": ["T1059.001", "T1027"],
    "encoded command": ["T1059.001", "T1027"],
    "bypass executionpolicy": ["T1059.001"],
    "cmd.exe": ["T1059.003"],
    "cmd": ["T1059.003"],
    "command prompt": ["T1059.003"],
    "windows command shell": ["T1059.003"],
    "bash": ["T1059.004"],
    "sh": ["T1059.004"],
    "unix shell": ["T1059.004"],
    "linux shell": ["T1059.004"],
    "/bin/bash": ["T1059.004"],
    "/bin/sh": ["T1059.004"],
    "python": ["T1059.006"],
    "python.exe": ["T1059.006"],
    "python3": ["T1059.006"],
    "vbscript": ["T1059.005"],
    "cscript": ["T1059.005"],
    "wscript": ["T1059.005"],
    "javascript": ["T1059.007"],
    "jscript": ["T1059.007"],
    "applescript": ["T1059.002"],
    "osascript": ["T1059.002"],
    "wmi": ["T1047"],
    "wmic": ["T1047"],
    "wmic.exe": ["T1047"],
    "win32_process": ["T1047"],
    "invoke-wmimethod": ["T1047"],
    "mshta": ["T1218.005"],
    "mshta.exe": ["T1218.005"],
    "rundll32": ["T1218.011"],
    "rundll32.exe": ["T1218.011"],
    "regsvr32": ["T1218.010"],
    "regsvr32.exe": ["T1218.010"],
    "certutil": ["T1140", "T1105"],
    "certutil.exe": ["T1140", "T1105"],
    "bitsadmin": ["T1197", "T1105"],
    "bitsadmin.exe": ["T1197", "T1105"],
    "msiexec": ["T1218.007"],
    "msiexec.exe": ["T1218.007"],
    "installutil": ["T1218.004"],
    "installutil.exe": ["T1218.004"],
    "regasm": ["T1218.009"],
    "regsvcs": ["T1218.009"],
    "msbuild": ["T1127.001"],
    "msbuild.exe": ["T1127.001"],
    "cmstp": ["T1218.003"],
    "cmstp.exe": ["T1218.003"],
    "forfiles": ["T1202"],
    "pcalua": ["T1202"],
    "syncappvpublishingserver": ["T1216.001"],
    "control.exe": ["T1218.002"],
    "mavinject": ["T1218.013"],
    "odbcconf": ["T1218.008"],
    
    # =========================================================================
    # PERSISTENCE (TA0003)
    # =========================================================================
    "scheduled task": ["T1053.005"],
    "schtasks": ["T1053.005"],
    "schtasks.exe": ["T1053.005"],
    "at.exe": ["T1053.002"],
    "cron": ["T1053.003"],
    "crontab": ["T1053.003"],
    "registry run key": ["T1547.001"],
    "run key": ["T1547.001"],
    "runonce": ["T1547.001"],
    "hkcu run": ["T1547.001"],
    "hklm run": ["T1547.001"],
    "startup folder": ["T1547.001"],
    "autostart": ["T1547.001"],
    "service creation": ["T1543.003"],
    "new service": ["T1543.003"],
    "sc create": ["T1543.003"],
    "sc.exe": ["T1543.003"],
    "windows service": ["T1543.003"],
    "dll hijacking": ["T1574.001"],
    "dll search order hijacking": ["T1574.001"],
    "dll side-loading": ["T1574.002"],
    "dll sideloading": ["T1574.002"],
    "path interception": ["T1574.007"],
    "unquoted service path": ["T1574.009"],
    "bootkit": ["T1542.003"],
    "boot or logon autostart": ["T1547"],
    "winlogon": ["T1547.004"],
    "logon script": ["T1037.001"],
    "logon scripts": ["T1037.001"],
    "startup script": ["T1037"],
    "com hijacking": ["T1546.015"],
    "image file execution options": ["T1546.012"],
    "ifeo": ["T1546.012"],
    "accessibility features": ["T1546.008"],
    "sticky keys": ["T1546.008"],
    "sethc": ["T1546.008"],
    "utilman": ["T1546.008"],
    "account manipulation": ["T1098"],
    "ssh authorized keys": ["T1098.004"],
    "authorized_keys": ["T1098.004"],
    "web shell": ["T1505.003"],
    "webshell": ["T1505.003"],
    "backdoor": ["T1543"],
    
    # =========================================================================
    # PRIVILEGE ESCALATION (TA0004)
    # =========================================================================
    "uac bypass": ["T1548.002"],
    "user account control": ["T1548.002"],
    "bypass uac": ["T1548.002"],
    "fodhelper": ["T1548.002"],
    "eventvwr": ["T1548.002"],
    "sdclt": ["T1548.002"],
    "cmstp bypass": ["T1548.002"],
    "setuid": ["T1548.001"],
    "setgid": ["T1548.001"],
    "sudo": ["T1548.003"],
    "sudo caching": ["T1548.003"],
    "elevated privileges": ["T1548"],
    "privilege escalation": ["T1548"],
    "access token manipulation": ["T1134"],
    "token impersonation": ["T1134.001"],
    "token theft": ["T1134.001"],
    "create process with token": ["T1134.002"],
    "make and impersonate token": ["T1134.003"],
    "parent pid spoofing": ["T1134.004"],
    "ppid spoofing": ["T1134.004"],
    "potato": ["T1134"],
    "juicy potato": ["T1134"],
    "rotten potato": ["T1134"],
    "sweet potato": ["T1134"],
    "hot potato": ["T1134"],
    "printspoofer": ["T1134"],
    "getsystem": ["T1134"],
    "valid accounts": ["T1078"],
    "domain admin": ["T1078.002"],
    "local admin": ["T1078.003"],
    
    # =========================================================================
    # DEFENSE EVASION (TA0005)
    # =========================================================================
    "process injection": ["T1055"],
    "dll injection": ["T1055.001"],
    "createremotethread": ["T1055.001"],
    "remote thread injection": ["T1055.001"],
    "process hollowing": ["T1055.012"],
    "process doppelganging": ["T1055.013"],
    "thread execution hijacking": ["T1055.003"],
    "apc injection": ["T1055.004"],
    "ntqueueapcthread": ["T1055.004"],
    "atom bombing": ["T1055.009"],
    "extra window memory injection": ["T1055.011"],
    "ewmi": ["T1055.011"],
    "portable executable injection": ["T1055.002"],
    "pe injection": ["T1055.002"],
    "reflective dll injection": ["T1055.001"],
    "timestomp": ["T1070.006"],
    "timestamp": ["T1070.006"],
    "log clearing": ["T1070.001"],
    "clear event log": ["T1070.001"],
    "wevtutil": ["T1070.001"],
    "clear logs": ["T1070.001"],
    "indicator removal": ["T1070"],
    "file deletion": ["T1070.004"],
    "obfuscation": ["T1027"],
    "obfuscated": ["T1027"],
    "encoded command": ["T1027", "T1059.001"],
    "base64": ["T1027", "T1132.001"],
    "base64 encoded": ["T1027"],
    "xor": ["T1027"],
    "packing": ["T1027.002"],
    "packed": ["T1027.002"],
    "masquerading": ["T1036"],
    "rename": ["T1036.003"],
    "double extension": ["T1036.007"],
    "right-to-left override": ["T1036.002"],
    "rtlo": ["T1036.002"],
    "signed binary proxy": ["T1218"],
    "lolbin": ["T1218"],
    "lolbins": ["T1218"],
    "living off the land": ["T1218"],
    "disable defender": ["T1562.001"],
    "disable antivirus": ["T1562.001"],
    "tamper protection": ["T1562.001"],
    "disable windows defender": ["T1562.001"],
    "amsi bypass": ["T1562.001"],
    "etw bypass": ["T1562.006"],
    "rootkit": ["T1014"],
    "hidden files": ["T1564.001"],
    "hidden directories": ["T1564.001"],
    "attrib +h": ["T1564.001"],
    "alternate data stream": ["T1564.004"],
    "ads": ["T1564.004"],
    "ntfs ads": ["T1564.004"],
    "virtualization evasion": ["T1497"],
    "sandbox evasion": ["T1497"],
    "anti-vm": ["T1497.001"],
    "anti-sandbox": ["T1497.002"],
    
    # =========================================================================
    # DISCOVERY (TA0007)
    # =========================================================================
    "whoami": ["T1033"],
    "whoami.exe": ["T1033"],
    "net user": ["T1087.001"],
    "net user /domain": ["T1087.002"],
    "net group": ["T1087.002"],
    "net localgroup": ["T1087.001"],
    "get-aduser": ["T1087.002"],
    "get-adgroup": ["T1087.002"],
    "systeminfo": ["T1082"],
    "systeminfo.exe": ["T1082"],
    "hostname": ["T1082"],
    "ipconfig": ["T1016"],
    "ipconfig.exe": ["T1016"],
    "ifconfig": ["T1016"],
    "ip addr": ["T1016"],
    "arp -a": ["T1016"],
    "arp.exe": ["T1016"],
    "netstat": ["T1049"],
    "netstat.exe": ["T1049"],
    "ss -": ["T1049"],
    "network connections": ["T1049"],
    "tasklist": ["T1057"],
    "tasklist.exe": ["T1057"],
    "ps aux": ["T1057"],
    "get-process": ["T1057"],
    "process list": ["T1057"],
    "running processes": ["T1057"],
    "nltest": ["T1482"],
    "nltest.exe": ["T1482"],
    "domain trust": ["T1482"],
    "dsquery": ["T1018"],
    "net view": ["T1018"],
    "net view /domain": ["T1018"],
    "remote system discovery": ["T1018"],
    "ping sweep": ["T1018"],
    "nslookup": ["T1016"],
    "nbtstat": ["T1016"],
    "route print": ["T1016"],
    "quser": ["T1033"],
    "qwinsta": ["T1033"],
    "query user": ["T1033"],
    "dir": ["T1083"],
    "ls": ["T1083"],
    "find": ["T1083"],
    "file and directory discovery": ["T1083"],
    "reg query": ["T1012"],
    "registry query": ["T1012"],
    "seatbelt": ["T1082", "T1087"],
    "sharphound": ["T1087", "T1482"],
    "bloodhound": ["T1087", "T1482"],
    "adexplorer": ["T1087.002"],
    "adfind": ["T1087.002", "T1482"],
    "ldapsearch": ["T1087.002"],
    "powerview": ["T1087.002", "T1482"],
    "get-netuser": ["T1087.002"],
    "get-netgroup": ["T1087.002"],
    "get-netcomputer": ["T1018"],
    
    # =========================================================================
    # LATERAL MOVEMENT (TA0008)
    # =========================================================================
    "psexec": ["T1569.002", "T1021.002"],
    "psexec.exe": ["T1569.002", "T1021.002"],
    "paexec": ["T1569.002"],
    "wmiexec": ["T1047"],
    "smbexec": ["T1021.002"],
    "atexec": ["T1053.002"],
    "dcomexec": ["T1021.003"],
    "remote desktop": ["T1021.001"],
    "rdp": ["T1021.001"],
    "mstsc": ["T1021.001"],
    "mstsc.exe": ["T1021.001"],
    "terminal services": ["T1021.001"],
    "winrm": ["T1021.006"],
    "wsman": ["T1021.006"],
    "invoke-command -computername": ["T1021.006"],
    "enter-pssession": ["T1021.006"],
    "evil-winrm": ["T1021.006"],
    "ssh": ["T1021.004"],
    "ssh lateral": ["T1021.004"],
    "smb": ["T1021.002"],
    "smb/windows admin shares": ["T1021.002"],
    "admin$": ["T1021.002"],
    "c$": ["T1021.002"],
    "ipc$": ["T1021.002"],
    "net use": ["T1021.002"],
    "remote service": ["T1021"],
    "lateral movement": ["T1021"],
    "impacket": ["T1021.002", "T1047"],
    "crackmapexec": ["T1021.002"],
    "cme": ["T1021.002"],
    "remote file copy": ["T1570"],
    
    # =========================================================================
    # COLLECTION (TA0009)
    # =========================================================================
    "keylogger": ["T1056.001"],
    "keylogging": ["T1056.001"],
    "input capture": ["T1056"],
    "screen capture": ["T1113"],
    "screenshot": ["T1113"],
    "clipboard": ["T1115"],
    "clipboard data": ["T1115"],
    "email collection": ["T1114"],
    "local email collection": ["T1114.001"],
    "audio capture": ["T1123"],
    "video capture": ["T1125"],
    "webcam": ["T1125"],
    "data staged": ["T1074"],
    "local data staging": ["T1074.001"],
    "archive collected data": ["T1560"],
    "compress": ["T1560"],
    "7zip": ["T1560.001"],
    "zip": ["T1560.001"],
    "rar": ["T1560.001"],
    
    # =========================================================================
    # COMMAND AND CONTROL (TA0011)
    # =========================================================================
    "c2": ["T1071"],
    "c&c": ["T1071"],
    "command and control": ["T1071"],
    "beacon": ["T1071.001"],
    "callback": ["T1071.001"],
    "http c2": ["T1071.001"],
    "https c2": ["T1071.001"],
    "dns tunneling": ["T1071.004"],
    "dns c2": ["T1071.004"],
    "dnscat": ["T1071.004"],
    "cobalt strike": ["T1071.001", "T1059.001", "T1055"],
    "cobaltstrike": ["T1071.001"],
    "metasploit": ["T1059", "T1055", "T1071"],
    "meterpreter": ["T1059", "T1055"],
    "empire": ["T1059.001", "T1071"],
    "covenant": ["T1071"],
    "sliver": ["T1071"],
    "mythic": ["T1071"],
    "brute ratel": ["T1071"],
    "bruteratel": ["T1071"],
    "havoc": ["T1071"],
    "proxy": ["T1090"],
    "multi-hop proxy": ["T1090.003"],
    "domain fronting": ["T1090.004"],
    "web service": ["T1102"],
    "dead drop resolver": ["T1102.001"],
    "data encoding": ["T1132"],
    "standard encoding": ["T1132.001"],
    "non-standard encoding": ["T1132.002"],
    "encrypted channel": ["T1573"],
    "ssl": ["T1573.002"],
    "tls": ["T1573.002"],
    "port knocking": ["T1205.001"],
    "fallback channels": ["T1008"],
    "remote access tools": ["T1219"],
    "teamviewer": ["T1219"],
    "anydesk": ["T1219"],
    "remote access trojan": ["T1219"],
    "rat": ["T1219"],
    
    # =========================================================================
    # EXFILTRATION (TA0010)
    # =========================================================================
    "data exfiltration": ["T1041"],
    "exfil": ["T1041"],
    "exfiltration over c2": ["T1041"],
    "exfiltration over web service": ["T1567"],
    "exfil to cloud storage": ["T1567.002"],
    "exfiltration over dns": ["T1048.003"],
    "exfiltration over alternative protocol": ["T1048"],
    "scheduled transfer": ["T1029"],
    "data transfer size limits": ["T1030"],
    "automated exfiltration": ["T1020"],
    
    # =========================================================================
    # IMPACT (TA0040)
    # =========================================================================
    "ransomware": ["T1486"],
    "encryption": ["T1486"],
    "data encrypted for impact": ["T1486"],
    "data destruction": ["T1485"],
    "wiper": ["T1485"],
    "defacement": ["T1491"],
    "disk wipe": ["T1561"],
    "disk content wipe": ["T1561.001"],
    "disk structure wipe": ["T1561.002"],
    "inhibit system recovery": ["T1490"],
    "delete shadow copies": ["T1490"],
    "vssadmin delete shadows": ["T1490"],
    "bcdedit": ["T1490"],
    "wbadmin": ["T1490"],
    "service stop": ["T1489"],
    "stop service": ["T1489"],
    "net stop": ["T1489"],
    "resource hijacking": ["T1496"],
    "cryptominer": ["T1496"],
    "crypto miner": ["T1496"],
    "cryptojacking": ["T1496"],
    "account access removal": ["T1531"],
    
    # =========================================================================
    # INITIAL ACCESS (TA0001)
    # =========================================================================
    "phishing": ["T1566"],
    "spearphishing": ["T1566.001"],
    "spearphishing attachment": ["T1566.001"],
    "spearphishing link": ["T1566.002"],
    "macro": ["T1566.001", "T1059.005"],
    "malicious macro": ["T1566.001"],
    "drive-by compromise": ["T1189"],
    "drive-by": ["T1189"],
    "watering hole": ["T1189"],
    "exploit public-facing application": ["T1190"],
    "external remote services": ["T1133"],
    "vpn": ["T1133"],
    "citrix": ["T1133"],
    "hardware additions": ["T1200"],
    "usb": ["T1200", "T1091"],
    "replication through removable media": ["T1091"],
    "supply chain compromise": ["T1195"],
    "trusted relationship": ["T1199"],
    
    # =========================================================================
    # WINDOWS EVENT IDS (Very actionable!)
    # =========================================================================
    "event 1": ["T1059"],  # Sysmon - Process creation
    "event id 1": ["T1059"],
    "eventid 1": ["T1059"],
    "sysmon 1": ["T1059"],
    "event 3": ["T1071"],  # Sysmon - Network connection
    "event id 3": ["T1071"],
    "sysmon 3": ["T1071"],
    "event 7": ["T1055.001"],  # Sysmon - Image loaded
    "event id 7": ["T1055.001"],
    "sysmon 7": ["T1055.001"],
    "event 8": ["T1055"],  # Sysmon - CreateRemoteThread
    "event id 8": ["T1055"],
    "sysmon 8": ["T1055"],
    "event 10": ["T1003.001"],  # Sysmon - ProcessAccess (LSASS)
    "event id 10": ["T1003.001"],
    "sysmon 10": ["T1003.001"],
    "event 11": ["T1105"],  # Sysmon - FileCreate
    "event id 11": ["T1105"],
    "sysmon 11": ["T1105"],
    "event 12": ["T1547.001"],  # Sysmon - RegistryEvent (create/delete)
    "event id 12": ["T1547.001"],
    "sysmon 12": ["T1547.001"],
    "event 13": ["T1547.001"],  # Sysmon - RegistryEvent (set value)
    "event id 13": ["T1547.001"],
    "sysmon 13": ["T1547.001"],
    "event 22": ["T1071.004"],  # Sysmon - DNSEvent
    "event id 22": ["T1071.004"],
    "sysmon 22": ["T1071.004"],
    "event 4624": ["T1078"],  # Windows Security - Successful logon
    "event id 4624": ["T1078"],
    "4624": ["T1078"],
    "event 4625": ["T1110"],  # Windows Security - Failed logon
    "event id 4625": ["T1110"],
    "4625": ["T1110"],
    "event 4648": ["T1078"],  # Windows Security - Explicit credential logon
    "event id 4648": ["T1078"],
    "event 4672": ["T1078"],  # Windows Security - Special privileges
    "event id 4672": ["T1078"],
    "4672": ["T1078"],
    "event 4688": ["T1059"],  # Windows Security - Process creation
    "event id 4688": ["T1059"],
    "4688": ["T1059"],
    "event 4698": ["T1053.005"],  # Windows Security - Scheduled task created
    "event id 4698": ["T1053.005"],
    "4698": ["T1053.005"],
    "event 4720": ["T1136.001"],  # Windows Security - User account created
    "event id 4720": ["T1136.001"],
    "4720": ["T1136.001"],
    "event 4732": ["T1098"],  # Windows Security - Member added to local group
    "event id 4732": ["T1098"],
    "event 4768": ["T1558"],  # Windows Security - Kerberos TGT request
    "event id 4768": ["T1558"],
    "event 4769": ["T1558.003"],  # Windows Security - Kerberos service ticket
    "event id 4769": ["T1558.003"],
    "4769": ["T1558.003"],
    "event 4771": ["T1110"],  # Windows Security - Kerberos pre-auth failed
    "event id 4771": ["T1110"],
    "event 4776": ["T1110"],  # Windows Security - NTLM authentication
    "event id 4776": ["T1110"],
    "event 5140": ["T1021.002"],  # Windows Security - Network share access
    "event id 5140": ["T1021.002"],
    "event 5145": ["T1021.002"],  # Windows Security - Network share object checked
    "event id 5145": ["T1021.002"],
    "event 7045": ["T1543.003"],  # System - Service installed
    "event id 7045": ["T1543.003"],
    "7045": ["T1543.003"],
    "event 1102": ["T1070.001"],  # Security log cleared
    "event id 1102": ["T1070.001"],
    "1102": ["T1070.001"],
}

# Normalize aliases for lookup
_ALIAS_INDEX: Dict[str, List[str]] = {}


def _build_alias_index() -> None:
    """Build normalized alias lookup index."""
    _ALIAS_INDEX.clear()
    for alias, tech_ids in TECHNIQUE_ALIASES.items():
        normalized = _normalize_text(alias)
        if normalized:
            _ALIAS_INDEX[normalized] = tech_ids


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TechniqueRecord:
    """Cached technique metadata."""
    id: str
    name: str
    normalized_name: str
    parent_id: Optional[str] = None
    tactic_ids: Tuple[str, ...] = ()


@dataclass(frozen=True)
class TechniqueCandidate:
    """A candidate technique match with confidence score."""
    id: str
    name: str
    score: float      # 0.0 – 1.0
    source: str       # e.g. "id_regex", "name_exact", "name_fuzzy", "alias"


# Global indexes
_TECHNIQUES: Dict[str, TechniqueRecord] = {}
_NAME_INDEX: Dict[str, Set[str]] = {}
_PARENT_INDEX: Dict[str, Set[str]] = {}
_TACTIC_INDEX: Dict[str, Set[str]] = {}  # tactic_id -> technique_ids

_LOADED_ONCE = False
_LAST_LOADED_SIGNATURE: Optional[Tuple[Optional[int], Optional[int]]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_text(s: str) -> str:
    """Normalize text for matching: lowercase, alphanumeric only, single spaces."""
    s = s.lower()
    s = "".join(ch if ch.isalnum() else " " for ch in s)
    return " ".join(s.split())


def _extract_parent_id(tech_id: str) -> Optional[str]:
    """Extract parent technique ID from sub-technique ID."""
    if "." in tech_id:
        return tech_id.split(".")[0]
    return None


def _add_technique(tech_id: str, name: Optional[str], tactic_ids: Optional[List[str]] = None) -> None:
    """Add a technique to the index."""
    if not tech_id:
        return

    tech_id = tech_id.upper()
    name = (name or "").strip()
    normalized = _normalize_text(name) if name else ""
    parent_id = _extract_parent_id(tech_id)
    tactics = tuple(tactic_ids or [])

    if tech_id in _TECHNIQUES:
        existing = _TECHNIQUES[tech_id]
        if existing.name:
            return

    rec = TechniqueRecord(
        id=tech_id,
        name=name,
        normalized_name=normalized,
        parent_id=parent_id,
        tactic_ids=tactics,
    )
    _TECHNIQUES[tech_id] = rec

    if normalized:
        _NAME_INDEX.setdefault(normalized, set()).add(tech_id)

    if parent_id:
        _PARENT_INDEX.setdefault(parent_id, set()).add(tech_id)

    for tactic_id in tactics:
        _TACTIC_INDEX.setdefault(tactic_id, set()).add(tech_id)


def _clear_index() -> None:
    """Clear all indexes."""
    _TECHNIQUES.clear()
    _NAME_INDEX.clear()
    _PARENT_INDEX.clear()
    _TACTIC_INDEX.clear()


def _mtime_ns(path: Path) -> Optional[int]:
    """Get file modification time in nanoseconds, or None if not found."""
    try:
        return path.stat().st_mtime_ns
    except FileNotFoundError:
        return None


def _infer_technique_id_from_chunk_record(rec: dict) -> Optional[str]:
    """Infer technique ID from a chunk record."""
    chunk_id = rec.get("chunk_id")
    if isinstance(chunk_id, str) and chunk_id:
        m = _CHUNKID_TECH_PREFIX_RE.match(chunk_id)
        if m:
            return m.group(1).upper()

    for key in ("technique_id", "id"):
        v = rec.get(key)
        if isinstance(v, str) and v:
            m = TECHID_RE.search(v)
            if m:
                return m.group(1).upper()

    return None


# ---------------------------------------------------------------------------
# Loading functions
# ---------------------------------------------------------------------------

def _load_techniques_from_knowledge_pack(path: Path) -> None:
    """Load technique ID -> name from mitre_knowledge_pack_v1.jsonl."""
    count_lines = 0
    before = len(_TECHNIQUES)

    print(f"[resolver] Loading techniques from knowledge pack: {path} ...")

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            count_lines += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            tech_id = rec.get("technique_id")
            tech_name = rec.get("technique_name")
            tactic_ids = rec.get("tactic_ids", [])

            if isinstance(tech_id, str) and tech_id:
                _add_technique(
                    tech_id,
                    str(tech_name) if tech_name is not None else None,
                    tactic_ids if isinstance(tactic_ids, list) else None,
                )

    print(f"[resolver] Parsed {count_lines} technique records; before={before}, after={len(_TECHNIQUES)}")


def _load_techniques_from_chunks(path: Path) -> None:
    """Fallback: build technique ID -> name mapping by scanning chunks."""
    count_lines = 0
    before = len(_TECHNIQUES)

    print(f"[resolver] Loading techniques from chunks: {path} ...")

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            count_lines += 1

            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            meta = rec.get("metadata", {}) or {}
            if not isinstance(meta, dict):
                meta = {}

            tech_id = (
                rec.get("technique_id")
                or meta.get("technique_id")
                or _infer_technique_id_from_chunk_record(rec)
            )

            tech_name = (
                rec.get("technique_name")
                or meta.get("technique_name")
                or rec.get("name")
                or meta.get("name")
            )

            if isinstance(tech_id, str) and tech_id:
                _add_technique(tech_id, str(tech_name) if tech_name is not None else None)

    print(f"[resolver] Parsed {count_lines} chunk records; before={before}, after={len(_TECHNIQUES)}")


def ensure_loaded(force: bool = False) -> None:
    """Lazy-load index."""
    global _LOADED_ONCE, _LAST_LOADED_SIGNATURE

    kp_m = _mtime_ns(KNOWLEDGE_PACK_PATH)
    ch_m = _mtime_ns(CHUNKS_PATH)
    signature = (kp_m, ch_m)

    if not force and _LOADED_ONCE and _LAST_LOADED_SIGNATURE == signature and _TECHNIQUES:
        return

    if kp_m is None and ch_m is None:
        print(
            f"[resolver] WARNING: resolver sources not found:\n"
            f"  - knowledge pack: {KNOWLEDGE_PACK_PATH}\n"
            f"  - chunks:         {CHUNKS_PATH}\n"
            "Technique resolver will remain empty until one exists."
        )
        _LOADED_ONCE = True
        _LAST_LOADED_SIGNATURE = signature
        return

    _clear_index()

    if kp_m is not None:
        _load_techniques_from_knowledge_pack(KNOWLEDGE_PACK_PATH)
    elif ch_m is not None:
        _load_techniques_from_chunks(CHUNKS_PATH)

    _build_alias_index()

    _LOADED_ONCE = True
    _LAST_LOADED_SIGNATURE = signature

    sub_technique_count = sum(1 for t in _TECHNIQUES.values() if t.parent_id)
    print(
        f"[resolver] Technique resolver ready: "
        f"{len(_TECHNIQUES)} techniques ({sub_technique_count} sub-techniques), "
        f"{len(_ALIAS_INDEX)} aliases"
    )


# ---------------------------------------------------------------------------
# Fuzzy matching
# ---------------------------------------------------------------------------

try:
    from rapidfuzz import fuzz as _rfuzz
    _HAVE_RAPIDFUZZ = True
except ImportError:
    _HAVE_RAPIDFUZZ = False


def _fuzzy_score(name: str, text: str) -> float:
    """Compute fuzzy match score between technique name and text."""
    name_l = name.lower()
    text_l = text.lower()

    if not name_l or not text_l:
        return 0.0

    if _HAVE_RAPIDFUZZ:
        score = _rfuzz.partial_ratio(name_l, text_l)
        return float(score) / 100.0

    if name_l in text_l:
        return 0.8

    name_words = set(name_l.split())
    text_words = set(text_l.split())
    if name_words and text_words:
        overlap = len(name_words & text_words) / len(name_words)
        if overlap >= 0.5:
            return 0.6 * overlap

    return 0.0


# ---------------------------------------------------------------------------
# Context-aware scoring (NEW)
# ---------------------------------------------------------------------------

DETECTION_KEYWORDS = {
    "detect", "detection", "hunt", "hunting", "monitor", "alert",
    "sysmon", "event id", "eventid", "log", "telemetry", "analytic",
    "sigma", "rule", "indicator", "ioc"
}

MITIGATION_KEYWORDS = {
    "mitigate", "mitigation", "prevent", "block", "remediate", "defense",
    "protect", "countermeasure", "control", "harden", "secure"
}


def _get_context_boost(query: str) -> Tuple[float, float]:
    """
    Analyze query for context and return (detection_boost, mitigation_boost).
    
    Returns boosts to apply to detection-focused or mitigation-focused results.
    """
    query_lower = query.lower()
    query_words = set(query_lower.split())
    
    detection_boost = 0.0
    mitigation_boost = 0.0
    
    if query_words & DETECTION_KEYWORDS:
        detection_boost = 0.1
    
    if query_words & MITIGATION_KEYWORDS:
        mitigation_boost = 0.1
    
    return detection_boost, mitigation_boost


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_all_techniques() -> List[TechniqueRecord]:
    """Get all loaded techniques."""
    ensure_loaded()
    return list(_TECHNIQUES.values())


def get_technique(tech_id: str) -> Optional[TechniqueRecord]:
    """Get a specific technique by ID."""
    ensure_loaded()
    return _TECHNIQUES.get(tech_id.upper())


def get_sub_techniques(parent_id: str) -> List[TechniqueRecord]:
    """Get all sub-techniques for a parent technique ID."""
    ensure_loaded()
    parent_id = parent_id.upper()
    sub_ids = _PARENT_INDEX.get(parent_id, set())
    return [_TECHNIQUES[tid] for tid in sub_ids if tid in _TECHNIQUES]


def get_techniques_by_tactic(tactic_id: str) -> List[TechniqueRecord]:
    """Get all techniques for a given tactic."""
    ensure_loaded()
    tactic_id = tactic_id.upper()
    tech_ids = _TACTIC_INDEX.get(tactic_id, set())
    return [_TECHNIQUES[tid] for tid in tech_ids if tid in _TECHNIQUES]


@lru_cache(maxsize=1024)
def resolve_techniques_from_text_cached(text: str, max_results: int = 5) -> Tuple[TechniqueCandidate, ...]:
    """Cached version of resolve_techniques_from_text."""
    return tuple(resolve_techniques_from_text(text, max_results=max_results, include_parent_boost=True))


def resolve_techniques_from_text(
    text: str,
    max_results: int = 5,
    include_parent_boost: bool = True,
) -> List[TechniqueCandidate]:
    """
    Extract technique candidates from free text.
    
    Matching strategies (in order of confidence):
    1. Explicit IDs via regex (T1234, T1234.001) - score: 1.0
    2. Alias matching (e.g., "mimikatz" -> T1003.001) - score: 0.92
    3. Exact name match (normalized) - score: 0.90
    4. Fuzzy name match - score: varies (0.7-0.85)
    5. Parent technique boost (if sub-technique matched) - score: 0.5
    """
    ensure_loaded()

    if not text or not _TECHNIQUES:
        return []

    text_norm = _normalize_text(text)
    text_lower = text.lower()

    candidates: Dict[str, TechniqueCandidate] = {}

    def _update_candidate(tid: str, name: str, score: float, source: str) -> None:
        existing = candidates.get(tid)
        if existing is None or score > existing.score:
            candidates[tid] = TechniqueCandidate(id=tid, name=name, score=score, source=source)

    # 1) Explicit IDs via regex
    for match in TECHID_RE.finditer(text):
        tid = match.group(1).upper()
        rec = _TECHNIQUES.get(tid)
        _update_candidate(tid, rec.name if rec else "", 1.0, "id_regex")

    # 2) Alias matching
    for alias_norm, tech_ids in _ALIAS_INDEX.items():
        if alias_norm in text_norm:
            for tid in tech_ids:
                rec = _TECHNIQUES.get(tid)
                if rec:
                    _update_candidate(tid, rec.name, 0.92, "alias")

    # 3) Exact name match (normalized substring)
    for rec in _TECHNIQUES.values():
        if rec.normalized_name and len(rec.normalized_name) >= 4:
            if rec.normalized_name in text_norm:
                _update_candidate(rec.id, rec.name, 0.90, "name_exact")

    # 4) Fuzzy match
    for rec in _TECHNIQUES.values():
        if not rec.name or len(rec.name) < 5:
            continue

        existing = candidates.get(rec.id)
        if existing and existing.score >= 0.85:
            continue

        score = _fuzzy_score(rec.name, text_lower)
        if score >= 0.70:
            adjusted_score = 0.70 + (score - 0.70) * 0.5
            _update_candidate(rec.id, rec.name, adjusted_score, "name_fuzzy")

    # 5) Parent technique boost
    if include_parent_boost:
        matched_parents: Set[str] = set()
        for tid in list(candidates.keys()):
            rec = _TECHNIQUES.get(tid)
            if rec and rec.parent_id:
                matched_parents.add(rec.parent_id)

        for parent_id in matched_parents:
            if parent_id not in candidates:
                parent_rec = _TECHNIQUES.get(parent_id)
                if parent_rec:
                    _update_candidate(parent_id, parent_rec.name, 0.50, "parent_boost")

    # Sort by score descending, then by ID for stability
    sorted_candidates = sorted(
        candidates.values(),
        key=lambda c: (-c.score, c.id),
    )

    return sorted_candidates[:max_results]


def resolve_technique_id(text: str) -> Optional[str]:
    """Convenience function: resolve the single best technique ID from text."""
    candidates = resolve_techniques_from_text(text, max_results=1)
    return candidates[0].id if candidates else None


def extract_all_technique_ids(text: str) -> List[str]:
    """
    Extract ALL technique IDs mentioned in text (regex only).
    
    Unlike resolve_techniques_from_text, this only finds explicit IDs,
    not aliases or fuzzy matches.
    """
    matches = TECHID_RE.findall(text)
    seen = set()
    result = []
    for m in matches:
        tid = m.upper()
        if tid not in seen:
            seen.add(tid)
            result.append(tid)
    return result


def get_alias_count() -> int:
    """Get the number of aliases in the index."""
    return len(_ALIAS_INDEX)


def lookup_alias(term: str) -> List[str]:
    """
    Look up technique IDs for a specific alias term.
    
    Useful for debugging or understanding alias mappings.
    """
    ensure_loaded()
    normalized = _normalize_text(term)
    return _ALIAS_INDEX.get(normalized, [])


# ---------------------------------------------------------------------------
# CLI for testing
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI for testing the resolver."""
    import argparse

    parser = argparse.ArgumentParser(description="Test technique resolver")
    parser.add_argument("text", nargs="+", help="Text to analyze")
    parser.add_argument("-n", "--max-results", type=int, default=5, help="Max results")
    parser.add_argument("--reload", action="store_true", help="Force reload index")
    parser.add_argument("--aliases", action="store_true", help="Show alias lookup")

    args = parser.parse_args()
    text = " ".join(args.text)

    if args.reload:
        ensure_loaded(force=True)

    if args.aliases:
        # Alias lookup mode
        tech_ids = lookup_alias(text)
        if tech_ids:
            print(f"[resolver] Alias '{text}' maps to: {tech_ids}")
        else:
            print(f"[resolver] No alias found for: '{text}'")
        return

    print(f"\n[resolver] Input: {text!r}\n")

    candidates = resolve_techniques_from_text(text, max_results=args.max_results)

    if not candidates:
        print("[resolver] No techniques found.")
        return

    print("[resolver] Candidates:")
    for c in candidates:
        print(f"  {c.id:12} | {c.score:.2f} | {c.source:12} | {c.name}")


if __name__ == "__main__":
    main()