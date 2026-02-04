"""
MITRE ATT&CK Tactic definitions and mappings.

This module contains the official tactic taxonomy and mappings
to key techniques for each tactic.
"""

from enum import Enum
from typing import Dict, List, Optional, Tuple


class Tactic(Enum):
    """MITRE ATT&CK Tactics with their IDs and common aliases."""

    RECONNAISSANCE = ("TA0043", ["recon", "reconnaissance", "information gathering", "target selection"])
    RESOURCE_DEVELOPMENT = ("TA0042", ["resource development", "infrastructure", "capability development"])
    INITIAL_ACCESS = ("TA0001", ["initial access", "entry point", "breach", "compromise"])
    EXECUTION = ("TA0002", ["execution", "run", "execute", "code execution"])
    PERSISTENCE = ("TA0003", ["persistence", "persist", "maintain access", "foothold"])
    PRIVILEGE_ESCALATION = ("TA0004", ["privilege escalation", "privesc", "elevate", "admin access", "root"])
    DEFENSE_EVASION = ("TA0005", ["defense evasion", "evasion", "avoid detection", "stealth"])
    CREDENTIAL_ACCESS = ("TA0006", ["credential access", "credential", "password", "authentication", "dumping"])
    DISCOVERY = ("TA0007", ["discovery", "enumerate", "reconnaissance internal", "survey"])
    LATERAL_MOVEMENT = ("TA0008", ["lateral movement", "lateral", "move laterally", "pivot", "spread"])
    COLLECTION = ("TA0009", ["collection", "collect", "gather data", "data staging"])
    COMMAND_AND_CONTROL = ("TA0011", ["command and control", "c2", "c&c", "beacon", "callback"])
    EXFILTRATION = ("TA0010", ["exfiltration", "exfil", "data theft", "steal data"])
    IMPACT = ("TA0040", ["impact", "destroy", "disrupt", "ransomware", "wiper"])

    def __init__(self, tactic_id: str, aliases: List[str]):
        self.tactic_id = tactic_id
        self.aliases = aliases

    @classmethod
    def from_id(cls, tactic_id: str) -> Optional["Tactic"]:
        """Get Tactic enum from tactic ID."""
        tactic_id = tactic_id.upper()
        for tactic in cls:
            if tactic.tactic_id == tactic_id:
                return tactic
        return None

    @classmethod
    def from_alias(cls, alias: str) -> Optional["Tactic"]:
        """Get Tactic enum from alias string."""
        alias_lower = alias.lower()
        for tactic in cls:
            for tactic_alias in tactic.aliases:
                if tactic_alias in alias_lower or alias_lower in tactic_alias:
                    return tactic
        return None


# Tactic ID to key techniques mapping
# These are the most common/important techniques for each tactic
TACTIC_KEY_TECHNIQUES: Dict[str, List[str]] = {
    "TA0043": ["T1595", "T1592", "T1589", "T1590", "T1591"],  # Reconnaissance
    "TA0042": ["T1583", "T1584", "T1585", "T1586", "T1587"],  # Resource Development
    "TA0001": ["T1566", "T1190", "T1133", "T1078", "T1189"],  # Initial Access
    "TA0002": ["T1059", "T1204", "T1053", "T1203", "T1047"],  # Execution
    "TA0003": ["T1547", "T1053", "T1136", "T1098", "T1543"],  # Persistence
    "TA0004": ["T1548", "T1134", "T1068", "T1078", "T1055"],  # Privilege Escalation
    "TA0005": ["T1027", "T1070", "T1562", "T1036", "T1055"],  # Defense Evasion
    "TA0006": ["T1003", "T1558", "T1555", "T1552", "T1110"],  # Credential Access
    "TA0007": ["T1082", "T1083", "T1057", "T1018", "T1087"],  # Discovery
    "TA0008": ["T1021", "T1570", "T1072", "T1080", "T1563"],  # Lateral Movement
    "TA0009": ["T1560", "T1123", "T1119", "T1115", "T1074"],  # Collection
    "TA0011": ["T1071", "T1095", "T1573", "T1105", "T1572"],  # Command and Control
    "TA0010": ["T1041", "T1048", "T1567", "T1029", "T1030"],  # Exfiltration
    "TA0040": ["T1486", "T1485", "T1490", "T1489", "T1491"],  # Impact
}


# Build reverse mappings
TACTIC_ID_TO_NAME: Dict[str, str] = {
    tactic.tactic_id: tactic.name.lower().replace("_", " ")
    for tactic in Tactic
}

TACTIC_NAME_TO_ID: Dict[str, str] = {
    tactic.name.lower().replace("_", " "): tactic.tactic_id
    for tactic in Tactic
}


def detect_tactic_from_query(query: str) -> Optional[Tuple[str, str]]:
    """
    Detect if the query is asking about a specific tactic.

    Returns:
        Tuple of (tactic_name, tactic_id) or None if no tactic detected.
    """
    query_lower = query.lower()

    for tactic in Tactic:
        for alias in tactic.aliases:
            if alias in query_lower:
                return (tactic.name.lower().replace("_", " "), tactic.tactic_id)

    return None


def get_key_techniques_for_tactic(tactic_id: str) -> List[str]:
    """Get key techniques for a given tactic ID."""
    return TACTIC_KEY_TECHNIQUES.get(tactic_id.upper(), [])
