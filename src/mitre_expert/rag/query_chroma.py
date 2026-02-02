"""
Production-Grade Query Module for MITRE ATT&CK and D3FEND chunks.

FEATURES:
  1. Cross-encoder reranking for better precision
  2. Hybrid search (BM25 + semantic) with RRF fusion
  3. LM Studio embedding support (default)
  4. Advanced query expansion for MITRE-specific terms
  5. Tactic-aware query routing
  6. Multi-strategy retrieval with fallback
  7. Comprehensive error handling
  8. Query intent classification
  9. Result validation and quality scoring

Configuration:
  MITRE_EMBED_BACKEND     - "lmstudio" (default), "ollama", or "hf"
  MITRE_RERANK_ENABLED    - "true" to enable reranking (default: true)
  MITRE_HYBRID_ENABLED    - "true" to enable hybrid search (default: false)
  MITRE_QUERY_EXPANSION   - "true" to enable query expansion (default: true)
  MITRE_STRICT_MODE       - "true" for production strict validation (default: false)
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import chromadb
from chromadb.utils import embedding_functions

from mitre_expert.config import (
    CHROMA_DB_DIR,
    MITRE_CHROMA_COLLECTION,
    D3FEND_CHROMA_COLLECTION,
    PREFETCH_K,
    GET_HARD_CAP,
    EMBED_BACKEND,
    HF_EMBED_MODEL,
    OLLAMA_EMBED_MODEL,
    OLLAMA_BASE_URL,
    LMSTUDIO_BASE_URL,
    LMSTUDIO_EMBED_MODEL,
)

# Conditional import for technique resolver
try:
    from mitre_expert.models.technique_resolver import (
        resolve_techniques_from_text,
        TechniqueCandidate,
    )
    TECHNIQUE_RESOLVER_AVAILABLE = True
except ImportError:
    TECHNIQUE_RESOLVER_AVAILABLE = False
    TechniqueCandidate = None


# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mitre_expert.query")


# ---------------------------------------------------------------------------
# Feature Flags
# ---------------------------------------------------------------------------

RERANK_ENABLED = os.getenv("MITRE_RERANK_ENABLED", "true").lower() == "true"
HYBRID_ENABLED = os.getenv("MITRE_HYBRID_ENABLED", "false").lower() == "true"
QUERY_EXPANSION_ENABLED = os.getenv("MITRE_QUERY_EXPANSION", "true").lower() == "true"
STRICT_MODE = os.getenv("MITRE_STRICT_MODE", "false").lower() == "true"

# Minimum confidence thresholds for production
MIN_RERANK_SCORE = float(os.getenv("MITRE_MIN_RERANK_SCORE", "-5.0"))
MIN_SEMANTIC_SIMILARITY = float(os.getenv("MITRE_MIN_SEMANTIC_SIMILARITY", "0.3"))


# ---------------------------------------------------------------------------
# MITRE ATT&CK Tactic Definitions
# ---------------------------------------------------------------------------

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


# Tactic ID to key techniques mapping
TACTIC_KEY_TECHNIQUES: Dict[str, List[str]] = {
    "TA0043": ["T1595", "T1592", "T1589", "T1590", "T1591"],
    "TA0042": ["T1583", "T1584", "T1585", "T1586", "T1587"],
    "TA0001": ["T1566", "T1190", "T1133", "T1078", "T1189"],
    "TA0002": ["T1059", "T1204", "T1053", "T1203", "T1047"],
    "TA0003": ["T1547", "T1053", "T1136", "T1098", "T1543"],
    "TA0004": ["T1548", "T1134", "T1068", "T1078", "T1055"],
    "TA0005": ["T1027", "T1070", "T1562", "T1036", "T1055"],
    "TA0006": ["T1003", "T1558", "T1555", "T1552", "T1110"],
    "TA0007": ["T1082", "T1083", "T1057", "T1018", "T1087"],
    "TA0008": ["T1021", "T1570", "T1072", "T1080", "T1563"],
    "TA0009": ["T1560", "T1123", "T1119", "T1115", "T1074"],
    "TA0011": ["T1071", "T1095", "T1573", "T1105", "T1572"],
    "TA0010": ["T1041", "T1048", "T1567", "T1029", "T1030"],
    "TA0040": ["T1486", "T1485", "T1490", "T1489", "T1491"],
}


# ---------------------------------------------------------------------------
# Query Intent Classification
# ---------------------------------------------------------------------------

class QueryIntent(Enum):
    """Classification of user query intent."""
    TECHNIQUE_SPECIFIC = "technique_specific"
    TACTIC_BROAD = "tactic_broad"
    DETECTION = "detection"
    MITIGATION = "mitigation"
    PROCEDURE = "procedure"
    DEFINITION = "definition"
    COMPARISON = "comparison"
    DEFENSE = "defense"
    UNKNOWN = "unknown"


@dataclass
class QueryAnalysis:
    """Result of analyzing a user query."""
    original_query: str
    intent: QueryIntent
    detected_tactic: Optional[str] = None
    detected_tactic_id: Optional[str] = None
    detected_techniques: List[str] = field(default_factory=list)
    detected_sections: List[str] = field(default_factory=list)
    expanded_query: str = ""
    confidence: float = 0.0
    suggested_filters: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Enhanced Query Expansion
# ---------------------------------------------------------------------------

MITRE_SYNONYMS = {
    "powershell": ["T1059.001", "command scripting interpreter", "script execution", "pwsh"],
    "cmd": ["T1059.003", "windows command shell", "command prompt", "cmd.exe"],
    "bash": ["T1059.004", "unix shell", "linux shell", "/bin/bash"],
    "python": ["T1059.006", "scripting", "script interpreter"],
    "wmi": ["T1047", "windows management instrumentation", "wmic"],
    "mimikatz": ["T1003", "credential dumping", "LSASS", "password extraction", "sekurlsa"],
    "credential": ["T1003", "password", "hash", "NTLM", "Kerberos", "authentication"],
    "injection": ["T1055", "process injection", "DLL injection", "memory injection"],
    "persistence": ["T1547", "boot", "autostart", "registry", "scheduled task"],
    "c2": ["command and control", "beacon", "callback", "C&C", "implant"],
    "exfil": ["exfiltration", "data theft", "data transfer", "upload"],
    "privilege": ["T1548", "elevation", "escalation", "admin", "root", "UAC"],
    "defense evasion": ["T1027", "obfuscation", "encoding", "packing", "bypass"],
    "phishing": ["T1566", "spearphishing", "email", "attachment", "link"],
    "ransomware": ["T1486", "encryption", "data encrypted", "crypto"],
    "rdp": ["T1021.001", "remote desktop", "mstsc", "terminal services"],
    "smb": ["T1021.002", "windows admin shares", "net use", "psexec"],
    "ssh": ["T1021.004", "secure shell", "openssh"],
    "winrm": ["T1021.006", "windows remote management", "powershell remoting"],
    "psexec": ["T1021.002", "T1569.002", "remote service"],
    "cobalt strike": ["T1059.001", "beacon", "malleable c2"],
    "lsass": ["T1003.001", "local security authority", "credential dumping"],
    "sam": ["T1003.002", "security account manager", "registry hive"],
    "ntds": ["T1003.003", "active directory", "domain controller"],
    "kerberos": ["T1558", "golden ticket", "silver ticket", "kerberoasting"],
    "dcsync": ["T1003.006", "domain replication"],
    "sysmon": ["WinEventLog:Sysmon", "event id 1", "process creation"],
    "security log": ["WinEventLog:Security", "event id 4688", "event id 4624"],
    "auditd": ["linux audit", "syscall", "execve"],
    "detect": ["detection", "hunt", "monitor", "alert", "identify"],
    "mitigate": ["mitigation", "prevent", "block", "remediate", "defense"],
    "hunt": ["threat hunting", "proactive", "search", "investigate"],
}

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
}


def detect_tactic_from_query(query: str) -> Optional[Tuple[str, str]]:
    """Detect if the query is asking about a specific tactic."""
    query_lower = query.lower()
    
    for tactic in Tactic:
        for alias in tactic.aliases:
            if alias in query_lower:
                return (tactic.name.lower().replace("_", " "), tactic.tactic_id)
    
    return None


def detect_technique_ids_from_query(query: str) -> List[str]:
    """Extract technique IDs mentioned in the query."""
    pattern = r'\bT\d{4}(?:\.\d{3})?\b'
    matches = re.findall(pattern, query, re.IGNORECASE)
    return [m.upper() for m in matches]


def classify_query_intent(query: str) -> QueryIntent:
    """Classify the intent of a user query."""
    query_lower = query.lower()
    
    if re.search(r'\bT\d{4}', query, re.IGNORECASE):
        return QueryIntent.TECHNIQUE_SPECIFIC
    
    if detect_tactic_from_query(query):
        return QueryIntent.TACTIC_BROAD
    
    detection_keywords = ["detect", "detection", "hunt", "find", "identify", "monitor", "alert", "log"]
    mitigation_keywords = ["mitigate", "mitigation", "prevent", "block", "defend", "protect", "stop"]
    procedure_keywords = ["example", "procedure", "how do", "how does", "real-world", "attack"]
    definition_keywords = ["what is", "what are", "define", "explain", "describe"]
    comparison_keywords = ["compare", "difference", "versus", "vs", "between"]
    defense_keywords = ["defense", "d3fend", "countermeasure", "counter", "defensive"]
    
    if any(kw in query_lower for kw in detection_keywords):
        return QueryIntent.DETECTION
    if any(kw in query_lower for kw in mitigation_keywords):
        return QueryIntent.MITIGATION
    if any(kw in query_lower for kw in defense_keywords):
        return QueryIntent.DEFENSE
    if any(kw in query_lower for kw in procedure_keywords):
        return QueryIntent.PROCEDURE
    if any(kw in query_lower for kw in definition_keywords):
        return QueryIntent.DEFINITION
    if any(kw in query_lower for kw in comparison_keywords):
        return QueryIntent.COMPARISON
    
    return QueryIntent.UNKNOWN


def analyze_query(query: str) -> QueryAnalysis:
    """Perform comprehensive analysis of a user query."""
    intent = classify_query_intent(query)
    tactic_info = detect_tactic_from_query(query)
    technique_ids = detect_technique_ids_from_query(query)
    
    sections = []
    if intent == QueryIntent.DETECTION:
        sections = ["detection_strategy"]
    elif intent == QueryIntent.MITIGATION:
        sections = ["mitigation"]
    elif intent == QueryIntent.PROCEDURE:
        sections = ["procedure_example"]
    elif intent == QueryIntent.DEFINITION:
        sections = ["description", "definition"]
    
    expanded = expand_query_advanced(query, intent, tactic_info)
    
    filters = {}
    if technique_ids:
        if len(technique_ids) == 1:
            filters["technique_id"] = technique_ids[0]
        else:
            filters["technique_id"] = {"$in": technique_ids}
    
    if sections and intent in [QueryIntent.DETECTION, QueryIntent.MITIGATION]:
        if len(sections) == 1:
            filters["section"] = sections[0]
    
    confidence = 0.5
    if technique_ids:
        confidence += 0.3
    if tactic_info:
        confidence += 0.2
    if intent != QueryIntent.UNKNOWN:
        confidence += 0.1
    
    return QueryAnalysis(
        original_query=query,
        intent=intent,
        detected_tactic=tactic_info[0] if tactic_info else None,
        detected_tactic_id=tactic_info[1] if tactic_info else None,
        detected_techniques=technique_ids,
        detected_sections=sections,
        expanded_query=expanded,
        confidence=min(confidence, 1.0),
        suggested_filters=filters,
    )


def expand_query_advanced(
    query: str,
    intent: QueryIntent,
    tactic_info: Optional[Tuple[str, str]] = None,
) -> str:
    """Advanced query expansion with intent and tactic awareness."""
    if not QUERY_EXPANSION_ENABLED:
        return query
    
    query_lower = query.lower()
    expansions = []
    
    if tactic_info:
        tactic_name = tactic_info[0]
        if tactic_name in TACTIC_EXPANSIONS:
            expansions.extend(TACTIC_EXPANSIONS[tactic_name][:5])
    
    for term, synonyms in MITRE_SYNONYMS.items():
        if term in query_lower:
            expansions.extend(synonyms[:3])
    
    if intent == QueryIntent.DETECTION:
        expansions.extend(["detection_strategy", "analytic", "log source", "data component"])
    elif intent == QueryIntent.MITIGATION:
        expansions.extend(["mitigation", "remediation", "countermeasure", "defense"])
    elif intent == QueryIntent.PROCEDURE:
        expansions.extend(["procedure", "example", "threat actor", "malware", "campaign"])
    
    if expansions:
        unique_expansions = list(dict.fromkeys(expansions))[:8]
        expanded = f"{query} {' '.join(unique_expansions)}"
        return expanded
    
    return query


def expand_query(query: str) -> str:
    """Basic query expansion with MITRE-specific synonyms."""
    if not QUERY_EXPANSION_ENABLED:
        return query
    
    query_lower = query.lower()
    expansions = []
    
    for term, synonyms in MITRE_SYNONYMS.items():
        if term in query_lower:
            expansions.extend(synonyms[:2])
    
    if expansions:
        unique_expansions = list(dict.fromkeys(expansions))[:5]
        expanded = f"{query} {' '.join(unique_expansions)}"
        return expanded
    
    return query


# ---------------------------------------------------------------------------
# Dataset helpers
# ---------------------------------------------------------------------------

def normalize_dataset(dataset: str | None) -> str:
    """Normalize and validate dataset name."""
    ds = (dataset or "mitre").strip().lower()
    if ds not in ("mitre", "d3fend", "all"):
        raise ValueError(f"Unknown dataset={dataset!r}. Expected 'mitre'|'d3fend'|'all'.")
    return ds


def collection_name_for(dataset: str) -> str:
    """Get collection name for a dataset."""
    ds = normalize_dataset(dataset)
    if ds == "mitre":
        return MITRE_CHROMA_COLLECTION
    if ds == "d3fend":
        return D3FEND_CHROMA_COLLECTION
    raise ValueError("collection_name_for() does not accept dataset='all'")


def datasets_for_all() -> List[str]:
    """Get list of all datasets for merged queries."""
    return ["mitre", "d3fend"]


# ---------------------------------------------------------------------------
# Embedding backends
# ---------------------------------------------------------------------------

class LMStudioEmbeddingFunction(embedding_functions.EmbeddingFunction):
    """Embedding function using LM Studio's OpenAI-compatible API."""

    def __init__(
        self,
        base_url: str = "http://localhost:1234/v1",
        model: str = "text-embedding-bge-large-en-v1.5",
        max_retries: int = 3,
        timeout: int = 120,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.max_retries = max_retries
        self.timeout = timeout
        self._embed_url = f"{self.base_url}/embeddings"
        self._session = None

    def _get_session(self):
        if self._session is None:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            
            self._session = requests.Session()
            retry_strategy = Retry(
                total=self.max_retries,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)
        
        return self._session

    def __call__(self, input: List[str]) -> List[List[float]]:
        if not input:
            return []
        
        session = self._get_session()
        payload = {"input": input}
        if self.model:
            payload["model"] = self.model

        try:
            resp = session.post(
                self._embed_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()

            embeddings = []
            for item in sorted(data.get("data", []), key=lambda x: x.get("index", 0)):
                embeddings.append(item["embedding"])

            return embeddings

        except Exception as e:
            logger.error(f"LM Studio embedding request failed: {e}")
            raise ConnectionError(
                f"LM Studio embedding request failed: {e}\n"
                f"Make sure LM Studio is running at {self.base_url} with model '{self.model}' loaded."
            ) from e


class OllamaEmbeddingFunction(embedding_functions.EmbeddingFunction):
    """Embedding function that calls Ollama locally."""

    def __init__(self, model: str = "nomic-embed-text", base_url: str | None = None) -> None:
        self.model = model
        self.base_url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        self._session = None

    def _get_session(self):
        if self._session is None:
            import requests
            self._session = requests.Session()
        return self._session

    def __call__(self, input: List[str]) -> List[List[float]]:
        if not input:
            return []
        
        session = self._get_session()

        try:
            resp = session.post(
                f"{self.base_url}/api/embed",
                json={"model": self.model, "input": input},
                timeout=60,
            )
            if resp.status_code != 404:
                resp.raise_for_status()
                data = resp.json()
                if "embeddings" in data:
                    return data["embeddings"]
                if "embedding" in data:
                    return [data["embedding"]]
        except Exception:
            pass
        
        out: List[List[float]] = []
        for t in input:
            r = session.post(
                f"{self.base_url}/api/embeddings",
                json={"model": self.model, "prompt": t},
                timeout=60,
            )
            r.raise_for_status()
            data = r.json()
            if "embedding" in data:
                out.append(data["embedding"])
            elif "embeddings" in data and data["embeddings"]:
                out.append(data["embeddings"][0])
            else:
                raise ValueError(f"Unexpected Ollama response: {list(data.keys())}")
        return out


class HFSentenceTransformerEmbedding(embedding_functions.EmbeddingFunction):
    """Embedding function using sentence-transformers."""

    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer
        import torch

        self.model_name = model_name
        device = "mps" if torch.backends.mps.is_available() else "cpu"
        logger.info(f"Loading sentence-transformers model: {model_name} on {device}")
        self.model = SentenceTransformer(model_name, device=device)

    def __call__(self, input: List[str]) -> List[List[float]]:
        if not input:
            return []
        
        embeddings = self.model.encode(
            input,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )
        return embeddings.tolist()


def get_embedding_function() -> embedding_functions.EmbeddingFunction:
    """Get embedding function based on environment configuration."""
    backend = EMBED_BACKEND

    if backend == "lmstudio":
        logger.info(f"Using LM Studio embedding backend: url={LMSTUDIO_BASE_URL} model={LMSTUDIO_EMBED_MODEL}")
        return LMStudioEmbeddingFunction(base_url=LMSTUDIO_BASE_URL, model=LMSTUDIO_EMBED_MODEL)

    if backend == "hf":
        logger.info(f"Using HuggingFace sentence-transformers backend: {HF_EMBED_MODEL}")
        return HFSentenceTransformerEmbedding(HF_EMBED_MODEL)

    if backend == "ollama":
        logger.info(f"Using Ollama backend: model={OLLAMA_EMBED_MODEL} base_url={OLLAMA_BASE_URL}")
        return OllamaEmbeddingFunction(model=OLLAMA_EMBED_MODEL, base_url=OLLAMA_BASE_URL)

    raise ValueError(f"Unknown EMBED_BACKEND={backend!r}. Expected 'lmstudio', 'hf', or 'ollama'.")


# ---------------------------------------------------------------------------
# Reranking
# ---------------------------------------------------------------------------

_RERANKER = None


def _get_reranker():
    """Get or create cross-encoder reranker."""
    global _RERANKER

    if not RERANK_ENABLED:
        return None

    if _RERANKER is None:
        try:
            from sentence_transformers import CrossEncoder
            logger.info("Loading cross-encoder: cross-encoder/ms-marco-MiniLM-L-6-v2")
            _RERANKER = CrossEncoder(
                "cross-encoder/ms-marco-MiniLM-L-6-v2",
                max_length=512,
            )
        except ImportError:
            logger.warning("sentence-transformers not installed. Reranking disabled.")
            return None
        except Exception as e:
            logger.warning(f"Failed to load reranker: {e}")
            return None

    return _RERANKER


def rerank_results(
    query: str,
    ids: List[str],
    docs: List[str],
    metas: List[Dict[str, Any]],
    dists: List[float],
    top_k: int,
    min_score: float = MIN_RERANK_SCORE,
) -> Tuple[List[str], List[str], List[Dict[str, Any]], List[float]]:
    """Rerank results using cross-encoder."""
    reranker = _get_reranker()

    if reranker is None or len(ids) == 0:
        return ids[:top_k], docs[:top_k], metas[:top_k], dists[:top_k] if dists else []

    if len(ids) <= top_k:
        return ids, docs, metas, dists if dists else []

    pairs = [(query, doc) for doc in docs]

    try:
        scores = reranker.predict(pairs)
    except Exception as e:
        logger.warning(f"Reranking failed: {e}. Returning unranked results.")
        return ids[:top_k], docs[:top_k], metas[:top_k], dists[:top_k] if dists else []

    ranked = sorted(
        zip(ids, docs, metas, scores),
        key=lambda x: x[3],
        reverse=True
    )

    if STRICT_MODE:
        ranked = [r for r in ranked if r[3] >= min_score]

    ranked = ranked[:top_k]

    if not ranked:
        logger.warning(f"All results filtered out by min_score={min_score}. Returning top results anyway.")
        ranked = sorted(
            zip(ids, docs, metas, scores),
            key=lambda x: x[3],
            reverse=True
        )[:top_k]

    return (
        [r[0] for r in ranked],
        [r[1] for r in ranked],
        [r[2] for r in ranked],
        [float(r[3]) for r in ranked],
    )


# ---------------------------------------------------------------------------
# BM25 Hybrid Search
# ---------------------------------------------------------------------------

_BM25_INDEX = {}


def _get_bm25_index(dataset: str):
    """Get or create BM25 index for a dataset."""
    global _BM25_INDEX

    if not HYBRID_ENABLED:
        return None

    if dataset in _BM25_INDEX:
        return _BM25_INDEX[dataset]

    try:
        from rank_bm25 import BM25Okapi
    except ImportError:
        logger.warning("rank-bm25 not installed. Hybrid search disabled.")
        return None

    logger.info(f"Building BM25 index for {dataset}...")

    collection = get_collection(dataset=dataset, with_embed=False)
    result = collection.get(limit=50000, include=["documents", "metadatas"])

    corpus_ids = result.get("ids", [])
    corpus_docs = result.get("documents", [])
    corpus_metas = result.get("metadatas", [])

    if not corpus_docs:
        return None

    tokenized = [doc.lower().split() for doc in corpus_docs]
    bm25 = BM25Okapi(tokenized)

    _BM25_INDEX[dataset] = {
        "bm25": bm25,
        "ids": corpus_ids,
        "docs": corpus_docs,
        "metas": corpus_metas,
    }

    logger.info(f"BM25 index built with {len(corpus_ids)} documents")
    return _BM25_INDEX[dataset]


def hybrid_search(
    dataset: str,
    query: str,
    k: int = 5,
    semantic_weight: float = 0.6,
    bm25_weight: float = 0.4,
    where: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Hybrid search combining BM25 and semantic search with RRF."""
    bm25_index = _get_bm25_index(dataset)

    if bm25_index is None:
        return search_chunks(dataset=dataset, query=query, k=k, where=where)

    semantic_result = search_chunks(dataset=dataset, query=query, k=k * 3, where=where, use_rerank=False)
    semantic_ids = semantic_result.get("ids", [[]])[0]

    tokenized_query = query.lower().split()
    bm25_scores = bm25_index["bm25"].get_scores(tokenized_query)
    bm25_ranking = sorted(
        enumerate(bm25_scores),
        key=lambda x: x[1],
        reverse=True
    )[:k * 3]

    rrf_k = 60
    rrf_scores: Dict[str, float] = {}

    for rank, doc_id in enumerate(semantic_ids):
        rrf_scores[doc_id] = rrf_scores.get(doc_id, 0) + semantic_weight / (rrf_k + rank + 1)

    for rank, (idx, _) in enumerate(bm25_ranking):
        doc_id = bm25_index["ids"][idx]
        rrf_scores[doc_id] = rrf_scores.get(doc_id, 0) + bm25_weight / (rrf_k + rank + 1)

    sorted_ids = sorted(rrf_scores.keys(), key=lambda x: rrf_scores[x], reverse=True)[:k]
    id_to_idx = {id_: i for i, id_ in enumerate(bm25_index["ids"])}

    return {
        "ids": [sorted_ids],
        "documents": [[bm25_index["docs"][id_to_idx[id_]] for id_ in sorted_ids]],
        "metadatas": [[bm25_index["metas"][id_to_idx[id_]] for id_ in sorted_ids]],
        "distances": [[1.0 - rrf_scores[id_] for id_ in sorted_ids]],
    }


# ---------------------------------------------------------------------------
# Cached Chroma handles
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _cached_client() -> chromadb.PersistentClient:
    """Get cached Chroma client."""
    CHROMA_DB_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(CHROMA_DB_DIR))


@lru_cache(maxsize=1)
def _cached_embed_fn() -> embedding_functions.EmbeddingFunction:
    """Get cached embedding function."""
    return get_embedding_function()


@lru_cache(maxsize=16)
def get_collection(dataset: str = "mitre", with_embed: bool = True):
    """Get a Chroma collection."""
    ds = normalize_dataset(dataset)
    if ds == "all":
        raise ValueError("get_collection() does not accept dataset='all'")

    client = _cached_client()
    name = collection_name_for(ds)

    if with_embed:
        embed_fn = _cached_embed_fn()
        return client.get_or_create_collection(name=name, embedding_function=embed_fn)

    return client.get_or_create_collection(name=name)


# ---------------------------------------------------------------------------
# Filter normalization
# ---------------------------------------------------------------------------

def normalize_where(where: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Normalize filter dict for Chroma."""
    if not where:
        return None

    if len(where) == 1:
        only_key = next(iter(where.keys()))
        if isinstance(only_key, str) and only_key.startswith("$"):
            value = where[only_key]
            if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
                return value[0]
            return where
        return where

    clauses = [{k: v} for k, v in where.items()]
    return {"$and": clauses}


# ---------------------------------------------------------------------------
# Post-filter helpers
# ---------------------------------------------------------------------------

def _parse_csv_field(v: Any) -> List[str]:
    """Parse a possibly comma-separated metadata field into a list."""
    if v is None:
        return []
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [str(v).strip()] if str(v).strip() else []


def _match_any(meta: Dict[str, Any], key: str, wanted: Optional[List[str]]) -> bool:
    """Check if any wanted value exists in metadata field."""
    if not wanted:
        return True
    hay = set(_parse_csv_field(meta.get(key)))
    return any(w in hay for w in wanted)


def _match_any_substring(meta: Dict[str, Any], key: str, wanted: Optional[List[str]]) -> bool:
    """Check if any wanted value exists in metadata field (substring match)."""
    if not wanted:
        return True
    hay = _parse_csv_field(meta.get(key))
    hay_lower = [h.lower() for h in hay]
    for w in wanted:
        w_lower = w.lower()
        for h in hay_lower:
            if w_lower in h or h in w_lower:
                return True
    return False


def _filter_mitre_result(
    result: Dict[str, Any],
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
    tactic_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Apply MITRE-specific post-filters."""
    ids = result.get("ids", [[]])[0]
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    dists = result.get("distances", [[]])[0] if result.get("distances") else []

    if not ids:
        return result

    keep_ids, keep_docs, keep_metas, keep_dists = [], [], [], []

    for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
        meta = meta or {}

        if dc:
            if not _match_any(meta, "data_component_ids", dc):
                if not _match_any(meta, "analytic_data_component_ids", dc):
                    continue

        if logsource:
            matched = (
                _match_any_substring(meta, "log_source_names", logsource) or
                _match_any_substring(meta, "analytic_log_source_names", logsource)
            )
            if not matched:
                continue

        if tactic_id:
            tactic_ids = _parse_csv_field(meta.get("tactic_ids"))
            if tactic_id not in tactic_ids:
                continue

        keep_ids.append(cid)
        keep_docs.append(doc)
        keep_metas.append(meta)
        if dists and i < len(dists):
            keep_dists.append(dists[i])

    return {
        "ids": [keep_ids],
        "documents": [keep_docs],
        "metadatas": [keep_metas],
        "distances": [keep_dists] if dists else [[]],
    }


def _filter_d3fend_result(
    result: Dict[str, Any],
    attack_technique: Optional[str] = None,
) -> Dict[str, Any]:
    """Apply D3FEND-specific post-filters."""
    if not attack_technique:
        return result

    ids = result.get("ids", [[]])[0]
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    dists = result.get("distances", [[]])[0] if result.get("distances") else []

    if not ids:
        return result

    attack_technique = attack_technique.upper()
    keep_ids, keep_docs, keep_metas, keep_dists = [], [], [], []

    for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
        meta = meta or {}

        primary = (meta.get("primary_attack_technique") or "").upper()
        if primary == attack_technique:
            keep_ids.append(cid)
            keep_docs.append(doc)
            keep_metas.append(meta)
            if dists and i < len(dists):
                keep_dists.append(dists[i])
            continue

        attack_list = _parse_csv_field(meta.get("attack_techniques"))
        if attack_technique in [t.upper() for t in attack_list]:
            keep_ids.append(cid)
            keep_docs.append(doc)
            keep_metas.append(meta)
            if dists and i < len(dists):
                keep_dists.append(dists[i])

    return {
        "ids": [keep_ids],
        "documents": [keep_docs],
        "metadatas": [keep_metas],
        "distances": [keep_dists] if dists else [[]],
    }


# ---------------------------------------------------------------------------
# Core query functions
# ---------------------------------------------------------------------------

def _apply_get_limit(limit: Optional[int]) -> Optional[int]:
    """Apply limit with optional hard cap."""
    if limit is not None:
        return int(limit)
    cap = GET_HARD_CAP
    return cap if cap > 0 else None


def get_chunks(
    dataset: str,
    where: Dict[str, Any],
    limit: Optional[int] = None,
    include: Optional[List[str]] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
    attack_technique: Optional[str] = None,
    tactic_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministic fetch via collection.get(where=...)."""
    ds = normalize_dataset(dataset)
    if ds == "all":
        raise ValueError("get_chunks(dataset='all') is not supported")

    collection = get_collection(dataset=ds, with_embed=False)
    where_norm = normalize_where(where)
    lim = _apply_get_limit(limit)
    inc = include or ["documents", "metadatas"]

    out = collection.get(where=where_norm, limit=lim, include=inc)

    normalized = {
        "ids": [out.get("ids", [])],
        "documents": [out.get("documents", [])],
        "metadatas": [out.get("metadatas", [])],
        "distances": [[]],
    }

    if ds == "mitre":
        normalized = _filter_mitre_result(normalized, dc=dc, logsource=logsource, tactic_id=tactic_id)
    elif ds == "d3fend":
        normalized = _filter_d3fend_result(normalized, attack_technique=attack_technique)

    return normalized


def search_chunks(
    dataset: str,
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    include: Optional[List[str]] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
    attack_technique: Optional[str] = None,
    tactic_id: Optional[str] = None,
    use_rerank: bool = True,
    use_expansion: bool = True,
) -> Dict[str, Any]:
    """Enhanced semantic query with optional reranking and query expansion."""
    ds = normalize_dataset(dataset)
    where_norm = normalize_where(where)
    inc = include or ["documents", "metadatas", "distances"]

    if ds == "all":
        return _search_all(query=query, k=k, where=where_norm, include=inc)

    expanded_query = expand_query(query) if use_expansion else query
    collection = get_collection(dataset=ds, with_embed=True)
    prefetch = max(int(k) * 3, PREFETCH_K) if (use_rerank and RERANK_ENABLED) else max(int(k), PREFETCH_K)

    try:
        raw = collection.query(
            query_texts=[expanded_query],
            n_results=prefetch,
            include=inc,
            where=where_norm,
        )
    except Exception as e:
        logger.error(f"Chroma query failed: {e}")
        raise

    if ds == "mitre":
        filtered = _filter_mitre_result(raw, dc=dc, logsource=logsource, tactic_id=tactic_id)
    elif ds == "d3fend":
        filtered = _filter_d3fend_result(raw, attack_technique=attack_technique)
    else:
        filtered = raw

    ids = filtered.get("ids", [[]])[0]
    docs = filtered.get("documents", [[]])[0]
    metas = filtered.get("metadatas", [[]])[0]
    dists = filtered.get("distances", [[]])[0] if filtered.get("distances") else []

    if use_rerank and RERANK_ENABLED and len(ids) > k:
        ids, docs, metas, dists = rerank_results(query, ids, docs, metas, dists, k)
    else:
        ids, docs, metas, dists = ids[:k], docs[:k], metas[:k], dists[:k] if dists else []

    return {
        "ids": [ids],
        "documents": [docs],
        "metadatas": [metas],
        "distances": [dists] if dists else [[]],
    }


def search_chunks_smart(
    query: str,
    dataset: str = "mitre",
    k: int = 5,
    **kwargs,
) -> Dict[str, Any]:
    """Smart search that analyzes the query and applies appropriate strategies."""
    start_time = time.time()
    
    analysis = analyze_query(query)
    logger.info(
        f"Query analysis: intent={analysis.intent.value}, "
        f"tactic={analysis.detected_tactic}, "
        f"techniques={analysis.detected_techniques}, "
        f"confidence={analysis.confidence:.2f}"
    )
    
    ds = normalize_dataset(dataset)
    
    if ds == "d3fend" or analysis.intent == QueryIntent.DEFENSE:
        result = search_chunks(
            dataset="d3fend",
            query=analysis.expanded_query,
            k=k,
            **kwargs,
        )
    elif analysis.detected_tactic_id and ds == "mitre":
        result = search_by_tactic(
            tactic_id=analysis.detected_tactic_id,
            query=query,
            k=k,
            section=analysis.detected_sections[0] if analysis.detected_sections else None,
        )
    elif analysis.detected_techniques and ds == "mitre":
        technique_id = analysis.detected_techniques[0]
        result = search_chunks(
            dataset="mitre",
            query=analysis.expanded_query,
            k=k,
            where={"technique_id": technique_id},
            **kwargs,
        )
    else:
        result = search_chunks_enhanced(
            dataset=ds,
            query=analysis.expanded_query,
            k=k,
            **kwargs,
        )
    
    elapsed = time.time() - start_time
    logger.info(f"Search completed in {elapsed:.3f}s, returned {len(result.get('ids', [[]])[0])} results")
    
    result["_analysis"] = {
        "intent": analysis.intent.value,
        "detected_tactic": analysis.detected_tactic,
        "detected_tactic_id": analysis.detected_tactic_id,
        "detected_techniques": analysis.detected_techniques,
        "confidence": analysis.confidence,
        "elapsed_seconds": elapsed,
    }
    
    return result


def search_by_tactic(
    tactic_id: str,
    query: str = "",
    k: int = 5,
    section: Optional[str] = None,
) -> Dict[str, Any]:
    """Search for chunks related to a specific MITRE ATT&CK tactic."""
    tactic_id = tactic_id.upper()
    
    if tactic_id not in TACTIC_KEY_TECHNIQUES:
        logger.warning(f"Unknown tactic ID: {tactic_id}")
        return search_chunks(
            dataset="mitre",
            query=query or f"tactic {tactic_id}",
            k=k,
        )
    
    key_techniques = TACTIC_KEY_TECHNIQUES[tactic_id]
    logger.info(f"Searching tactic {tactic_id} with key techniques: {key_techniques}")
    
    where_filter: Dict[str, Any] = {
        "technique_id": {"$in": key_techniques}
    }
    
    tactic_name = None
    for tactic in Tactic:
        if tactic.tactic_id == tactic_id:
            tactic_name = tactic.name.lower().replace("_", " ")
            break
    
    expanded_query = query if query else tactic_name or tactic_id
    if tactic_name and tactic_name not in expanded_query.lower():
        expanded_query = f"{expanded_query} {tactic_name}"
    
    result = search_chunks(
        dataset="mitre",
        query=expanded_query,
        k=k * 3,
        where=where_filter,
        use_rerank=False,
    )
    
    if section:
        ids = result.get("ids", [[]])[0]
        docs = result.get("documents", [[]])[0]
        metas = result.get("metadatas", [[]])[0]
        dists = result.get("distances", [[]])[0] if result.get("distances") else []
        
        filtered_ids, filtered_docs, filtered_metas, filtered_dists = [], [], [], []
        
        for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
            if meta and meta.get("section") == section:
                filtered_ids.append(cid)
                filtered_docs.append(doc)
                filtered_metas.append(meta)
                if dists and i < len(dists):
                    filtered_dists.append(dists[i])
        
        result = {
            "ids": [filtered_ids],
            "documents": [filtered_docs],
            "metadatas": [filtered_metas],
            "distances": [filtered_dists] if filtered_dists else [[]],
        }
    
    ids = result.get("ids", [[]])[0]
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    dists = result.get("distances", [[]])[0] if result.get("distances") else []
    
    if RERANK_ENABLED and len(ids) > k:
        ids, docs, metas, dists = rerank_results(query or expanded_query, ids, docs, metas, dists, k)
    else:
        ids, docs, metas, dists = ids[:k], docs[:k], metas[:k], dists[:k] if dists else []
    
    return {
        "ids": [ids],
        "documents": [docs],
        "metadatas": [metas],
        "distances": [dists] if dists else [[]],
    }


def search_chunks_enhanced(
    dataset: str,
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Full enhanced search: hybrid + reranking."""
    if HYBRID_ENABLED:
        result = hybrid_search(dataset=dataset, query=query, k=k * 2, where=where)

        if RERANK_ENABLED:
            ids = result.get("ids", [[]])[0]
            docs = result.get("documents", [[]])[0]
            metas = result.get("metadatas", [[]])[0]
            dists = result.get("distances", [[]])[0]

            ids, docs, metas, dists = rerank_results(query, ids, docs, metas, dists, k)

            return {
                "ids": [ids],
                "documents": [docs],
                "metadatas": [metas],
                "distances": [dists],
            }

        return result

    return search_chunks(dataset=dataset, query=query, k=k, where=where, **kwargs)


def _search_all(
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    include: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Semantic query across all datasets, merged by best score."""
    inc = include or ["documents", "metadatas", "distances"]
    merged: List[Tuple[str, str, Dict[str, Any], float]] = []

    for ds in datasets_for_all():
        try:
            res = search_chunks(dataset=ds, query=query, k=max(k, PREFETCH_K), where=where, include=inc)
            ids = res.get("ids", [[]])[0]
            docs = res.get("documents", [[]])[0]
            metas = res.get("metadatas", [[]])[0]
            dists = res.get("distances", [[]])[0] if res.get("distances") else []

            for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
                dist = float(dists[i]) if dists and i < len(dists) else 1.0
                meta = meta or {}
                meta["dataset"] = ds
                merged.append((cid, doc, meta, dist))
        except Exception as e:
            logger.warning(f"Error searching dataset {ds}: {e}")
            continue

    if merged:
        avg_score = sum(m[3] for m in merged) / len(merged)
        if avg_score > 2:
            merged.sort(key=lambda x: x[3], reverse=True)
        else:
            merged.sort(key=lambda x: x[3])
    
    merged = merged[:k]

    return {
        "ids": [[x[0] for x in merged]],
        "documents": [[x[1] for x in merged]],
        "metadatas": [[x[2] for x in merged]],
        "distances": [[x[3] for x in merged]],
    }


# ---------------------------------------------------------------------------
# D3FEND-specific helpers
# ---------------------------------------------------------------------------

def search_d3fend_for_technique(
    technique_id: str,
    k: int = 5,
    include_summary: bool = True,
) -> Dict[str, Any]:
    """Find D3FEND defenses that counter a specific ATT&CK technique."""
    technique_id = technique_id.upper()

    results = search_chunks(
        dataset="d3fend",
        query=f"defense countermeasure for {technique_id}",
        k=k * 2,
        attack_technique=technique_id,
    )

    ids = results.get("ids", [[]])[0]

    if len(ids) >= k:
        return {
            "ids": [ids[:k]],
            "documents": [results.get("documents", [[]])[0][:k]],
            "metadatas": [results.get("metadatas", [[]])[0][:k]],
            "distances": [results.get("distances", [[]])[0][:k]] if results.get("distances") else [[]],
        }

    broader = search_chunks(
        dataset="d3fend",
        query=f"defense countermeasure mitigation for ATT&CK technique {technique_id}",
        k=k,
    )

    seen_d3fend_ids: Set[str] = set()
    merged_ids, merged_docs, merged_metas, merged_dists = [], [], [], []

    all_results = [
        (results.get("ids", [[]])[0], results.get("documents", [[]])[0],
         results.get("metadatas", [[]])[0], results.get("distances", [[]])[0] if results.get("distances") else []),
        (broader.get("ids", [[]])[0], broader.get("documents", [[]])[0],
         broader.get("metadatas", [[]])[0], broader.get("distances", [[]])[0] if broader.get("distances") else []),
    ]

    for ids, docs, metas, dists in all_results:
        for i, (cid, doc, meta) in enumerate(zip(ids, docs, metas)):
            d3fend_id = (meta or {}).get("d3fend_id", cid)
            if d3fend_id in seen_d3fend_ids:
                continue
            seen_d3fend_ids.add(d3fend_id)

            merged_ids.append(cid)
            merged_docs.append(doc)
            merged_metas.append(meta)
            merged_dists.append(dists[i] if dists and i < len(dists) else 1.0)

            if len(merged_ids) >= k:
                break
        if len(merged_ids) >= k:
            break

    return {
        "ids": [merged_ids],
        "documents": [merged_docs],
        "metadatas": [merged_metas],
        "distances": [merged_dists] if merged_dists else [[]],
    }


# ---------------------------------------------------------------------------
# Backward-compatible wrappers
# ---------------------------------------------------------------------------

def get_mitre_chunks_by_filter(
    where: Dict[str, Any],
    limit: Optional[int] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Backward-compatible MITRE get wrapper."""
    return get_chunks(dataset="mitre", where=where, limit=limit, dc=dc, logsource=logsource)


def search_mitre_chunks(
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Backward-compatible MITRE search wrapper."""
    return search_chunks(dataset="mitre", query=query, k=k, where=where, dc=dc, logsource=logsource)


def get_d3fend_chunks_by_filter(
    where: Dict[str, Any],
    limit: Optional[int] = None,
    include: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Backward-compatible D3FEND get wrapper."""
    return get_chunks(dataset="d3fend", where=where, limit=limit, include=include)


def search_d3fend_chunks(
    query: str,
    k: int = 5,
    where: Optional[Dict[str, Any]] = None,
    include: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Backward-compatible D3FEND search wrapper."""
    return search_chunks(dataset="d3fend", query=query, k=k, where=where, include=include)


# ---------------------------------------------------------------------------
# Technique detection helpers
# ---------------------------------------------------------------------------

def detect_techniques_from_query(
    query: str,
    detect_k: int = 30,
    max_candidates: int = 3,
) -> List[Tuple[str, float]]:
    """MITRE semantic technique detection."""
    collection = get_collection(dataset="mitre", with_embed=True)

    raw = collection.query(
        query_texts=[query],
        n_results=detect_k,
        include=["metadatas", "distances"],
    )

    metas = raw.get("metadatas", [[]])[0]
    dists = raw.get("distances", [[]])[0]

    if not metas:
        return []

    tech_best: Dict[str, float] = {}
    for meta, dist in zip(metas, dists):
        meta = meta or {}
        tech_id = meta.get("technique_id")
        if not tech_id:
            continue
        sim = 1.0 - float(dist)
        prev = tech_best.get(tech_id)
        if prev is None or sim > prev:
            tech_best[tech_id] = sim

    ranked = sorted(tech_best.items(), key=lambda x: x[1], reverse=True)
    return ranked[:max_candidates]


def resolve_best_technique(
    query: str,
    max_results: int = 3,
) -> Optional[Any]:
    """MITRE technique resolver (regex/name match + semantic fallback)."""
    if TECHNIQUE_RESOLVER_AVAILABLE:
        resolved = resolve_techniques_from_text(query, max_results=max_results)
        if resolved:
            return resolved[0]

    semantic_cands = detect_techniques_from_query(query, detect_k=30, max_candidates=max_results)
    if semantic_cands:
        best_tech, score = semantic_cands[0]
        if TECHNIQUE_RESOLVER_AVAILABLE and TechniqueCandidate:
            return TechniqueCandidate(id=best_tech, name="", score=float(score), source="semantic")
        return {"id": best_tech, "name": "", "score": float(score), "source": "semantic"}

    return None


def auto_search_mitre_chunks(
    query: str,
    k: int = 5,
    dc: Optional[List[str]] = None,
    logsource: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """MITRE auto search: resolve technique then filter, or global search."""
    best = resolve_best_technique(query, max_results=3)
    if best:
        tech_id = best.id if hasattr(best, 'id') else best.get('id')
        if tech_id:
            return search_mitre_chunks(query=query, k=k, where={"technique_id": tech_id}, dc=dc, logsource=logsource)
    return search_mitre_chunks(query=query, k=k, where=None, dc=dc, logsource=logsource)


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------

def pretty_print_results(result: Dict[str, Any], show_analysis: bool = True) -> None:
    """Print query results in a readable format."""
    ids = result.get("ids", [[]])[0]
    docs = result.get("documents", [[]])[0]
    metas = result.get("metadatas", [[]])[0]
    dists = result.get("distances", [[]])[0] if result.get("distances") else []

    if show_analysis and "_analysis" in result:
        analysis = result["_analysis"]
        print("\n" + "=" * 80)
        print("QUERY ANALYSIS")
        print("=" * 80)
        print(f"  Intent:      {analysis.get('intent', 'unknown')}")
        print(f"  Tactic:      {analysis.get('detected_tactic', 'none')} ({analysis.get('detected_tactic_id', '')})")
        print(f"  Techniques:  {analysis.get('detected_techniques', [])}")
        print(f"  Confidence:  {analysis.get('confidence', 0):.2f}")
        print(f"  Time:        {analysis.get('elapsed_seconds', 0):.3f}s")
        print()

    if not ids:
        print("[query] No results.")
        return

    for rank, (cid, doc, meta) in enumerate(zip(ids, docs, metas), start=1):
        dist = dists[rank - 1] if dists and rank - 1 < len(dists) else None
        meta = meta or {}

        print("=" * 80)
        print(f"[{rank}] id={cid}")

        if meta.get("dataset"):
            print(f"    dataset:       {meta['dataset']}")
        if dist is not None:
            print(f"    score/dist:    {float(dist):.4f}")

        if meta.get("technique_id"):
            tech_name = meta.get("technique_name", "")
            print(f"    technique:     {meta['technique_id']} {('- ' + tech_name) if tech_name else ''}")

        if meta.get("tactic_ids"):
            print(f"    tactics:       {meta['tactic_ids']}")

        if meta.get("d3fend_id"):
            label = meta.get("label", "")
            print(f"    d3fend:        {meta['d3fend_id']} {('- ' + label) if label else ''}")

        print(f"    section:       {meta.get('section', 'unknown')}")

        print("---- text ----")
        print((doc or "")[:1200])
        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Production-grade MITRE/D3FEND query system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "How do attackers use PowerShell?" --dataset mitre
  %(prog)s "lateral movement detection" --dataset mitre --mode smart
  %(prog)s "defenses against credential dumping" --dataset d3fend
  %(prog)s "T1059.001" --dataset mitre --section detection_strategy
        """,
    )
    parser.add_argument("query", nargs="+", help="Query text")
    parser.add_argument("-k", "--topk", type=int, default=5, help="Number of results")
    parser.add_argument("--dataset", choices=["mitre", "d3fend", "all"], default="mitre")
    parser.add_argument(
        "--mode",
        choices=["search", "get", "enhanced", "smart"],
        default="smart",
        help="Search mode: smart (recommended), search, enhanced, or get",
    )
    parser.add_argument("--tech", dest="technique_id", help="Technique filter (e.g., T1059.001)")
    parser.add_argument("--tactic", dest="tactic_id", help="Tactic filter (e.g., TA0008)")
    parser.add_argument("--section", help="Section filter (e.g., detection_strategy, mitigation)")
    parser.add_argument("--no-rerank", action="store_true", help="Disable reranking")
    parser.add_argument("--no-expand", action="store_true", help="Disable query expansion")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = parse_args(argv or sys.argv[1:])
    query_text = " ".join(args.query)

    if args.verbose:
        logging.getLogger("mitre_expert").setLevel(logging.DEBUG)

    where: Dict[str, Any] = {}
    if args.technique_id:
        where["technique_id"] = args.technique_id
    if args.section:
        where["section"] = args.section

    ds = normalize_dataset(args.dataset)

    print(f"[query] Dataset: {ds}")
    print(f"[query] Mode: {args.mode}")
    print(f"[query] Reranking: {'disabled' if args.no_rerank else 'enabled'}")
    print(f"[query] Query expansion: {'disabled' if args.no_expand else 'enabled'}")
    print(f"[query] Query: {query_text}")
    print()

    if args.mode == "get":
        result = get_chunks(dataset=ds, where=where, limit=args.topk)
    elif args.mode == "enhanced":
        result = search_chunks_enhanced(dataset=ds, query=query_text, k=args.topk, where=where or None)
    elif args.mode == "smart":
        if args.tactic_id:
            result = search_by_tactic(
                tactic_id=args.tactic_id,
                query=query_text,
                k=args.topk,
                section=args.section,
            )
        else:
            result = search_chunks_smart(
                query=query_text,
                dataset=ds,
                k=args.topk,
            )
    else:
        result = search_chunks(
            dataset=ds,
            query=query_text,
            k=args.topk,
            where=where or None,
            tactic_id=args.tactic_id,
            use_rerank=not args.no_rerank,
            use_expansion=not args.no_expand,
        )

    pretty_print_results(result)


if __name__ == "__main__":
    main()