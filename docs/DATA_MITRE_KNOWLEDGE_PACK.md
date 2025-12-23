MITRE Knowledge Pack & Chunks — Data Model v1

This document describes how the MITRE knowledge pack and RAG chunks are built and structured.

These are the core artifacts:

Input (preferred)
data/processed/mitre/techniques_full_enriched_v2.jsonl

Input (fallback)
data/raw/mitre/techniques_full.jsonl

Builder script
src/mitre_expert/knowledge_pack/build_knowledge_pack.py

Outputs (runtime source of truth)

data/processed/mitre/mitre_knowledge_pack_v1.jsonl ← normalized techniques

data/processed/mitre/mitre_chunks_v1.jsonl ← exploded chunks for RAG

Everything downstream (Chroma, resolver, Mapper, Detect, DocQA) sits on top of these files.

1. Builder: build_knowledge_pack.py

Path: src/mitre_expert/knowledge_pack/build_knowledge_pack.py

1.1 Input path selection
ENRICHED_TECHNIQUES_PATH = Path("data/processed/mitre/techniques_full_enriched_v2.jsonl")
RAW_TECHNIQUES_FALLBACK_PATH = Path("data/raw/mitre/techniques_full.jsonl")

def _pick_input_path() -> Path:
    if ENRICHED_TECHNIQUES_PATH.exists():
        return ENRICHED_TECHNIQUES_PATH
    return RAW_TECHNIQUES_FALLBACK_PATH


Prefer enriched techniques: techniques_full_enriched_v2.jsonl

If missing, use raw: techniques_full.jsonl

1.2 Supported input formats
def _load_raw_techniques(path: Path) -> Iterator[Dict[str, Any]]:
    """
    Supports:
    - {"techniques": [ {...}, {...} ]}
    - [ {...}, {...} ]
    - JSONL (one technique JSON object per line).
    """


Accepted shapes:

Single JSON object with techniques array

{
  "techniques": [
    { "..technique.." },
    { "..technique.." }
  ]
}


JSON array of techniques

[
  { "..technique.." },
  { "..technique.." }
]


JSONL: one technique per line

{"technique_id": "T1548", ...}
{"technique_id": "T1548.002", ...}
...


If full-file JSON fails or has an unexpected top-level shape, the loader falls back to JSONL parsing.

1.3 High-level build flow
def build_knowledge_pack() -> None:
    input_path = _pick_input_path()
    raw_iter = list(_load_raw_techniques(input_path))

    # 1) Normalize raw → TechniqueRecord
    technique_records: list[TechniqueRecord] = []
    for rec in raw_iter:
        try:
            t = TechniqueRecord.from_raw(rec)
            technique_records.append(t)
        except KeyError as e:
            print(f"[warn] Skipping record due to missing key: {e}")
            continue

    # 2) Write normalized techniques
    technique_dicts = (t.to_dict() for t in technique_records)
    n_techniques = _write_jsonl(KNOWLEDGE_PACK_PATH, technique_dicts)

    # 3) Explode techniques into chunks
    def chunk_dicts() -> Iterable[Dict[str, Any]]:
        for t in technique_records:
            for chunk in t.iter_chunks():
                if not chunk.text or not chunk.text.strip():
                    continue
                yield chunk.to_dict()

    n_chunks = _write_jsonl(CHUNKS_PATH, chunk_dicts())


Outputs:

KNOWLEDGE_PACK_PATH = data/processed/mitre/mitre_knowledge_pack_v1.jsonl

CHUNKS_PATH = data/processed/mitre/mitre_chunks_v1.jsonl

2. Input: Enriched technique records

File: data/processed/mitre/techniques_full_enriched_v2.jsonl
Shape: one technique JSON object per line, e.g.:

{
  "technique_id": "T1548",
  "technique_name": "Abuse Elevation Control Mechanism",
  "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions...",
  "url": "https://attack.mitre.org/techniques/T1548",
  "domain": "enterprise-attack",

  "tactics": [
    {
      "tactic_id": "TA0005",
      "tactic_name": "Defense Evasion",
      "tactic_description": "...",
      "tactic_url": "https://attack.mitre.org/tactics/TA0005"
    },
    {
      "tactic_id": "TA0004",
      "tactic_name": "Privilege Escalation",
      "tactic_description": "...",
      "tactic_url": "https://attack.mitre.org/tactics/TA0004"
    }
  ],

  "platforms": "IaaS, Identity Provider, Linux, Office Suite, Windows, macOS",
  "is_sub_technique": false,
  "sub_technique_of": null,

  "procedure_examples": [ ... ],
  "associated_mitigations": [ ... ],
  "associated_detection_strategies": [ ... ],

  "data_components": [ ... ],
  "data_component_ids": ["DC0032", "DC0088", "..."],
  "log_source_names": [
    "WinEventLog:Security",
    "fs:fsusage",
    "WinEventLog:Sysmon",
    "auditd:SYSCALL",
    "AWS:CloudTrail",
    "macos:unifiedlog",
    "azure:signinlogs"
  ]
}


Example sub-technique (T1548.002) follows the same shape plus:

"is_sub_technique": true,
"sub_technique_of": "T1548"


Key enrichments:

Full tactic objects

Rich procedure_examples (campaigns, groups, software)

Rich associated_mitigations

Rich associated_detection_strategies (with per-analytic descriptions)

Telemetry:

data_components with nested log_sources

Flattened data_component_ids

Flattened log_source_names

The builder uses this enriched structure to generate normalized techniques and then chunks.

3. Normalized techniques: mitre_knowledge_pack_v1.jsonl

TechniqueRecord.from_raw(...) normalizes a raw/enriched technique into a clean record, then to_dict() is written to JSONL.

Conceptual schema:

{
  "technique_id": "T1548",
  "technique_name": "Abuse Elevation Control Mechanism",
  "description": "Adversaries may circumvent mechanisms...",
  "url": "https://attack.mitre.org/techniques/T1548",
  "domain": "enterprise-attack",

  "tactic_ids": ["TA0005", "TA0004"],
  "tactic_names": ["Defense Evasion", "Privilege Escalation"],

  "platforms": [
    "IaaS",
    "Identity Provider",
    "Linux",
    "Office Suite",
    "Windows",
    "macOS"
  ],

  "is_sub_technique": false,
  "sub_technique_of": null,

  "procedure_examples": [ ... ],            // structured from input
  "associated_mitigations": [ ... ],        // structured from input
  "associated_detection_strategies": [ ... ],

  "data_component_ids": ["DC0032", "DC0088", "..."],
  "log_source_names": [
    "WinEventLog:Security",
    "fs:fsusage",
    "WinEventLog:Sysmon",
    "auditd:SYSCALL",
    "AWS:CloudTrail",
    "macos:unifiedlog",
    "azure:signinlogs"
  ]
}


Normalization notes:

platforms: normalized to a list (even if input is a comma-separated string).

tactic_ids / tactic_names: flattened from tactics objects.

data_components (full structure) are not kept here; instead we keep:

data_component_ids

log_source_names

File format:

data/processed/mitre/mitre_knowledge_pack_v1.jsonl

One normalized technique per line.

This file is primarily for inspection / docs; the RAG layer uses the chunk file.

4. RAG chunks: mitre_chunks_v1.jsonl

TechniqueRecord.iter_chunks() explodes a technique into multiple ChunkRecord objects.

Each chunk:

Belongs to exactly one technique.

Represents one section: description, procedure example, mitigation, or detection strategy.

Carries key metadata used by:

Chroma RAG

Technique resolver

Mapper

Detect

DocQA

4.1 ChunkRecord schema (conceptual)
{
  "chunk_id": "T1548_desc",

  "technique_id": "T1548",
  "technique_name": "Abuse Elevation Control Mechanism",

  "section": "description",  // or "procedure_example" | "mitigation" | "detection_strategy"
  "text": "Adversaries may circumvent mechanisms designed to control elevate privileges...",

  "tactic_ids": ["TA0005", "TA0004"],
  "tactic_names": ["Defense Evasion", "Privilege Escalation"],
  "platforms": ["IaaS", "Identity Provider", "Linux", "Office Suite", "Windows", "macOS"],

  "data_component_ids": ["DC0032", "DC0088", "..."],
  "log_source_names": [
    "WinEventLog:Security",
    "fs:fsusage",
    "WinEventLog:Sysmon",
    "auditd:SYSCALL",
    "AWS:CloudTrail",
    "macos:unifiedlog",
    "azure:signinlogs"
  ],

  // Optional linkouts depending on section:
  "procedure_source_id": null,
  "procedure_source_name": null,
  "procedure_source_type": null,

  "mitigation_id": null,
  "mitigation_name": null,

  "analytic_id": null,
  "analytic_name": null
}


Invariants:

Every chunk has:

technique_id

technique_name

section

text (non-empty)

Telemetry (data_component_ids, log_source_names) is copied from the parent technique.

A chunk may additionally bind to:

One mitigation (mitigation_id, mitigation_name)

One analytic (analytic_id, analytic_name)

One procedure source (procedure_source_id, procedure_source_name, procedure_source_type)

5. Chunk types
5.1 Description chunks

One per technique, from description.

Example:

{
  "chunk_id": "T1548_desc",
  "technique_id": "T1548",
  "technique_name": "Abuse Elevation Control Mechanism",
  "section": "description",
  "text": "Adversaries may circumvent mechanisms designed to control elevate privileges...",
  "tactic_ids": ["TA0005", "TA0004"],
  "tactic_names": ["Defense Evasion", "Privilege Escalation"],
  "platforms": ["IaaS", "Identity Provider", "Linux", "Office Suite", "Windows", "macOS"],
  "data_component_ids": ["DC0032", "DC0088", "..."],
  "log_source_names": ["WinEventLog:Security", "fs:fsusage", "..."],
  "procedure_source_id": null,
  "procedure_source_name": null,
  "procedure_source_type": null,
  "mitigation_id": null,
  "mitigation_name": null,
  "analytic_id": null,
  "analytic_name": null
}


chunk_id convention:
<TECH_ID>_desc

5.2 Procedure example chunks

For each entry in procedure_examples, create a chunk:

{
  "chunk_id": "T1548_proc_G1048",
  "technique_id": "T1548",
  "technique_name": "Abuse Elevation Control Mechanism",
  "section": "procedure_example",

  "text": "[UNC3886] has used vSphere Installation Bundles (VIBs)...\n\n[UNC3886] is a China-nexus cyberespionage group...",

  "procedure_source_id": "G1048",
  "procedure_source_name": "UNC3886",
  "procedure_source_type": "group",

  "mitigation_id": null,
  "mitigation_name": null,
  "analytic_id": null,
  "analytic_name": null,

  "tactic_ids": [...],
  "tactic_names": [...],
  "platforms": [...],
  "data_component_ids": [...],
  "log_source_names": [...]
}


chunk_id convention:
<TECH_ID>_proc_<SOURCE_ID>

5.3 Mitigation chunks

For each entry in associated_mitigations, create one chunk.

Pattern:

{
  "chunk_id": "T1548_mit_M1047",
  "technique_id": "T1548",
  "technique_name": "Abuse Elevation Control Mechanism",
  "section": "mitigation",

  "text": "<mapping_description>\n\n<mitigation_source_description>",

  "mitigation_id": "M1047",
  "mitigation_name": "Audit",

  "procedure_source_id": null,
  "procedure_source_name": null,
  "procedure_source_type": null,
  "analytic_id": null,
  "analytic_name": null,

  "tactic_ids": [...],
  "tactic_names": [...],
  "platforms": [...],
  "data_component_ids": [...],
  "log_source_names": [...]
}


chunk_id convention:
<TECH_ID>_mit_<MIT_ID>

This applies for all mitigations tied to a technique, e.g. for T1548: M1047, M1038, M1028, M1026, M1022, M1051, M1052, M1018, etc.

5.4 Detection strategy chunks

For each analytic inside each entry of associated_detection_strategies, create a detection chunk.

Example (T1548):

{
  "chunk_id": "T1548_det_AN0975",
  "technique_id": "T1548",
  "technique_name": "Abuse Elevation Control Mechanism",
  "section": "detection_strategy",

  "text": "Detection Strategy for Abuse Elevation Control Mechanism (T1548)\n\nCorrelate registry modifications (e.g., UAC bypass registry keys), unusual parent-child process relationships (e.g., control.exe spawning cmd.exe), and unsigned elevated process executions with non-standard tokens or elevation flags.",

  "analytic_id": "AN0975",
  "analytic_name": "Analytic 0975",

  "procedure_source_id": null,
  "procedure_source_name": null,
  "procedure_source_type": null,
  "mitigation_id": null,
  "mitigation_name": null,

  "tactic_ids": [...],
  "tactic_names": [...],
  "platforms": [...],
  "data_component_ids": [...],
  "log_source_names": [...]
}


chunk_id convention:
<TECH_ID>_det_<ANALYTIC_ID>

Example for T1548.002:

T1548.002_det_AN1094 with a similar pattern.

6. Telemetry fields: data components & log sources

Telemetry from the enriched techniques file is propagated to all chunks.

6.1 In input

For a technique record:

"data_components": [
  {
    "data_component_id": "DC0032",
    "data_component_stix_id": "x-mitre-data-component--...",
    "log_sources": [
      { "name": "WinEventLog:Security", "channel": "EventCode=4688" }
    ]
  },
  {
    "data_component_id": "DC0059",
    "data_component_stix_id": "x-mitre-data-component--...",
    "log_sources": [
      { "name": "auditd:SYSCALL", "channel": "setuid or setgid bit changes" }
    ]
  },
  ...
],
"data_component_ids": ["DC0032", "DC0088", "DC0063", "DC0059", "DC0034", "DC0021", "DC0010"],
"log_source_names": [
  "WinEventLog:Security",
  "fs:fsusage",
  "WinEventLog:Sysmon",
  "auditd:SYSCALL",
  "AWS:CloudTrail",
  "macos:unifiedlog",
  "azure:signinlogs"
]

6.2 In normalized techniques

data_component_ids: list of strings

log_source_names: list of strings

The richer data_components object is only used in the build step; the flat lists are what we use at runtime.

6.3 In chunks

Every chunk for a technique copies:

"data_component_ids": [...],
"log_source_names": [...]


This allows:

Mapper to reason about which techniques align with observed telemetry.

Detect to focus on detection_strategy chunks whose telemetry matches the environment:

intersection of available_logs (e.g., "Proxy", "Firewall", "WinEventLog:Security") with log_source_names.

later—if desired—also intersection with data_component_ids (e.g. "DC0002" for authentication logs).

7. How the chunks are used at runtime
7.1 Chroma index

data/processed/mitre/mitre_chunks_v1.jsonl feeds:

src/mitre_expert/rag/index_chroma.py

For each chunk:

document = text

metadata = sanitized subset of chunk fields:

technique_id, technique_name

section

mitigation_id, mitigation_name

analytic_id, analytic_name

tactic_ids, tactic_names

platforms

data_component_ids, log_source_names

plus internal chunk_id / source if needed

Chroma collection is then used by query_chroma.py for:

get_mitre_chunks_by_filter(...)

search_mitre_chunks(...)

detect_techniques_from_query(...)

auto_search_mitre_chunks(...)

7.2 Technique resolver

src/mitre_expert/models/technique_resolver.py:

Loads mitre_chunks_v1.jsonl.

Extracts (technique_id, technique_name) from chunk metadata.

Builds in-memory vocab:

ID regex (T####, T####.###)

normalized name substring

optional fuzzy match (rapidfuzz)

This resolver drives:

mapping decisions for /mapper and /query

best-technique selection when user asks for detection on free-text queries

7.3 MITRE specialists

MITRE-DocQA

Uses section for context selection.

For mitigation enumeration: focuses on section="mitigation" chunks and their mitigation_id / mitigation_name.

MITRE-Mapper

Uses technique/tactic metadata plus telemetry (data_component_ids, log_source_names) to produce structured mappings like:

T1110, T1110.001, T1110.003, T1110.004, T1078.002 for authentication anomalies.

MITRE-Detect

Uses section="detection_strategy" chunks.

Reads analytic_id / analytic_name for headings.

Intersects telemetry in chunks with platform + available_logs from the request to steer detection ideas.

8. Rebuilding & debugging
8.1 Rebuild knowledge pack

From repo root:

# Build normalized techniques + chunks
python -m mitre_expert.knowledge_pack.build_knowledge_pack

# Or via helper script
./scripts/run_build_mitre_knowledge_pack.sh


This regenerates:

data/processed/mitre/mitre_knowledge_pack_v1.jsonl

data/processed/mitre/mitre_chunks_v1.jsonl

Then re-index embeddings:

./scripts/run_index_mitre_chroma.sh

8.2 Quick checks

If no input file is found:

Ensure at least one of:

data/processed/mitre/techniques_full_enriched_v2.jsonl

data/raw/mitre/techniques_full.jsonl

If chunks file is tiny or empty:

Look for [warn] Skipping record due to missing key in build logs.

Ensure technique records actually have descriptions/mitigations/detections; empty text gets skipped.

To verify a technique, e.g. T1548:

grep '"technique_id": "T1548"' data/processed/mitre/mitre_chunks_v1.jsonl

You should see:

T1548_desc

T1548_proc_*

T1548_mit_*

T1548_det_*

9. Summary

The enriched techniques file is the input.

build_knowledge_pack.py:

Normalizes techniques → mitre_knowledge_pack_v1.jsonl

Explodes them into chunks → mitre_chunks_v1.jsonl

Each chunk:

Is bound to a single technique

Represents a section (description / procedure / mitigation / detection_strategy)

Carries tactics, platforms, and telemetry (data_component_ids, log_source_names)

Optionally binds to a mitigation, analytic, or procedure source

At runtime:

Chroma indexes chunks.

Technique resolver builds vocabulary from chunks.

DocQA / Mapper / Detect all operate on this unified chunk representation.

Design rule of thumb:
If you change the shape or semantics of the MITRE data, update the builder → regenerate the knowledge pack → re-index Chroma. The entire “MITRE expert layer” is downstream of this pipeline.