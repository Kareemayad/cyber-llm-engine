# MITRE Expert Layer v1 — Architecture & Runtime Flow

This repository implements a **local MITRE ATT&CK expert** with:

- A **MITRE knowledge pack** (chunked JSONL)
- A **ChromaDB RAG index** over those chunks
- Three MITRE-aware “specialists” built on a single local LLM:
  - **MITRE-DocQA**: encyclopedia Q&A about ATT&CK
  - **MITRE-Mapper**: map alerts/log text/CTI → techniques + tactics (+ telemetry)
  - **MITRE-Detect**: generate detection ideas for a technique, given available logs/platform
- A **router** that decides which specialist(s) to run
- A **FastAPI** server exposing `/query` (smart entrypoint) + specialist endpoints

> Mental model: **one local LLM + one Chroma index + rule-based routing + structured composition**.

---

## 1) High-Level Flow (End-to-End)

### Offline build

1. Raw MITRE data (STIX/JSON/JSONL) → normalized **TechniqueRecord** objects.
2. Techniques → **chunked JSONL knowledge pack** (`mitre_chunks_v1.jsonl`).
3. Knowledge pack → **Chroma embeddings index** (`mitre_chunks_v1` collection).

### Runtime

1. Client calls `/query` with natural language text (alert/log/CTI/question).
2. Router decides route: `docqa | mapper | detect | mapper_detect`.
3. Selected module(s) run:
   - deterministic resolution (regex / metadata lookups)
   - semantic search over Chroma
   - LLM answer generation with strict MITRE-focused prompts
4. AnswerComposer merges into a single response object:

```json
{
  "question": "...",
  "summary": "...",
  "tactics": ["TA0005", "TA0004"],
  "techniques": [
    {
      "id": "T1548",
      "name": "Abuse Elevation Control Mechanism",
      "confidence": 0.97,
      "tactics": ["TA0004", "TA0005"],
      "data_components": ["DC0032", "DC0088", "..."],
      "log_sources": ["WinEventLog:Security", "auditd:SYSCALL", "..."]
    }
  ],
  "sections": {
    "mapping": { ... },
    "docqa": { "answer": "..." },
    "detection": { "answer": "..." }
  },
  "route_kind": "mapper_detect",
  "route_reasons": ["contains log-like terms", "mentions detection"]
}
2) Repository Layout (What Matters)
text
Copy code
data/
  raw/mitre/                 # Raw MITRE exports (STIX/JSON/JSONL)
  processed/mitre/
    mitre_knowledge_pack_v1.jsonl  # Normalized techniques
    mitre_chunks_v1.jsonl          # Chunked RAG source (central runtime input)
  embeddings/mitre/chroma/  # Persistent ChromaDB index

src/
  mitre_expert/
    api/                    # FastAPI endpoints
    knowledge_pack/         # Build techniques + chunks
    llm/                    # DocQA, Mapper, Detect, AnswerComposer, local_llm
    models/                 # TechniqueRecord, ChunkRecord, technique_resolver, enums
    rag/                    # Chroma indexing/query helpers
    config.py               # Paths/env config

  router/
    router.py               # Rule-based router for /query

scripts/
  run_build_mitre_knowledge_pack.sh
  run_index_mitre_chroma.sh
  run_mitre_docqa_api.sh
Single source of truth: data/processed/mitre/mitre_chunks_v1.jsonl powers:

Chroma RAG index

Technique resolver vocabulary

Telemetry-aware scoring (Mapper + Detect + DocQA context)

3) Data Pipeline — How MITRE Knowledge Is Prepared
3.1 Raw Inputs
Located in data/raw/mitre/:

Official MITRE ATT&CK STIX/JSON (e.g. enterprise-attack.json)

Extended technique dumps (e.g. techniques_full.jsonl)

Enriched telemetry versions (e.g. techniques_full_enriched_v2.jsonl)

Raw files are never queried at runtime. They are transformed into a normalized knowledge pack + chunked JSONL.

3.2 Normalized Techniques
File: src/mitre_expert/knowledge_pack/build_knowledge_pack.py
Core types: TechniqueRecord, ChunkRecord (src/mitre_expert/models/technique.py).

Flow:

_pick_input_path() prefers enriched techniques file:

data/processed/mitre/techniques_full_enriched_v2.jsonl

falls back to data/raw/mitre/techniques_full.jsonl

_load_raw_techniques() supports:

{"techniques": [ {...}, {...} ]}

[ {...}, {...} ]

JSONL one technique per line

TechniqueRecord.from_raw(rec) normalizes each record:

technique_id, technique_name, domain, url

tactic_ids, tactic_names (flattened from nested tactics)

platforms (normalized strings)

telemetry enrichment:

data_component_ids: List[str]

log_source_names: List[str]

nested content for chunking:

procedure_examples

associated_mitigations

associated_detection_strategies

Output (normalized techniques) →
data/processed/mitre/mitre_knowledge_pack_v1.jsonl

3.3 Chunked Knowledge Pack (RAG Source)
Still in build_knowledge_pack.py, TechniqueRecord.iter_chunks() explodes each technique into multiple ChunkRecords:

One description chunk (technique-level summary)

One procedure_example chunk per procedure

One mitigation chunk per associated mitigation

One detection_strategy chunk per analytic

Each ChunkRecord includes:

chunk_id (e.g., T1548_desc, T1548_mit_M1052, T1548_det_AN0975)

technique_id, technique_name

section:

description

procedure_example

mitigation

detection_strategy

text (body)

Tactics / platforms:

tactic_ids, tactic_names

platforms

Telemetry (copied from technique):

data_component_ids

log_source_names

Optional analytics/mitigation metadata:

procedure_source_*

mitigation_id, mitigation_name

analytic_id, analytic_name

Chunks are written as JSONL:

data/processed/mitre/mitre_chunks_v1.jsonl ← central runtime file

4) RAG Index — ChromaDB + Embeddings
4.1 Indexing
File: src/mitre_expert/rag/index_chroma.py

Input: data/processed/mitre/mitre_chunks_v1.jsonl

Output: Chroma persistent DB under data/embeddings/mitre/chroma/

collection: "mitre_chunks_v1"

Steps:

_load_chunks(CHUNKS_PATH) streams JSONL records.

For each record:

Ensure a unique ID:

rec["id"] or rec["chunk_id"] or "chunk_{idx}"

duplicate IDs get ::dup::N suffix

Require non-empty text.

_build_metadata_from_record(rec) flattens metadata:

Core keys: technique_id, technique_name, section, chunk_type, type

Tactics / platforms

Telemetry: data_component_ids, log_source_names

Mitigation & analytic IDs/names

_sanitize_metadata(meta) makes values Chroma-safe:

Drop None

list/tuple/set → comma-separated string, dropping None

Convert other types to str

Embedding backend (MITRE_EMBED_BACKEND env):

"hf": sentence-transformers/all-MiniLM-L6-v2 by default

"ollama": local Ollama embeddings (e.g. nomic-embed-text)

Insert embeddings in batches (BATCH_SIZE=64).

Result: each chunk has:

document = chunk text

metadata = flattened fields

embedding = vector for semantic search

4.2 Query Helpers
File: src/mitre_expert/rag/query_chroma.py

Key design points:

Cached Chroma client, embedding function, and collections

Distinguishes:

With embed collection (for .query())

No-embed collection (for .get() deterministic filter fetches)

Normalizes Chroma filters for newer versions (single top-level operator)

Helpers:

normalize_where(where: dict | None) -> dict | None

Converts {"a":1,"b":2} → {"$and":[{"a":1},{"b":2}]}

Leaves already operator-based filters ({"$and":[...]}) as-is.

get_mitre_chunks_by_filter(where, limit=None, dc=None, logsource=None)

Uses no-embed collection + .get() with metadata filter.

Applies post-filters:

dc → membership in data_component_ids

logsource → membership in log_source_names

Returns normalized structure: ids/documents/metadatas/distances.

search_mitre_chunks(query, k=5, where=None, dc=None, logsource=None)

Uses embedded collection + .query().

Prefetches more than k (configurable via MITRE_PREFETCH_K) to allow post-filters.

Applies dc/logsource post-filter, then trims to k.

detect_techniques_from_query(query, detect_k=30, max_candidates=3)

Global semantic search for detection of likely techniques.

Aggregates similarity per technique_id (max similarity) to avoid bias toward chunk-rich techniques.

resolve_best_technique(query, max_results=3)

Calls deterministic resolver (resolve_techniques_from_text) first.

If nothing, falls back to semantic detection above.

Returns TechniqueCandidate or None.

auto_search_mitre_chunks(query, k=5, dc=None, logsource=None)

For DocQA:

If technique detected → semantic search constrained to that technique_id.

Else → global semantic search.

5) Technique Resolver — Deterministic Technique Detection
File: src/mitre_expert/models/technique_resolver.py

Purpose: identify technique IDs in text without using the LLM.

At startup (or first use):

Scan mitre_chunks_v1.jsonl.

Build vocabulary:

technique_id → TechniqueInfo(id, name, normalized_name)

name index for normalized technique names

Resolution (resolve_techniques_from_text(text, max_results=5)):

ID regex:

Find T#### and T####.### patterns.

Score = 1.0, source = "id_regex".

Exact name match:

If normalized_name appears as substring in normalized text.

Score ≈ 0.95, source = "name_exact".

Fuzzy name match (optional, if rapidfuzz installed):

partial_ratio(name, text) ≥ threshold.

Score scaled into [0,1], source = "name_fuzzy".

Deduplicate by technique_id, keep highest score/source.

Return TechniqueCandidate list sorted by score, truncated to max_results.

This resolver feeds:

resolve_best_technique() in RAG.

map_text_to_techniques() in MITRE-Mapper.

Router /query heuristics (via resolver when needed).

6) Local LLM Wrapper
File: src/mitre_expert/llm/local_llm.py

Model:

Default: local HF model at
src/mitre_expert/models/llama3.1-8b-instruct

Path override: MITRE_DOCQA_MODEL_PATH

Device / dtype:

MPS (Apple Silicon):

DEVICE=mps, DTYPE=float32 (stability for long prompts)

CUDA:

DTYPE=bfloat16 if supported, else float16

CPU:

DTYPE=float32

Config env:

MITRE_LLM_MAX_CONTEXT (optional global context cap)

MITRE_LLM_MAX_NEW_TOKENS (optional global max generation length)

generate_answer(system_prompt, user_content, ...):

Load tokenizer/model once (lazy, cached).

Build chat messages: [{"role":"system"...}, {"role":"user"...}].

Use tokenizer.apply_chat_template(...) when available.

Tokenize without truncation; manually enforce context window:

Use model’s max_position_embeddings (or env override).

Left-truncate prompt if needed (keep latest tokens).

Generation:

If temperature is None → greedy (do_sample=False).

If temperature is not None → sampling with top_p + repetition_penalty.

Decode only newly generated tokens.

DocQA/Detect treat temperature=None as true deterministic mode.
API maps temperature=0.0 from JSON payloads → None.

7) Specialist Modules
7.1 MITRE-DocQA (Encyclopedic Answers)
File: src/mitre_expert/llm/mitre_docqa.py

Goal: answer MITRE ATT&CK questions (techniques, mitigations, tactics, etc.) using only MITRE chunks.

Core pieces:

DOCQA_SYSTEM_PROMPT (in llm/prompts.py):

Enforces:

Only use MITRE CONTEXT.

No invented tools/mitigations/IDs.

Explicitly say “not specified” if context lacks details.

Context building
build_mitre_context(question: str, topk: int = 8) -> str:

Detect whether question is a mitigation enumeration:

Looks for phrases like:

“which mitigations…”

“list mitigations…”

“mitigations for T####…”

Uses technique ID regex.

If enumeration mode:

best = resolve_best_technique(question)

technique_id = best.id (if present)

Fetch 1 description chunk via:

python
Copy code
get_mitre_chunks_by_filter(
    where={"technique_id": technique_id, "section": "description"},
    limit=1,
)
Fetch ALL mitigation chunks:

python
Copy code
get_mitre_chunks_by_filter(
    where={"technique_id": technique_id, "section": "mitigation"},
    limit=None,
)
Sort mitigations by M#### (numeric).

Emit structured blocks:

text
Copy code
[T1548 - Abuse Elevation Control Mechanism | description]
<desc text>

T1548 | mitigation M1018 - User Account Management
<M1018 text>

...
Else (default semantic mode):

result = auto_search_mitre_chunks(question, k=topk)

Emit per-chunk headers based on section (mitigation, description, detection_strategy, etc.).

Include mitigation headers like:

text
Copy code
T1548 | mitigation M1052 - User Account Control
<text>
Answer generation
answer_mitre_docqa(question, topk, temperature, context=None) -> str:

If context not given, calls build_mitre_context.

Detects:

whether the question wants mitigations

whether it specifically is mitigation enumeration.

If mitigations are requested:

Use task block that forces:

text
Copy code
- [M####] Mitigation_Name: 1–3 sentence description
Only list mitigations present in context.

No invented IDs/names.

If mitigations are not requested:

Simple explanatory answer from context, no extra “Mitigations” section.

Backstop for enumeration:

Extract all mitigation IDs from context and answer.

For any missing IDs, append:

text
Copy code
**Mitigations (additional from context)**
- [M10xx] (present in context)
Metadata extraction
extract_meta_from_context(context: str) -> Dict[str, List[str]]:

Pulls:

Technique IDs seen in context.

For each, fetches one chunk to read tactic_ids and platforms.

Mitigation IDs seen in context.

Returns:

json
Copy code
{
  "techniques": ["T1548", "T1548.002"],
  "tactics": ["TA0004", "TA0005"],
  "platforms": ["Windows", "Linux", ...],
  "mitigations": ["M1052", "M1018", ...]
}
Used by /docqa API.

7.2 MITRE-Mapper (Text/Alert → Techniques + Telemetry)
File: src/mitre_expert/llm/mitre_mapper.py

Goal: map log lines, alerts, CTI snippets → MITRE techniques + tactics + telemetry hints. No LLM involved; fully deterministic + semantic.

Types:

TechniquePrediction:

id, name

confidence (0–1, normalized per query)

tactics: List[str]

data_components: List[str]

log_sources: List[str]

MapperResult:

text (input text)

tactics: List[str] (deduped across predictions)

techniques: List[TechniquePrediction]

Key helpers:

_fetch_technique_meta(technique_id) (cached):

Uses get_mitre_chunks_by_filter(where={"technique_id": tid}, limit=1)

Reads:

technique_name

tactic_ids

data_component_ids

log_source_names

CSV fields are parsed into lists.

_combine_scores(resolver_cands, semantic_cands):

Start from resolver scores [0,1].

Add semantic “booster” (normalized semantic scores × weight).

_apply_priors(text, scores, observed_log_sources, observed_data_components):

Lightweight priors:

URL/proxy-ish text boosts network techniques (e.g. T1071).

Auth/password-ish text boosts T1110, etc.

Telemetry alignment:

If observed_log_sources / observed_data_components passed:

Techniques whose telemetry overlaps get a boost.

Techniques with zero overlap get a small penalty.

Main:

map_text_to_techniques(text, max_techniques=5, observed_log_sources=None, observed_data_components=None) -> MapperResult:

resolver_cands = resolve_techniques_from_text(...)

semantic_cands = detect_techniques_from_query(...)

raw_scores = _combine_scores(...)

raw_scores = _apply_priors(...)

Sort by score, keep top N, normalize so best = 1.0.

For each technique:

Use _fetch_technique_meta to populate:

name

tactic IDs

telemetry (data_components, log_sources).

Deduplicate tactics across all predictions.

mapper_result_to_dict(result) makes this JSON-serializable.

7.3 MITRE-Detect (Technique → Detection Ideas)
File: src/mitre_expert/llm/mitre_detect.py

Goal: given a technique ID (and optionally platform + available logs), generate detection guidance based on MITRE detection_strategy chunks.

Detection context
build_detection_context(technique_id, topk=8, available_logs=None) -> str:

Normalize technique_id to upper-case.

Normalize available_logs to a list of strings (or None).

Try dedicated detection_strategy chunks:

python
Copy code
det = get_mitre_chunks_by_filter(
    where={"technique_id": technique_id, "section": "detection_strategy"},
    limit=None,
    logsource=available_logs,  # optional telemetry-aware filter
)
For each detection chunk:

Build header:

text
Copy code
T1548 - Abuse Elevation Control Mechanism | detection_strategy [AN0975] - Analytic 0975
Append doc text.

Extract telemetry from metadata:

log_source_names

data_component_ids

Append a Telemetry: block:

text
Copy code
Telemetry:
- Log sources: WinEventLog:Security, WinEventLog:Sysmon, ...
- Data components: DC0032, DC0088, ...
If no detection_strategy chunks exist:

Fallback:

python
Copy code
result = search_mitre_chunks(
    query=f"detection or logging for {technique_id}",
    k=topk,
    where={"technique_id": technique_id},
    logsource=available_logs,
)
Emit generic headers [Txxxx - name | section] + text + telemetry hints (if present).

If still nothing:

Add "No detection-specific content found...".

Answer generation
answer_mitre_detect(technique_id, platform=None, available_logs=None, ...) -> str:

Normalizes technique_id to upper case.

If no context provided, builds one with build_detection_context().

Builds an ENVIRONMENT block:

text
Copy code
- platform: Windows
- available_logs: WinEventLog:Security, WinEventLog:Sysmon
User instructions:

Restate detection goal.

Log Sources section based on context.

Detection Ideas (2–5) based only on context.

Call out if context is weak.

Prefer ideas that align with ENVIRONMENT; mention when context uses telemetry not available in ENVIRONMENT.

Uses DETECT_SYSTEM_PROMPT + generate_answer.

API maps temperature=0.0 → None (greedy).

7.4 Answer Composer (Merge Results)
File: src/mitre_expert/llm/answer_composer.py

compose_answer(question, mapper_json=None, detect_answer=None, docqa_answer=None, primary_technique_id=None) -> dict:

Build raw sections:

python
Copy code
sections = {}
if mapper_json: sections["mapping"] = mapper_json
if docqa_answer: sections["docqa"] = {"answer": docqa_answer}
if detect_answer: sections["detection"] = {"answer": detect_answer}
Techniques:

Start from mapper_json["techniques"] if present:

Normalize IDs to upper-case.

Deduplicate by ID, keep highest confidence and best name.

If still no techniques but primary_technique_id exists:

Add single technique with confidence 1.0.

Tactics:

If mapper provided tactics:

Deduplicate and preserve order.

Summary:

mapper + detect:

“The query appears related to MITRE techniques: ... Detection guidance is also provided...”

mapper only:

“The query appears related to MITRE techniques: ...”

detect only:

“Detection guidance for technique Txxxx.”

docqa only:

“Answer based on MITRE-DocQA.”

None:

“No specific MITRE techniques or detections could be identified.”

Return dict suitable for API responses.

8) API Endpoints & Flows
8.1 /docqa
File: src/mitre_expert/api/routers/mitre_docqa.py

Request:

json
Copy code
{
  "question": "What is T1548? Which mitigations apply?",
  "topk": 8,
  "temperature": 0.2,
  "include_context": false
}
Flow:

ctx = build_mitre_context(question, topk).

temp_for_llm = None if temperature == 0.0, else payload.temperature.

answer = answer_mitre_docqa(question, topk, temperature=temp_for_llm, context=ctx).

meta_raw = extract_meta_from_context(ctx) → DocQAMeta.

Response:

json
Copy code
{
  "question": "...",
  "answer": "...",
  "context": "..."   // only if include_context=true
  "meta": {
    "techniques": ["T1548", "T1548.002"],
    "tactics": ["TA0004", "TA0005"],
    "platforms": ["Windows", "Linux", "..."],
    "mitigations": ["M1018", "M1022", "..."]
  }
}
8.2 /mapper
File: src/mitre_expert/api/routers/mitre_mapper.py

Request:

json
Copy code
{
  "text": "Repeated logon failures followed by a successful admin logon from same IP...",
  "max_techniques": 5,
  "observed_log_sources": ["WinEventLog:Security"],
  "observed_data_components": ["DC0032"]
}
Flow:

result = map_text_to_techniques(...) (with telemetry priors).

data = mapper_result_to_dict(result).

Response (simplified):

json
Copy code
{
  "tactics": ["TA0006", "TA0004"],
  "techniques": [
    {
      "id": "T1110",
      "name": "Brute Force",
      "confidence": 0.97,
      "tactics": ["TA0006"],
      "data_components": ["DC0032", "..."],
      "log_sources": ["WinEventLog:Security", "..."]
    },
    ...
  ]
}
8.3 /detect
File: src/mitre_expert/api/routers/mitre_detect.py

Request:

json
Copy code
{
  "technique_id": "T1548",
  "platform": "Windows",
  "available_logs": ["WinEventLog:Security", "WinEventLog:Sysmon"],
  "topk": 8,
  "temperature": 0.2,
  "include_context": false
}
Flow:

ctx = build_detection_context(technique_id, topk, available_logs).

Map temperature=0.0 → None (greedy).

answer = answer_mitre_detect(technique_id, platform, available_logs, topk, temperature=temp_for_llm, context=ctx).

Response:

json
Copy code
{
  "technique_id": "T1548",
  "answer": "...",
  "context": "..."   // only if include_context=true
}
8.4 /query (Smart Router Entry)
File: src/router/router.py (conceptual)

Request (simplified):

json
Copy code
{
  "query": "How do I detect abuse of UAC on Windows using Security and Sysmon logs?",
  "max_techniques": 5,
  "technique_id": null,
  "platform": "Windows",
  "available_logs": ["WinEventLog:Security", "WinEventLog:Sysmon"],
  "include_raw_sections": true
}
Routing:

route_query(query) uses heuristics:

mapping-like terms:

"log ", "logs ", "alert", "siem", "event id", "ioc", "hash", "ip ", "url ", "connection", "network flow"

detect-like terms:

"how to detect", "detection idea", "use case", "log source", "telemetry", "sigma"

technique IDs:

T####, T####.### matches

Routing rules (conceptual):

detect + technique ID → kind = "detect"

mapping + detect → kind = "mapper_detect"

mapping only → kind = "mapper"

detect only → kind = "detect"

otherwise → kind = "docqa"

Execution:

Initialize:

mapper_json = None

docqa_answer = None

detect_answer = None

top_technique_id = payload.technique_id (if provided)

If kind in ("mapper", "mapper_detect"):

Run mapper with telemetry:

python
Copy code
mapper_result = map_text_to_techniques(
    query,
    max_techniques=payload.max_techniques,
    observed_log_sources=payload.available_logs,
    observed_data_components=None  # or from request
)
mapper_json = mapper_result_to_dict(mapper_result)
If top_technique_id is still None and mapper produced techniques:

Set top_technique_id from best candidate.

If kind == "detect" and no technique_id yet:

best = resolve_best_technique(query)

If found, set top_technique_id = best.id.

If kind in ("detect", "mapper_detect") and top_technique_id:

Run Detect:

python
Copy code
detect_answer = answer_mitre_detect(
    technique_id=top_technique_id,
    platform=payload.platform,
    available_logs=payload.available_logs,
    ...
)
DocQA enrichment:

If kind == "docqa":

docqa_answer = answer_mitre_docqa(question=query, ...)

If kind in ("mapper_detect", "detect"):

If top_technique_id:

Explanatory DocQA:

python
Copy code
docqa_answer = answer_mitre_docqa(
    question=f"Explain {top_technique_id} in simple language.",
    ...
)
(Or use original question if desired.)

If kind == "mapper" and no detect_answer:

Optionally call DocQA with top technique.

Compose answer:

python
Copy code
composed = compose_answer(
    question=query,
    mapper_json=mapper_json,
    detect_answer=detect_answer,
    docqa_answer=docqa_answer,
    primary_technique_id=top_technique_id,
)
Include or drop raw sections depending on include_raw_sections.

Response:

json
Copy code
{
  "question": composed["question"],
  "summary": composed["summary"],
  "tactics": composed["tactics"],
  "techniques": composed["techniques"],
  "sections": composed["sections"],     // or null
  "route_kind": decision.kind,
  "route_reasons": decision.reasons
}
9) Developer Onboarding (Short, Practical)
This is a compressed view; the full architecture is above.

9.1 One-time build
Build knowledge pack

bash
Copy code
./scripts/run_build_mitre_knowledge_pack.sh
Input: data/raw/mitre/*

Output: data/processed/mitre/mitre_chunks_v1.jsonl

Index into Chroma

bash
Copy code
./scripts/run_index_mitre_chroma.sh
Reads: mitre_chunks_v1.jsonl

Writes: data/embeddings/mitre/chroma/

9.2 Run the API
bash
Copy code
./scripts/run_mitre_docqa_api.sh
FastAPI exposes:

/query — smart router entrypoint (recommended)

/docqa — direct MITRE-DocQA

/mapper — direct MITRE-Mapper (no LLM)

/detect — direct MITRE-Detect

9.3 Runtime Mental Model
/query → route_query(...) decides:

docqa (encyclopedia Q&A)

mapper (mapping only)

detect (detection only)

mapper_detect (mapping + detection)

Each specialist uses:

The same Chroma index (mitre_chunks_v1)

The same MITRE chunk file for resolver/vocab

The same local LLM (generate_answer)

9.4 Common Debugging
Route confusion?

Check route_kind + route_reasons in /query response.

Empty technique names?

Ensure mitre_chunks_v1.jsonl has technique_name populated.

Check _fetch_technique_meta and Chroma metadata.

Mitigation enumeration off?

Confirm question triggers _is_mitigation_enumeration_question.

Inspect build_mitre_context() output (include_context=true).

Weird mapping?

Inspect resolver_cands vs semantic_cands.

Telemetry priors use observed_log_sources / observed_data_components;
adjust or disable if they over-bias.

