MITRE Assistant – Capabilities & Roadmap
1. What we have now
1.1 Core data & indexing

Source data

MITRE ATT&CK techniques (from either):

data/processed/mitre/techniques_full_enriched_v2.jsonl (preferred), or

data/raw/mitre/techniques_full.jsonl (fallback).

Each technique is normalized into a TechniqueRecord and then exploded into chunks (ChunkRecord) for RAG.

Key processed files

data/processed/mitre/mitre_knowledge_pack_v1.jsonl
→ one normalized technique per line.

data/processed/mitre/mitre_chunks_v1.jsonl
→ one RAG chunk per line (description, procedure examples, mitigations, detection strategies).

Each chunk carries metadata:

technique_id, technique_name

tactic_ids, tactic_names

platforms

Telemetry enrichment:

data_component_ids (MITRE DC####)

log_source_names (e.g. WinEventLog:Security, sysmon, azure:signinlogs)

Section/type: description, procedure_example, mitigation, detection_strategy, etc.

Embeddings & RAG

index_chroma.py:

Reads mitre_chunks_v1.jsonl

Builds a Chroma collection: mitre_chunks_v1 in data/embeddings/mitre/chroma

Embedding backend: HF sentence-transformers or Ollama (config via env).

query_chroma.py:

search_mitre_chunks(...) → semantic search with filters

get_mitre_chunks_by_filter(...) → deterministic .get() (no embeddings)

Filters by technique_id, section, telemetry (data_component_ids, log_source_names), etc.

detect_techniques_from_query(...) → semantic detection of techniques by aggregating results.

Technique resolver

technique_resolver.py:

Parses mitre_chunks_v1.jsonl to build:

_TECHNIQUES: map of technique_id → TechniqueRecord(id, name)

Resolves techniques from text using:

Regex for IDs (T#### / T####.###)

Exact name match

Fuzzy name match (rapidfuzz if available)

Used by mapper and generic auto-search.

1.2 Routing layer

src/router/router.py

Route kinds:

docqa – MITRE Doc Q&A

mapper – MITRE Mapper (text → techniques)

detect – MITRE Detect (technique → detection guidance)

mapper_detect – combined workflow (not yet fully wired end-to-end, but conceptually: map first, then detect)

Routing rules (simplified)

If query has log/mapping signals (e.g. log, logs, alert, siem, event id, ioc, ip, url, network flow) → mapper

If query has detection signals (e.g. how to detect, sigma, rule, telemetry, detection idea, use case) → detect

If both mapping & detection keywords but no explicit technique id → mapper_detect

If detection + explicit technique (T1…) → detect

Otherwise → docqa

1.3 Route: DocQA (MITRE Q&A)

Code: (prompt only shown) DOCQA_SYSTEM_PROMPT in mitre_expert/llm/prompts.py.
Implementation side (not pasted here) is a standard RAG Doc QA flow.

What it does now

Takes a natural language question about MITRE ATT&CK (techniques, tactics, software, groups, mitigations, detection strategies).

Uses only MITRE CONTEXT retrieved from Chroma.

LLM answers as a MITRE ATT&CK encyclopedia, strictly no outside knowledge.

Good questions it can answer now

“What is T1548 and how does it work?”

“Which mitigations are associated with T1059 on Windows?”

“What does MITRE say about detecting credential dumping?”

“What tactics does technique T1110 belong to?”

“What are the common procedure examples for T1059.001 (PowerShell)?”

Limitations

Only MITRE content – no knowledge of:

Your environment

Your rules

Non-MITRE blogs/vendor content

Answers stay fairly high-level (no product-specific or environment-specific details).

1.4 Route: Mapper (text → techniques)

Code: mitre_expert/llm/mitre_mapper.py + API in mitre_expert/api/routers/mitre_mapper.py.

What it does now

Input: free-text scenario / log / alert description, e.g.:

“Multiple failed logons followed by success from same IP”

“PowerShell downloading a script from the internet”

Pipeline:

resolve_techniques_from_text(...) → deterministic IDs from text (IDs + names)

detect_techniques_from_query(...) → semantic technique candidates via Chroma

Combine + apply priors:

URL/proxy hints (e.g., bias T1071 when URLs mentioned)

Auth/brute-force hints (e.g., bias T1110 when “login”, “sign-in”, “failure” in text)

Telemetry alignment if observed_log_sources / observed_data_components are provided.

Lookup metadata (tactics, telemetry) via _fetch_technique_meta/Chroma.

Output:

MapperResult:

tactics: list of tactic_ids (TA####)

techniques: list of TechniquePrediction:

id, name, confidence (0–1)

tactics

data_components, log_sources

Good questions it can answer now

“What MITRE techniques does this SIEM alert description map to?”

“Given this log line or incident description, what are the top 3 techniques?”

“Which tactics are involved in this scenario?”

“For this alert, which MITRE data components/log sources are relevant?”

Limitations

Still purely text/RAG-based:

It does not parse real log schemas.

It doesn’t know your SIEM fields or actual pipeline.

Technique mapping is probabilistic (confidence scores), not guaranteed correct.

No direct “quality” judgment yet (e.g., “this alert could also be T1078”).

1.5 Route: Detect (technique → detection guidance)

Code:

mitre_expert/llm/mitre_detect.py

API: mitre_expert/api/routers/mitre_detect.py

What it does now

Input (DetectRequest):

technique_id (required)

Optional:

platform (e.g. “Windows”)

available_logs (e.g. ["WinEventLog:Security", "sysmon"])

topk (chunks for detection context)

temperature

include_context

Steps:

Build detection context (build_detection_context):

Prefer section="detection_strategy" chunks for that technique_id.

If missing, fall back to searching description + procedures scoped to that technique.

Add telemetry hints:

Log sources: ...

Data components: ...

Call LLM with DETECT_SYSTEM_PROMPT:

Very strict: ONLY use MITRE DETECTION CONTEXT.

No invented event IDs, products, or tools.

Answer structure (in natural language):

1–2 sentence detection goal.

Log Sources section.

Detection Ideas section (2–5 high-level patterns).

If context is weak → explicitly say so.

Good questions it can answer now

“How to detect T1110 (Brute Force) given I have WinEventLog:Security and Azure Sign-In Logs?”

“What log sources and general patterns does MITRE recommend for detecting T1059.001 PowerShell?”

“Which telemetry is mentioned for detecting T1548 UAC-related privilege escalation?”

“If I only have Sysmon, what’s the MITRE-based detection story for T1055?”

Limitations

No direct connection to:

Your existing rules.

Sigma/vendor rule sets.

Actual environment baselines or historical incidents.

Output is design-level, not “copy/paste” SIEM rules.

1.6 Route: Mapper + Detect (planned flow)

Concept:

For questions like:
“Here’s an alert / log scenario, how do I detect it better using MITRE?”

Flow:

Use Mapper to infer key techniques.

For each top technique, call Detect.

Aggregate into a response:

Mapped techniques + confidence

Detection ideas/log sources per technique.

Current status:

Routing path mapper_detect is defined in router.py.

Glue logic (controller) to run Mapper then Detect and merge answers is not shown here but is straightforward to implement.

2. Roadmap – How we improve & what data we’ll add
Stage 0 – Current “MITRE-only” baseline (where we are)

Data we use:

MITRE ATT&CK techniques +:

Descriptions

Procedure examples

Mitigations

Detection strategies / analytics

Telemetry enrichment:

data_component_ids

log_source_names

What we can answer across routes:

docqa: encyclopedia-style answers about MITRE techniques/tactics/mitigations/detections.

mapper: map free-text alerts/incidents to ATT&CK techniques + tactics + telemetry hints.

detect: for a technique, summarize:

Detection goal

Log sources/telemetry mentioned

High-level detection ideas

mapper_detect (conceptually): scenario → techniques → detection ideas.

Stage 1 – Add a rule corpus (Sigma / vendor / internal rules)

Goal: move from generic “ideas” to rule-aware guidance.

New data to add:

A collection of detection rules, each with:

Rule id/name

Rule language / product (Sigma, KQL, SPL, ES DSL, etc.)

Tagged technique_id(s) and tactic_ids

Platform(s)

Log sources used

Implementation idea:

Ingest rule metadata + body as additional chunks, e.g. section=detection_strategy or analytic.

Or store in a separate Chroma collection, but still indexed by technique_id, log_source_names, etc.

Extend build_detection_context to also fetch rule chunks for the given technique.

New questions we can answer then:

“Show me example Sigma/KQL rules for detecting T1110 on Windows.”

“Which existing rules for T1059 use Sysmon vs WinEventLog:Security?”

“For T1078, what rules do we already have, and which logs do they rely on?”

Stage 2 – Add product/SIEM-specific schema & patterns

Goal: environment type-aware answers (e.g., Splunk vs Sentinel vs Elastic), still not tied to a specific company.

New data to add:

For each log source / platform / SIEM type:

Field mappings, e.g.:

Windows Security:

EventID, AccountName, LogonType, IpAddress, etc.

Azure AD:

OperationName, ResultType, UserPrincipalName, etc.

Example pattern templates, e.g.:

“Brute force = many failed logons from same IP in short time window”

Splunk SPL template

KQL template

Elastic DSL template

Implementation idea:

Store this as additional analytic chunks keyed by:

technique_id

platform

log_source_names

siem_product (custom metadata field)

Extend /detect to:

Take siem_product / query_language as an optional field.

Prefer chunks whose siem_product matches.

New questions we can answer then:

“Give me a KQL example for T1110 using Azure Sign-In Logs.”

“How would a Sentinel rule for T1548 look given common fields?”

“What SPL fields should I use in Splunk for detecting T1059.001?”

Stage 3 – Add organization-specific detection catalogue & coverage

Goal: environment-aware, coverage and gap analysis.

New data to add:

Your own organization’s detection catalogue:

All SIEM/EDR rules with:

Rule id, name

Content (query/logic)

technique_id mappings

Log sources used

Status: enabled/disabled/deprecated

Optional:

Baseline metrics (e.g., firing frequency, false positives, incidents tied to rule).

Historical incident mappings to techniques.

Implementation idea:

Store your rules (metadata + maybe bodies) in a separate internal index.

Build a service that, for a given technique_id:

Finds all your rules mapped to it.

Compares:

MITRE-recommended telemetry vs telemetry your rules actually use.

MITRE detection ideas vs your implemented logic.

Extend /detect or a new /coverage endpoint to:

Return:

Techniques with no rules.

Techniques with rules but poor telemetry overlap.

Suggestions based on MITRE + your existing patterns.

New questions we can answer then:

“For T1110, what rules do we have, and where are the gaps vs MITRE guidance?”

“Which techniques we care about (e.g. in a threat model) have no detections at all?”

“Given our current rules and logs, how strong is our coverage for T1059 on Windows?”

Stage 4 – (Optional) Add live telemetry/metrics for feedback & tuning

Goal: move to a feedback loop: not just “what should we detect?” but “how well is it working?”

New data:

Aggregated stats from your SIEM:

Rule hit counts over time.

False-positive feedback (if you capture it).

Distribution of key features (e.g., normal vs abnormal patterns).

Potential abilities:

“This brute-force detection threshold is too low based on your normal authentication volumes.”

“This rule rarely fires – consider tuning or disabling, or check if it’s obsolete.”

“New MITRE technique Txxxx was added, you have no rules yet.”

3. Summary

Now:

We have a fully working MITRE Q&A, Mapper, and Detect stack.

All reasoning is grounded in MITRE ATT&CK content + telemetry enrichment, via Chroma.

Router picks:

docqa for ATT&CK encyclopedia-style questions.

mapper for log/alert/scenario → technique mapping.

detect for technique → detection guidance.

mapper_detect for scenario → techniques → detection ideas (conceptually, glue to implement).

Near future (Stage 1–2):

Add rule corpus + SIEM-specific schemas to turn high-level guidance into rule-aware, product-specific guidance.

Next level (Stage 3–4):

Add your own detection catalogue & metrics to talk about coverage, gaps, and quality in your real environment.