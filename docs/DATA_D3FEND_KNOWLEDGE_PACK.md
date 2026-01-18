Cyber LLM Engine – D3FEND Knowledge Pack
Defensive Knowledge Data Architecture (V1)
1. Purpose of This Document

This document explains what the D3FEND Knowledge Pack is, why it exists, how it is structured, and how it is used inside the Cyber LLM Engine.

It is written so that:

A SOC analyst, security engineer, or developer

With no prior knowledge of D3FEND

Can understand how defensive knowledge is represented, retrieved, and safely used by LLMs

This document focuses only on data, not API routing or LLM prompting.

2. What Is MITRE D3FEND?
2.1 D3FEND in One Sentence

MITRE D3FEND is a knowledge base of defensive countermeasures, describing how defenders can detect, prevent, or mitigate adversary behaviors.

If ATT&CK answers:

“What attackers do”

D3FEND answers:

“What defenders can do about it”

2.2 Why D3FEND Is Different from ATT&CK
MITRE ATT&CK	MITRE D3FEND
Offensive behaviors	Defensive techniques
Techniques & tactics	Countermeasures & artifacts
Attacker-centric	Defender-centric
Detection & mitigation	Prevention, detection, hardening

D3FEND is not a list of tools or products.
It is a conceptual, vendor-neutral defensive ontology.

3. Why a D3FEND Knowledge Pack Is Needed
3.1 Problems with Raw D3FEND Data

Raw D3FEND data:

Is graph-oriented (RDF-like)

Is not optimized for LLMs

Has inconsistent naming across sources

Is not chunked for semantic retrieval

Cannot be safely reasoned over without preprocessing

LLMs cannot consume raw D3FEND directly without hallucination risk.

3.2 Design Goals of the D3FEND Knowledge Pack

The D3FEND Knowledge Pack exists to ensure:

LLM-safe defensive reasoning

Strict grounding in provided context

Small, self-contained defensive chunks

Traceable D3FEND IDs and names

Future compatibility with ATT&CK mappings

4. High-Level Architecture

The D3FEND Knowledge Pack follows the same two-layer design philosophy as MITRE ATT&CK:

Raw D3FEND Sources
        ↓
Normalized Defensive Records
        ↓
RAG-Optimized Chunks
        ↓
Chroma Vector Store


The LLM never sees raw D3FEND data.

5. D3FEND Knowledge Pack Files (V1)

In version 1, the D3FEND pipeline produces:

data/processed/d3fend/
└── d3fend_chunks_v1.jsonl


⚠️ Important difference vs MITRE ATT&CK
There is no “full defensive record” file yet (like mitre_knowledge_pack_v1.jsonl).

D3FEND V1 is chunk-only by design.

6. d3fend_chunks_v1.jsonl
6.1 What This File Is

This file contains one JSON object per defensive knowledge chunk.

Each chunk represents:

One D3FEND defensive concept

Or a related article, definition, or relationship

This file is:

Embedded into Chroma

Queried by the D3FEND DocQA pipeline

Used only via retrieval-augmented generation

6.2 What This File Is NOT

It is:

❌ Not a full D3FEND ontology

❌ Not a reasoning engine

❌ Not a rule system

❌ Not a detection engine

It is defensive reference knowledge, not automation logic.

7. D3FEND Chunk Types

Each chunk is labeled with a section type, defined in:

src/mitre_expert/models/enums.py

7.1 Supported Section Types (V1)
Section Type	Meaning
d3fend_definition	Core definition of a defensive technique
d3fend_kb_article	Explanatory or guidance text
d3fend_relations	Relationships between defensive concepts
d3fend_references	External references or citations

These labels allow:

Controlled retrieval

Safe LLM prompting

Future filtering (e.g., “definitions only”)

8. D3FEND ChunkRecord Structure

Each line in d3fend_chunks_v1.jsonl represents a D3FEND ChunkRecord.

Conceptually:

D3FEND Chunk
├── chunk_id
├── section
├── text
├── d3fend_id (optional)
├── d3fend_name (optional)
├── relationships (optional)
├── references (optional)
└── source


Not all fields are present in all chunks.

9. Chunk ID Strategy

Chunk IDs are:

Deterministic

Human-readable

Traceable to source material

Example formats:

D3-DEF-001
D3-KB-LOGGING-02
D3-REL-TA0003


This allows:

Debugging

Stable references

Safe cache reuse

10. Why D3FEND Is Chunk-Only in V1

Unlike ATT&CK:

D3FEND is not technique-centric

It is concept-centric and relational

Creating a single “D3FENDRecord” would:

Lose graph relationships

Artificially flatten the ontology

Provide little benefit for DocQA

Therefore:

V1 treats D3FEND as a retrieval-only defensive knowledge base

11. How D3FEND Knowledge Is Used at Runtime
11.1 D3FEND DocQA Flow

User asks a defensive question

Semantic search retrieves top-k D3FEND chunks

Chunks are formatted into a D3FEND CONTEXT

LLM answers using only retrieved context

The LLM is explicitly forbidden from:

Inventing controls

Naming products

Adding steps not in context

11.2 Example Questions

“What defensive techniques help detect credential misuse?”

“What does D3FEND say about log integrity?”

“Which defensive artifacts support authentication monitoring?”

12. Safety & Anti-Hallucination Design

D3FEND responses are kept safe by:

Chunk-level retrieval

Section labeling

Strict prompt rules

No cross-dataset blending (yet)

No ATT&CK inference unless explicitly retrieved

If the answer is not in the retrieved context:

The system must say it is not specified

13. Relationship to MITRE ATT&CK (Current State)

In V1:

ATT&CK and D3FEND are logically separated

No automatic ATT&CK ↔ D3FEND mapping exists

User must query them independently

This is intentional, to avoid false correlations.

14. What Is Missing in D3FEND V1
14.1 No Canonical Defensive Record File

There is no equivalent of:

d3fend_knowledge_pack_v1.jsonl


This limits:

Deterministic lookups

Analytics

Graph traversal

14.2 No Explicit ATT&CK Mapping

While D3FEND concepts often relate to ATT&CK:

Those mappings are not yet materialized

No automated defensive recommendations exist

14.3 No Telemetry Metadata

Unlike MITRE ATT&CK:

D3FEND chunks do not include log sources

No data components are attached

This prevents detection-aware defensive advice.

14.4 No Confidence or Maturity Indicators

D3FEND techniques do not yet include:

Effectiveness

Deployment complexity

SOC maturity level

15. Planned D3FEND V2 Enhancements

Future versions may include:

Canonical D3FENDRecord objects

ATT&CK ↔ D3FEND link graph

Telemetry-aware defense mapping

SOC tier applicability (L1/L2/L3)

Control categories (prevent/detect/respond)

Defensive coverage scoring

16. Final Summary

The D3FEND Knowledge Pack transforms D3FEND from:

“A complex defensive ontology”

Into:

“A safe, LLM-ready defensive reference system”

It enables:

Grounded defensive explanations

Vendor-neutral security guidance

Safe SOC analyst education

Future ATT&CK-driven defense automation

It is intentionally conservative in V1, prioritizing:

Accuracy

Safety

Traceability

Over:

Automation

Assumptions

Over-interpretation