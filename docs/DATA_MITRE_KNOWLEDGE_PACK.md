Cyber LLM Engine – MITRE Knowledge Pack
Data Architecture & Processing (V1)
1. Purpose of This Document

This document explains what the MITRE Knowledge Pack is, why it exists, how it is built, and how it is used inside the Cyber LLM Engine.

It is written so that:

A new engineer, SOC analyst, or architect

With no prior exposure to this project

Can fully understand the data layer that powers all MITRE intelligence

2. What Is the MITRE Knowledge Pack?

The MITRE Knowledge Pack is the canonical, normalized, machine-readable representation of the MITRE ATT&CK framework used by this project.

It is not raw MITRE data.

It is:

Cleaned

Normalized

Enriched

Chunked

Designed for RAG (Retrieval-Augmented Generation)

The Knowledge Pack is the single source of truth for:

MITRE DocQA

MITRE Mapper

MITRE Detect

Any future MITRE-based intelligence

3. Why a Knowledge Pack Is Necessary
3.1 Problems with Raw MITRE Data

Raw MITRE ATT&CK data is:

Highly nested

Inconsistent across versions

Difficult to query semantically

Not optimized for LLM context windows

Not telemetry-aware by default

LLMs cannot reason safely or efficiently over raw ATT&CK JSON.

3.2 Design Goals of the Knowledge Pack

The Knowledge Pack solves this by ensuring:

Deterministic Structure
Every technique looks the same internally.

LLM-Friendly Chunking
Content is split into small, meaningful units.

Telemetry Awareness
Each chunk carries log source and data component metadata.

Traceability
Every chunk can be traced back to its original MITRE source.

Future Extensibility
Supports enrichment, analytics, and multi-dataset fusion.

4. File Outputs (What Gets Generated)

The MITRE Knowledge Pack produces two primary artifacts:

data/processed/mitre/
├── mitre_knowledge_pack_v1.jsonl
└── mitre_chunks_v1.jsonl


These files serve different purposes and must not be confused.

5. mitre_knowledge_pack_v1.jsonl
5.1 What This File Is

This file contains one JSON object per MITRE ATT&CK technique.

Each line represents a fully normalized technique record, including:

Metadata

Description

Procedures

Mitigations

Detection strategies

Telemetry enrichment

This is the authoritative internal representation of ATT&CK.

5.2 What This File Is NOT

It is:

❌ Not embedded

❌ Not directly queried by the LLM

❌ Not used for semantic search

Instead, it is used to:

Generate RAG chunks

Enable deterministic lookups

Support future analytics and exports

5.3 TechniqueRecord Structure

Each line maps to the following conceptual structure:

TechniqueRecord
├── technique_id
├── technique_name
├── domain
├── url
├── tactics
├── platforms
├── telemetry enrichment
│   ├── data_component_ids
│   └── log_source_names
├── description
├── procedure_examples[]
├── associated_mitigations[]
└── associated_detection_strategies[]

5.4 Telemetry Enrichment (Critical Design Choice)

Each technique includes:

MITRE Data Component IDs (e.g. DC0002)

Log Source Names (e.g. WinEventLog:Security)

These fields are propagated to every chunk later.

This enables:

Log-aware retrieval

Detection biasing

SOC-relevant answers

Without this, detection guidance would be generic and weak.

6. mitre_chunks_v1.jsonl
6.1 What This File Is

This file contains RAG-ready chunks, not full techniques.

Each line is a ChunkRecord, designed to:

Be embedded into Chroma

Fit inside LLM context windows

Represent one semantic idea

This is the primary runtime dataset.

6.2 Why Chunking Is Necessary

LLMs cannot safely reason over:

Entire techniques

Entire frameworks

Chunking allows:

Precision retrieval

Lower hallucination risk

Section-aware reasoning (mitigations vs detection)

6.3 Chunk Types

Each technique is split into multiple chunk types:

Section	Purpose
description	What the technique is
procedure_example	How attackers use it
mitigation	How to mitigate it
detection_strategy	How to detect it

Each chunk is self-contained and meaningful.

6.4 ChunkRecord Structure

Each chunk contains:

ChunkRecord
├── chunk_id
├── technique_id
├── technique_name
├── section
├── text
├── tactics
├── platforms
├── telemetry enrichment
│   ├── data_component_ids
│   └── log_source_names
├── optional mitigation metadata
└── optional detection metadata


This metadata is essential for:

Filtering

Biasing

Deterministic retrieval

7. Chunk ID Strategy

Chunk IDs are deterministic and human-readable:

T1059_desc
T1059_proc_1
T1059_mit_M1052
T1059_det_AN0001


This enables:

Debugging

Traceability

Safe deterministic retrieval

8. Knowledge Pack Build Pipeline
8.1 Input Sources

The build process consumes:

Raw MITRE ATT&CK technique data

Optional enriched ATT&CK exports

Telemetry mappings

8.2 Build Flow (Step by Step)
Raw MITRE Data
   ↓
TechniqueRecord.from_raw()
   ↓
Normalization & Enrichment
   ↓
mitre_knowledge_pack_v1.jsonl
   ↓
TechniqueRecord.iter_chunks()
   ↓
mitre_chunks_v1.jsonl

8.3 Why Two Files?
File	Role
knowledge_pack	Canonical source of truth
chunks	Runtime RAG dataset

This separation avoids:

Data duplication

Accidental mutation

Loss of rich structure

9. How the Knowledge Pack Is Used at Runtime
9.1 MITRE DocQA

Semantic search over chunks

Deterministic retrieval for mitigations

Metadata extraction (tactics, platforms)

9.2 MITRE Mapper

Uses chunks for semantic similarity

Uses telemetry metadata for priors

Uses knowledge pack for name resolution

9.3 MITRE Detect

Prefers detection_strategy chunks

Filters by log source availability

Falls back gracefully if data is missing

10. Safety & Anti-Hallucination Design

The Knowledge Pack enforces safety by:

Small, scoped chunks

Explicit section labeling

Telemetry-aware metadata

Deterministic fallback logic

Prompt-level enforcement

The LLM cannot invent data that does not exist in the pack.

11. What Is Missing (V1 Data Gaps)
11.1 No Versioning Metadata

There is no explicit:

ATT&CK version

Build timestamp

Source hash

This should be added in V2.

11.2 No Confidence Scoring

Chunks do not currently include:

Reliability indicators

Source confidence

11.3 No Cross-Technique Relations

Relationships such as:

Parent/sub-technique graphs

Kill-chain flows
are not yet materialized.

11.4 No D3FEND Integration Here

D3FEND uses a separate pipeline and is not yet merged.

12. Intended Future Enhancements

Planned improvements include:

Versioned knowledge packs

Multi-domain ATT&CK support

ATT&CK ↔ D3FEND linking

Detection rule references (Sigma)

SOC-tier-aware metadata

Graph-based representations

13. Final Summary

The MITRE Knowledge Pack is the foundation of trust in this system.

It transforms MITRE ATT&CK from:

“A large static framework”

Into:

“A machine-readable, LLM-safe, SOC-ready intelligence layer”

Without it:

RAG would be unreliable

Detection guidance would be vague

Mapping would be noisy

Hallucinations would be inevitable

With it:

Every answer is traceable

Every detection is grounded

Every explanation is defensible