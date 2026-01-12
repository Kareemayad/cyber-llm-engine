Cyber LLM Engine – MITRE Expert Layer
Architecture Document (V1)
1. Executive Summary

The Cyber LLM Engine – MITRE Expert Layer is a local, self-hosted AI system designed to assist Security Operations Center (SOC) teams.

It acts as an intelligent cybersecurity assistant that can:

Explain MITRE ATT&CK techniques in clear language

Map logs, alerts, and CTI text to likely ATT&CK techniques

Provide detection guidance based on available telemetry

Answer defensive (D3FEND) questions using structured countermeasure data

Do all of the above without hallucinating, by strictly grounding answers in trusted datasets

The system combines:

Retrieval-Augmented Generation (RAG)

Deterministic rule-based logic

Local Large Language Models (LLMs)

MITRE ATT&CK and D3FEND datasets

Everything runs locally, without sending data to external APIs.

2. Core Design Goals

This project was designed with the following principles:

2.1 Zero Hallucination Tolerance

The system must not invent:

Technique IDs

Mitigation IDs

Detection rules

Products, tools, or event IDs

If information is missing, the system explicitly says:

“The provided context does not specify this detail.”

2.2 Dataset-Grounded Intelligence

All answers are based only on:

MITRE ATT&CK data

MITRE D3FEND data

Explicitly retrieved context chunks

The LLM is not allowed to use its training knowledge beyond the supplied context.

2.3 SOC-First Usability

The system is designed for:

SOC Analysts (L1–L3)

Detection Engineers

Threat Hunters

Outputs are:

Structured

Explainable

Practical

Log-centric

2.4 Modular & Extensible

Each capability (DocQA, Mapper, Detect, D3FEND) is:

Independent

Replaceable

Testable

Future datasets and models can be added without rewriting the system.

3. High-Level System Overview

At a high level, the system works as follows:

User Input
   ↓
FastAPI Endpoint
   ↓
Rule-Based Router
   ↓
Specialist Module (DocQA / Mapper / Detect / D3FEND)
   ↓
RAG Retrieval (Chroma)
   ↓
Local LLM (strict prompts)
   ↓
Structured Answer

4. Datasets Used
4.1 MITRE ATT&CK

MITRE ATT&CK is a globally recognized knowledge base describing:

Adversary tactics

Techniques and sub-techniques

Mitigations

Detection guidance

Telemetry relationships

This project uses ATT&CK as the primary offensive and detection knowledge source.

4.2 MITRE D3FEND

MITRE D3FEND is a defensive ontology describing:

Defensive techniques

Security controls

Artifacts

Relationships to ATT&CK techniques

D3FEND is used to answer:

“How do we defend against X?”

“What countermeasures map to this attack?”

5. Offline Data Processing (Knowledge Pack Build)

Before the system can answer questions, raw MITRE data must be transformed.

5.1 MITRE Knowledge Pack Builder

File:
src/mitre_expert/knowledge_pack/build_knowledge_pack.py

Purpose

Convert raw MITRE ATT&CK data into:

A normalized internal representation

Small, searchable RAG chunks

Inputs

Raw or enriched MITRE technique JSON / JSONL files

Outputs

mitre_knowledge_pack_v1.jsonl

mitre_chunks_v1.jsonl

5.2 Technique Normalization

Each ATT&CK technique becomes a TechniqueRecord containing:

Technique ID (e.g. T1059.001)

Technique name

Tactics (IDs and names)

Platforms

Telemetry enrichment:

Data Component IDs

Log Source Names

Rich content:

Description

Procedure examples

Mitigations

Detection strategies

This ensures consistent structure regardless of input format.

5.3 Chunk Generation

Each technique is split into semantic chunks:

Chunk Type	Purpose
description	Explain what the technique is
procedure_example	How adversaries use it
mitigation	How to mitigate it
detection_strategy	How to detect it

Each chunk includes metadata such as:

technique_id

section

platforms

telemetry hints

These chunks are later embedded and indexed.

5.4 D3FEND Normalization

File:
src/mitre_expert/knowledge_pack/build_d3fend.py

Purpose

Transform D3FEND’s JSON-LD ontology and CSV mappings into structured defensive records.

Key Steps

Expand JSON-LD identifiers using namespaces

Canonicalize nodes into readable JSON

Attach ATT&CK mappings from CSV

Preserve full raw ontology data for traceability

Outputs

Consolidated JSON (debug/reference)

JSONL suitable for RAG chunking

6. Vector Database (Chroma)
6.1 Why Chroma?

Chroma is used as a vector database to:

Store embeddings of chunks

Enable semantic search

Support metadata-based filtering

Each dataset has its own collection:

mitre_chunks_v1

d3fend_chunks_v1

6.2 Retrieval Modes

The system supports two retrieval modes:

Semantic Search

Used when:

User asks a natural language question

Exact technique ID is unknown

Deterministic Get

Used when:

Technique ID and section are known

Exact chunks must be retrieved (e.g. all mitigations)

7. Runtime Architecture (FastAPI)
7.1 API Entry Point

File:
src/mitre_expert/api/main.py

The FastAPI app exposes:

Health check

Specialist endpoints

Unified /query endpoint

7.2 Unified Query Router

File:
src/mitre_expert/api/routers/router.py

This endpoint accepts:

A question or log

Dataset selection

Retrieval mode

Optional filters

It determines:

Which specialist to invoke

Whether to use LLMs or retrieval-only

7.3 Rule-Based Routing Logic

File:
src/router/router.py

The router analyzes the query using:

Technique ID detection

Log / alert keywords

Detection keywords

Possible routes:

docqa

mapper

detect

mapper_detect

This ensures the right intelligence path is used.

8. Specialist Modules
8.1 MITRE DocQA

Purpose:
Explain techniques, mitigations, tactics, platforms.

Key Features:

RAG context building

Special mitigation enumeration mode

Metadata extraction (tactics/platforms)

Strict non-hallucination prompt

8.2 MITRE Mapper

Purpose:
Map logs, alerts, or CTI text to ATT&CK techniques.

Signals Used:

Deterministic resolver (IDs, names, fuzzy match)

Semantic similarity (Chroma)

Domain-specific priors

Telemetry alignment (logs + data components)

Outputs ranked techniques with confidence scores.

8.3 MITRE Detect

Purpose:
Provide detection guidance for a technique.

Process:

Prefer detection_strategy chunks

Fallback to semantic retrieval if missing

Bias retrieval using available logs

Generate structured detection advice

8.4 D3FEND DocQA

Purpose:
Answer defensive questions using D3FEND data.

Characteristics:

Pure RAG

No inference beyond context

Defensive ontology focus

ATT&CK linkage preserved

9. Local LLM Layer

File:
src/mitre_expert/llm/local_llm.py

9.1 Why Local LLM?

Data privacy

Deterministic behavior

Cost control

Full control over prompts and context

9.2 Model Handling

Supports Apple MPS, CUDA, CPU

Uses HuggingFace Transformers

Chat template aware

Context window enforcement

Deterministic decoding for knowledge tasks

10. Prompt Engineering Philosophy

Each specialist has its own system prompt enforcing:

Context-only answers

Explicit refusal to guess

SOC-friendly tone

Structured output

Bullet lists where appropriate

This is a core safety mechanism, not an afterthought.

11. What Is Missing (V1 Gaps)
11.1 Chroma Indexing Scripts

The project assumes, but does not yet include:

A full indexing pipeline for MITRE and D3FEND

Metadata validation before insertion

11.2 D3FEND Chunk Generator

D3FEND normalization exists, but chunk generation into:

definitions

KB articles

relations

references
is not yet implemented.

11.3 Unified “dataset=all” Intelligence

Currently:

dataset=all is retrieval-only

Missing:

Combined MITRE + D3FEND reasoning and composition

11.4 Evaluation & Testing Framework

No regression or accuracy tests are defined yet.

12. Intended Future Direction

Planned enhancements include:

SOC L1–L3 role-aware responses

ATT&CK + D3FEND hybrid reasoning

Detection rule generation (Sigma templates)

Multi-dataset orchestration

Confidence explanations for Mapper outputs

13. Final Summary

This project is not just an LLM wrapper.

It is a:

Dataset-grounded

Deterministic-first

SOC-grade

Hallucination-resistant

Extensible cybersecurity intelligence engine

The MITRE Expert Layer provides a solid foundation for building advanced AI-driven SOC capabilities while preserving analyst trust and technical correctness.