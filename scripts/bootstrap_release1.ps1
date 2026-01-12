param(
  [string]$Repo = "Kareemayad/cyber-llm-engine",
  [string]$ProjectTitle = "Release 1  Execution Board"
)

$ErrorActionPreference = "Stop"

function Ensure-GH {
  try { gh --version | Out-Null } catch { throw "GitHub CLI (gh) not found in PATH. Fix PATH then re-run." }
}

function Ensure-Auth {
  $status = gh auth status 2>$null
  if ($LASTEXITCODE -ne 0) { throw "Not authenticated. Run: gh auth login" }
}

function Upsert-Label($name, $color, $desc) {
  $exists = gh label list -R $Repo --search $name --json name -q ".[].name" 2>$null | Select-String -SimpleMatch -Pattern $name
  if ($exists) {
    gh label edit $name -R $Repo --color $color --description $desc | Out-Null
    Write-Host " updated label $name"
  } else {
    gh label create $name -R $Repo --color $color --description $desc | Out-Null
    Write-Host " created label $name"
  }
}

function Create-Issue-IfMissing($title, $labels, $body) {
  $exists = gh issue list -R $Repo --search $title --json title -q ".[].title" 2>$null | Select-String -SimpleMatch -Pattern $title
  if ($exists) {
    Write-Host " exists: $title"
    return
  }
  gh issue create -R $Repo --title $title --body $body --label ($labels -join ",") | Out-Null
  Write-Host " created issue: $title"
}

# --- MAIN ---
Ensure-GH
Ensure-Auth

Write-Host "== Creating/updating labels =="
$labels = @(
  @{n="phase-1"; c="1D76DB"; d="Release 1 Phase 1: Foundations"},
  @{n="phase-2"; c="0E8A16"; d="Release 1 Phase 2: DocQA + Detect"},
  @{n="phase-3"; c="FBCA04"; d="Release 1 Phase 3: Mapper + Detection"},
  @{n="phase-4"; c="D93F0B"; d="Release 1 Phase 4: Integrations"},

  @{n="type:data"; c="C5DEF5"; d="Data work: schema, ingestion, datasets"},
  @{n="type:infra"; c="BFDADC"; d="Infrastructure: Chroma, embeddings, indexing"},
  @{n="type:feature"; c="5319E7"; d="Product features: APIs, routing, UX"},
  @{n="type:model"; c="0052CC"; d="Model training/fine-tuning"},
  @{n="type:integration"; c="0B3D91"; d="Integrations: n8n, SIEM, Slack/Jira"},

  @{n="model:docqa"; c="2ECC71"; d="DocQA component"},
  @{n="model:mapper"; c="F39C12"; d="Mapper component"},
  @{n="model:detect"; c="E74C3C"; d="Detect component"},
  @{n="model:composer"; c="9B59B6"; d="Answer Composer component"},
  @{n="router"; c="34495E"; d="Routing & orchestration"},

  @{n="prio:P0"; c="B60205"; d="Must-have for Release 1"},
  @{n="prio:P1"; c="D93F0B"; d="High priority"},
  @{n="prio:P2"; c="FBCA04"; d="Nice-to-have / later"},

  @{n="blocked"; c="000000"; d="Blocked by dependency"},
  @{n="needs-review"; c="006B75"; d="Ready for review/validation"},
  @{n="needs-eval"; c="6F42C1"; d="Needs evaluation results"}
)

foreach ($l in $labels) { Upsert-Label $l.n $l.c $l.d }

# Shared checklist blocks
$routingChecklist = @"
### Routing Decision Checklist
- [ ] Is this query best handled by **DocQA**?
- [ ] Does it require **Mapper** (scenario/log  techniques)?
- [ ] Does it require **Detect** (technique  detection)?
- [ ] Is this **deterministic** (no LLM needed)?
- [ ] Does output require **strict JSON**?
- [ ] Does this affect `/query` routing behavior?
- [ ] Is RAG context sufficient without fine-tuning?
"@

$evalDocQA = @"
### Eval Checklist  DocQA
- [ ] JSON validity rate (%) on eval set
- [ ] Correct ID accuracy (technique/group/software) on held-out set
- [ ] Relationship correctness (grouptech, softwaretech)
- [ ] Hallucination rate: made-up IDs or entities
- [ ] Latency & token usage recorded
"@

$evalMapper = @"
### Eval Checklist  Mapper
- [ ] JSON validity rate (%)
- [ ] Precision@1 / Precision@3 / Precision@5
- [ ] Recall@3 / Recall@5 / Recall@10
- [ ] Accuracy@3 (any-hit)
- [ ] Confidence calibration notes
- [ ] Common failure modes documented
"@

$evalDetect = @"
### Eval Checklist  Detect
- [ ] JSON validity rate (%)
- [ ] Log source relevance (spot-check 1020)
- [ ] Platform correctness
- [ ] Output specificity (fields/events suggested)
- [ ] Avoids impossible sources
"@

$evalComposer = @"
### Eval Checklist  Composer
- [ ] No contradictions after merge
- [ ] Dedup works (same technique/rule appears once)
- [ ] Preserves confidence values + provenance
- [ ] Output schema stable
"@

Write-Host "== Creating Release 1 issues =="

# Issues list (title, labels[], estimate, body)
$issues = @(
  @{
    t="[P1] Canonical MITRE Schema Design"; l=@("phase-1","type:data","prio:P0");
    e=2; b=@"
Goal: Define canonical internal schema for MITRE entities + relationships (DB + Chroma metadata).

Acceptance Criteria:
- [ ] Entity types defined: technique, tactic, group, software, mitigation, data_source, detection_rule
- [ ] Relationship model defined (grouptechnique, softwaretechnique, techniquetactic, etc.)
- [ ] Metadata fields required for RAG filters documented
- [ ] JSONSchema or Pydantic models committed

$routingChecklist
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P1] ATT&CK Ingestion Pipeline (STIX/JSON  Canonical)"; l=@("phase-1","type:data","prio:P0");
    e=2; b=@"
Goal: Parse ATT&CK STIX/JSON into canonical schema and persist to DB + Chroma.

Acceptance Criteria:
- [ ] Techniques ingested with correct IDs, names, tactics, platforms
- [ ] Detection + Data Sources sections extracted where available
- [ ] Stored in DB + Chroma collection `mitre_attack`
- [ ] Validation script passes

$routingChecklist
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P1] Navigator Layers Ingestion (Relationships)"; l=@("phase-1","type:data","prio:P0");
    e=2; b=@"
Goal: Parse Navigator layers and store relationship edges (grouptechnique, softwaretechnique).

Acceptance Criteria:
- [ ] Navigator JSON parsed
- [ ] Relationship edges stored in canonical format
- [ ] Query: group  techniques works
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P1] D3FEND Ingestion + Mapping"; l=@("phase-1","type:data","prio:P1");
    e=2; b=@"
Goal: Ingest D3FEND objects and map/link to ATT&CK entities where possible.

Acceptance Criteria:
- [ ] D3FEND ingested to `mitre_d3fend`
- [ ] Links to ATT&CK techniques available where possible
- [ ] RAG retrieval works for D3FEND terms
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P1] Detection Rules Ingestion (Sigma v1) + Normalization"; l=@("phase-1","type:data","prio:P0");
    e=5; b=@"
Goal: Parse Sigma rules and normalize metadata into `detection_rules` collection.

Acceptance Criteria:
- [ ] Sigma YAML parsed at scale
- [ ] Normalized fields: title, logsource, product/service, tags/mitre, level, status
- [ ] `mitre_attack_id` extracted when present
- [ ] Stored in Chroma with metadata filters
---
**Estimate:** 5 day(s)
"@
  },
  @{
    t="[P1] Chroma Collections + Embeddings + Chunking Strategy"; l=@("phase-1","type:infra","prio:P0");
    e=2; b=@"
Goal: Set up Chroma collections + embeddings and define chunking rules.

Acceptance Criteria:
- [ ] Collections: mitre_attack, mitre_d3fend, detection_rules, cti_examples
- [ ] Embedding backend configured and documented
- [ ] Chunk size/overlap implemented
- [ ] Smoke test indexing + query works
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P1] RAG Client Library (Search + Filters + Context Packing)"; l=@("phase-1","type:feature","prio:P0");
    e=2; b=@"
Goal: Python library to query Chroma with filters and pack context for prompts.

Acceptance Criteria:
- [ ] search(query, top_k, filters) works
- [ ] Filters: technique_id, entity_type, platform, source
- [ ] Context packing enforces max tokens
- [ ] Unit tests for retrieval + filtering
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P1] Minimal FastAPI Endpoint: /rag-test"; l=@("phase-1","type:feature","prio:P0");
    e=2; b=@"
Goal: Validate retrieval end-to-end via HTTP.

Acceptance Criteria:
- [ ] /rag-test?q= returns chunks + metadata
- [ ] Basic error handling + logging
- [ ] Documented run steps
---
**Estimate:** 2 day(s)
"@
  },

  @{
    t="[P2] DocQA Training Dataset Generation (ATT&CK + Navigator)"; l=@("phase-2","type:model","model:docqa","prio:P0");
    e=4; b=@"
Goal: Generate DocQA dataset for stable JSON and correct ID answering.

Acceptance Criteria:
- [ ] Dataset schema defined (prompt/input/output JSON)
- [ ] Covers techniques/tactics/groups/software + relationships
- [ ] Train/val split created

$evalDocQA
---
**Estimate:** 4 day(s)
"@
  },
  @{
    t="[P2] MITRE-DocQA LoRA v1 (MLX)"; l=@("phase-2","type:model","model:docqa","prio:P0","needs-eval");
    e=4; b=@"
Goal: Train DocQA LoRA for consistency and JSON stability.

Acceptance Criteria:
- [ ] Training config committed
- [ ] Adapter artifacts versioned
- [ ] Inference steps documented

$evalDocQA
---
**Estimate:** 4 day(s)
"@
  },
  @{
    t="[P2] DocQA Evaluation + Router Gating Rules"; l=@("phase-2","type:feature","router","model:docqa","prio:P0");
    e=2; b=@"
Goal: Compare Base+RAG vs DocQA LoRA; define routing gates.

Acceptance Criteria:
- [ ] Eval set created (IDs + tricky relationships)
- [ ] Metrics recorded
- [ ] Router rules implemented

$routingChecklist
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P2] Detect Dataset v0 (Technique  Log Sources / Detection Ideas)"; l=@("phase-2","type:data","model:detect","prio:P1");
    e=5; b=@"
Goal: Build Detect dataset from ATT&CK detection/data sources + Sigma metadata.

Acceptance Criteria:
- [ ] Dataset schema defined
- [ ] Includes platform/environment
- [ ] Output JSON includes log sources + hints + fields
---
**Estimate:** 5 day(s)
"@
  },
  @{
    t="[P2] Detect v0 (Prompt + RAG + Deterministic JSON)"; l=@("phase-2","type:feature","model:detect","prio:P0");
    e=2; b=@"
Goal: Implement Detect with templates + RAG (no fine-tune yet).

Acceptance Criteria:
- [ ] /detect returns schema-valid JSON
- [ ] Uses ATT&CK + rules RAG context
- [ ] Deterministic post-validation

$evalDetect
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P2] Core MITRE Router (DocQA vs Detect)"; l=@("phase-2","type:feature","router","prio:P0");
    e=2; b=@"
Goal: Rule-based routing for MITRE queries.

Acceptance Criteria:
- [ ] Heuristics implemented
- [ ] Route decision logged
- [ ] Tests for common patterns

$routingChecklist
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P2] Core FastAPI Services (/docqa /detect /query)"; l=@("phase-2","type:feature","prio:P0");
    e=3; b=@"
Goal: Standardize request/response schemas and expose endpoints.

Acceptance Criteria:
- [ ] /docqa, /detect, /query implemented
- [ ] Shared response envelope + error format
- [ ] OpenAPI docs render correctly
---
**Estimate:** 3 day(s)
"@
  },

  @{
    t="[P3] CTI  MITRE Dataset Collection"; l=@("phase-3","type:data","model:mapper","prio:P0");
    e=5; b=@"
Goal: Collect labeled CTI/log/scenario examples with technique labels.

Acceptance Criteria:
- [ ] Sources documented
- [ ] Raw corpus stored or reproducible scripts included
- [ ] Label sanity checks
---
**Estimate:** 5 day(s)
"@
  },
  @{
    t="[P3] Mapper Dataset Standardization (Strict JSONL)"; l=@("phase-3","type:data","type:model","model:mapper","prio:P0");
    e=5; b=@"
Goal: Convert all Mapper examples into a strict JSONL schema.

Acceptance Criteria:
- [ ] One schema for scenario/log/alert
- [ ] Output includes tactics, techniques, confidence
- [ ] Validation checks schema + allowed IDs
---
**Estimate:** 5 day(s)
"@
  },
  @{
    t="[P3] MITRE-Mapper LoRA v1 (Scenario/Log  Techniques)"; l=@("phase-3","type:model","model:mapper","prio:P0","needs-eval");
    e=5; b=@"
Goal: Train Mapper LoRA and integrate strict JSON output.

Acceptance Criteria:
- [ ] Training pipeline committed
- [ ] Adapter artifacts versioned
- [ ] /mapper returns schema-valid JSON

$evalMapper
---
**Estimate:** 5 day(s)
"@
  },
  @{
    t="[P3] Mapper Evaluation Suite (Multi-label Metrics)"; l=@("phase-3","type:feature","model:mapper","prio:P0");
    e=2; b=@"
Goal: Automated evaluation for Mapper.

Acceptance Criteria:
- [ ] precision@k / recall@k / accuracy@3 implemented
- [ ] Baseline vs LoRA comparison saved
- [ ] Results stored + plotted
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P3] Detection Router Extensions (Rules Search + Mapper Composition)"; l=@("phase-3","type:feature","router","prio:P0");
    e=2; b=@"
Goal: Extend routing for detection flows (Mapper  rules search  Detect hints).

Acceptance Criteria:
- [ ] detection patterns route correctly
- [ ] composition path works end-to-end
- [ ] decision logged

$routingChecklist
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P3] RAG Quality Tuning (Chunking/TopK/Filters per Use-case)"; l=@("phase-3","type:infra","prio:P1");
    e=2; b=@"
Goal: Improve retrieval reliability per use-case.

Acceptance Criteria:
- [ ] benchmark queries defined
- [ ] tuned top_k + filters per endpoint
- [ ] before/after documented
---
**Estimate:** 2 day(s)
"@
  },
  @{
    t="[P3] Logging & Analytics (Queries + Routes + Outputs)"; l=@("phase-3","type:feature","prio:P0");
    e=2; b=@"
Goal: Capture telemetry for improving router and fine-tunes.

Acceptance Criteria:
- [ ] logs include request, route, model version, JSON validity, latency
- [ ] persisted with rotation
- [ ] redaction supported
---
**Estimate:** 2 day(s)
"@
  },

  @{
    t="[P4] n8n  FastAPI API Contract"; l=@("phase-4","type:integration","prio:P0");
    e=1; b=@"
Goal: Define JSON contract between n8n workflows and FastAPI endpoints.

Acceptance Criteria:
- [ ] input schemas for alerts/CTI defined
- [ ] output schemas versioned
- [ ] example payloads committed
---
**Estimate:** 1 day(s)
"@
  },
  @{
    t="[P4] SIEM Alert Enrichment Flow (n8n)"; l=@("phase-4","type:integration","prio:P0");
    e=3; b=@"
Goal: SIEM webhook  /query  Slack/Jira enrichment.

Acceptance Criteria:
- [ ] n8n workflow exported
- [ ] retries/failures handled
- [ ] readable enrichment summary
---
**Estimate:** 3 day(s)
"@
  },
  @{
    t="[P4] CTI Batch Mapping Flow (n8n Scheduled)"; l=@("phase-4","type:integration","prio:P1");
    e=3; b=@"
Goal: Scheduled CTI ingestion  split  /mapper  storage.

Acceptance Criteria:
- [ ] schedule configured
- [ ] storage target defined
- [ ] dedup + tracking
---
**Estimate:** 3 day(s)
"@
  },
  @{
    t="[P4] Answer Composer (Merge + Dedup + Narrative)"; l=@("phase-4","type:feature","model:composer","prio:P0");
    e=2; b=@"
Goal: Merge outputs (DocQA/Mapper/Detect) into a final response.

Acceptance Criteria:
- [ ] dedup implemented
- [ ] narrative + structured JSON returned
- [ ] citations include chunk IDs/metadata

$evalComposer
---
**Estimate:** 2 day(s)
"@
  }
)

foreach ($it in $issues) {
  Create-Issue-IfMissing $it.t $it.l $it.b
}

Write-Host "== Done: labels + issues created =="
Write-Host "Next: create a Project board manually, or ask me for the script to create Project + auto-add issues."


