#!/usr/bin/env bash
set -euo pipefail

export MITRE_DOCQA_MODEL_PATH="${MITRE_DOCQA_MODEL_PATH:-src/mitre_expert/models/llama3.1-8b-instruct}"

uvicorn mitre_expert.api.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload
