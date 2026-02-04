# API Reference

Complete reference for all API endpoints in the Cyber LLM Engine.

## Base URL

```
http://localhost:8000
```

## Authentication

Currently no authentication required. For production, implement appropriate auth middleware.

---

## Health Check

### GET /healthz

Check if the API is running.

**Response:**
```json
{
  "status": "ok"
}
```

---

## MITRE DocQA

### POST /docqa

Answer questions about MITRE ATT&CK techniques, tactics, and mitigations.

**Request Body:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `question` | string | Yes | - | Natural language question |
| `topk` | integer | No | 8 | Number of chunks to retrieve (1-32) |
| `temperature` | float | No | 0.3 | LLM temperature (0.0-1.5) |
| `include_context` | boolean | No | false | Include raw RAG context |

**Example Request:**
```bash
curl -X POST http://localhost:8000/docqa \
  -H "Content-Type: application/json" \
  -d '{
    "question": "What is T1059 and how do attackers use it?",
    "topk": 8,
    "temperature": 0.3
  }'
```

**Example Response:**
```json
{
  "question": "What is T1059 and how do attackers use it?",
  "answer": "T1059 is Command and Scripting Interpreter. Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries...",
  "meta": {
    "techniques": ["T1059"],
    "tactics": ["TA0002"],
    "platforms": ["Windows", "Linux", "macOS"],
    "mitigations": ["M1038", "M1049"]
  }
}
```

---

## MITRE Detect

### POST /detect

Get detection guidance for a specific MITRE ATT&CK technique.

**Request Body:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `technique_id` | string | Yes | - | MITRE technique ID (e.g., T1059.001) |
| `platform` | string | No | null | Target platform (Windows, Linux, macOS) |
| `available_logs` | array | No | null | Available log sources |
| `topk` | integer | No | 8 | Number of chunks to retrieve |
| `temperature` | float | No | 0.2 | LLM temperature |
| `include_context` | boolean | No | false | Include raw context |

**Example Request:**
```bash
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{
    "technique_id": "T1059.001",
    "platform": "Windows",
    "available_logs": ["WinEventLog:Security", "Sysmon", "PowerShell"],
    "topk": 8
  }'
```

**Example Response:**
```json
{
  "technique_id": "T1059.001",
  "answer": "To detect T1059.001 (PowerShell), monitor for:\n\n**Log Sources:**\n- PowerShell Script Block Logging (Event ID 4104)\n- Sysmon Event ID 1 (Process Creation)\n- Windows Security Event ID 4688\n\n**Detection Ideas:**\n1. Monitor for suspicious PowerShell command-line arguments (-enc, -nop, -w hidden)\n2. Alert on PowerShell downloading content (DownloadString, Invoke-WebRequest)\n3. Detect base64 encoded commands...",
  "context": null
}
```

---

## MITRE Mapper

### POST /mapper

Map logs, alerts, or CTI text to MITRE ATT&CK techniques.

**Request Body:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `text` | string | Yes | - | Log, alert, or incident description |
| `max_techniques` | integer | No | 5 | Maximum techniques to return |
| `observed_log_sources` | array | No | null | Log sources in the alert |
| `observed_data_components` | array | No | null | Data components observed |
| `topk` | integer | No | 30 | RAG retrieval count |

**Example Request:**
```bash
curl -X POST http://localhost:8000/mapper \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Multiple failed login attempts followed by successful login from same IP. PowerShell process spawned cmd.exe which executed net user commands.",
    "max_techniques": 5,
    "observed_log_sources": ["Windows Security", "Sysmon"]
  }'
```

**Example Response:**
```json
{
  "tactics": ["TA0006", "TA0002", "TA0007"],
  "techniques": [
    {
      "id": "T1110",
      "name": "Brute Force",
      "confidence": 0.92,
      "tactics": ["TA0006"],
      "data_components": ["DC0002"],
      "log_sources": ["WinEventLog:Security"]
    },
    {
      "id": "T1059.001",
      "name": "PowerShell",
      "confidence": 0.88,
      "tactics": ["TA0002"],
      "data_components": ["DC0003"],
      "log_sources": ["Sysmon", "PowerShell"]
    },
    {
      "id": "T1087",
      "name": "Account Discovery",
      "confidence": 0.75,
      "tactics": ["TA0007"],
      "data_components": ["DC0002"],
      "log_sources": ["WinEventLog:Security"]
    }
  ]
}
```

---

## D3FEND DocQA

### POST /d3fend/docqa

Answer questions about MITRE D3FEND defensive techniques.

**Request Body:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `question` | string | Yes | - | Defensive question |
| `topk` | integer | No | 8 | Number of chunks to retrieve |
| `temperature` | float | No | 0.3 | LLM temperature |
| `include_context` | boolean | No | false | Include raw context |

**Example Request:**
```bash
curl -X POST http://localhost:8000/d3fend/docqa \
  -H "Content-Type: application/json" \
  -d '{
    "question": "What defensive techniques help against credential dumping?",
    "topk": 8
  }'
```

**Example Response:**
```json
{
  "question": "What defensive techniques help against credential dumping?",
  "answer": "According to D3FEND, the following defensive techniques help against credential dumping:\n\n1. **Credential Hardening** - Implement credential protection mechanisms\n2. **Process Monitoring** - Monitor for suspicious LSASS access\n3. **Memory Protection** - Enable Credential Guard on Windows...",
  "meta": {
    "d3fend_techniques": ["D3-CH", "D3-PM", "D3-MP"],
    "attack_techniques": ["T1003"]
  }
}
```

---

## Chat

### POST /chat

Conversational interface with session memory and context tracking.

**Request Body:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `message` | string | Yes | - | User message |
| `session_id` | string | No | null | Session ID for continuity |
| `dataset` | string | No | "mitre" | Dataset: mitre, d3fend, all |
| `available_logs` | array | No | null | Available log sources |
| `platform` | string | No | null | Target platform |

**Example Request (New Session):**
```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "What is T1059?",
    "dataset": "mitre"
  }'
```

**Example Response:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "What is T1059?",
  "answer": "T1059 is Command and Scripting Interpreter...",
  "current_technique": "T1059",
  "current_technique_name": "Command and Scripting Interpreter",
  "mentioned_techniques": ["T1059"],
  "tactics": ["TA0002"]
}
```

**Example Follow-up (With Session):**
```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "How do I detect it?",
    "session_id": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

**Response (Coreference Resolved):**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "How do I detect it?",
  "answer": "To detect T1059, monitor for...",
  "current_technique": "T1059",
  "mentioned_techniques": ["T1059"],
  "resolved_query": "How do I detect T1059?",
  "tactics": ["TA0002"]
}
```

### GET /chat/{session_id}/history

Get conversation history for a session.

**Example:**
```bash
curl http://localhost:8000/chat/550e8400-e29b-41d4-a716-446655440000/history
```

**Response:**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "messages": [
    {
      "role": "user",
      "content": "What is T1059?",
      "timestamp": "2024-01-15T10:30:00Z"
    },
    {
      "role": "assistant",
      "content": "T1059 is Command and Scripting Interpreter...",
      "timestamp": "2024-01-15T10:30:02Z"
    }
  ],
  "current_technique": "T1059"
}
```

### DELETE /chat/{session_id}

Delete a session.

**Example:**
```bash
curl -X DELETE http://localhost:8000/chat/550e8400-e29b-41d4-a716-446655440000
```

### POST /chat/{session_id}/reset-context

Reset context but keep conversation history.

### GET /chat/sessions

List all active sessions (admin).

### POST /chat/sessions/cleanup

Clean up old sessions.

**Query Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_age_hours` | 24 | Delete sessions older than this |

---

## Smart Query Router

### POST /query

Unified endpoint that automatically routes to the appropriate handler.

**Request Body:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | Yes | - | Question or log text |
| `dataset` | string | No | "mitre" | Dataset selection |
| `mode` | string | No | "auto" | Routing mode |
| `topk` | integer | No | 8 | Retrieval count |
| `include_context` | boolean | No | false | Include raw context |

**Routing Logic:**

| Query Pattern | Route |
|---------------|-------|
| Log/alert keywords | mapper |
| Detection keywords + technique | detect |
| D3FEND keywords | d3fend |
| Default | docqa |

**Example:**
```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "How do I detect T1059?",
    "dataset": "mitre"
  }'
```

---

## OpenAI-Compatible API

### POST /v1/chat/completions

OpenAI-compatible endpoint for integration with Open WebUI and other tools.

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `model` | string | Yes | Model name (ignored, uses local LLM) |
| `messages` | array | Yes | Chat messages array |
| `temperature` | float | No | LLM temperature |
| `max_tokens` | integer | No | Max response tokens |
| `stream` | boolean | No | Enable streaming (not supported) |

**Example Request:**
```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mitre-expert",
    "messages": [
      {"role": "user", "content": "What is T1059?"}
    ],
    "temperature": 0.3
  }'
```

**Example Response:**
```json
{
  "id": "chatcmpl-abc123",
  "object": "chat.completion",
  "created": 1705312800,
  "model": "mitre-expert",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "T1059 is Command and Scripting Interpreter..."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 150,
    "total_tokens": 160
  }
}
```

---

## Error Responses

### Standard Error Format

```json
{
  "detail": "Error message describing the issue"
}
```

### Common HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 404 | Not Found - Session/resource not found |
| 422 | Validation Error - Request body validation failed |
| 500 | Internal Server Error |

### Validation Error Example

```json
{
  "detail": [
    {
      "loc": ["body", "technique_id"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

---

## Rate Limiting

Currently no rate limiting. For production, implement appropriate limits.

Suggested limits:
- `/chat`: 60 requests/minute per session
- `/docqa`, `/detect`, `/mapper`: 30 requests/minute
- `/query`: 30 requests/minute

---

## Interactive Documentation

Visit `/docs` for Swagger UI documentation:
```
http://localhost:8000/docs
```

Visit `/redoc` for ReDoc documentation:
```
http://localhost:8000/redoc
```
