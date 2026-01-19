# Chat Module for Cyber LLM Engine

This update adds conversational capabilities to your MITRE Expert Layer, transforming it from a single-turn Q&A system into a stateful chatbot.

## New Files

```
src/mitre_expert/
├── chat/                          # NEW: Chat module
│   ├── __init__.py
│   ├── session.py                 # Session management & memory
│   └── coreference.py             # Pronoun resolution ("it" → "T1059")
└── api/
    ├── main.py                    # UPDATED: Added chat router
    └── routers/
        └── chat.py                # NEW: Chat API endpoints
```

## Installation

Copy the files to your project:

```bash
# Copy the chat module
cp -r src/mitre_expert/chat /path/to/your/project/src/mitre_expert/

# Copy the chat router
cp src/mitre_expert/api/routers/chat.py /path/to/your/project/src/mitre_expert/api/routers/

# Replace main.py (or manually add the chat router import)
cp src/mitre_expert/api/main.py /path/to/your/project/src/mitre_expert/api/
```

## API Endpoints

### Chat Endpoint
```
POST /chat
```

Send messages with conversation memory:

```json
{
  "message": "What is T1059?",
  "session_id": null,
  "dataset": "mitre",
  "available_logs": ["Sysmon", "Windows Security"],
  "platform": "Windows"
}
```

Response includes `session_id` for follow-up:

```json
{
  "session_id": "abc-123",
  "answer": "T1059 is Command and Scripting Interpreter...",
  "current_technique": "T1059",
  "mentioned_techniques": ["T1059"]
}
```

### Follow-up with Context
```json
{
  "message": "How do I detect it?",
  "session_id": "abc-123"
}
```

The system automatically resolves "it" to "T1059" from context.

### Session Management

```
GET  /chat/{session_id}/history     # Get conversation history
DELETE /chat/{session_id}           # Delete session
POST /chat/{session_id}/reset-context  # Reset context, keep history
GET  /chat/sessions                 # List all sessions (admin)
POST /chat/sessions/cleanup         # Clean up old sessions
```

## Example Conversation

```
User: What is T1059?
Bot:  T1059 is Command and Scripting Interpreter. Adversaries may 
      abuse command and script interpreters to execute commands...
      [session tracks: current_technique = "T1059"]

User: How do I detect it?
      [resolved to: "How do I detect T1059?"]
Bot:  To detect T1059, monitor for:
      - Process creation events (Sysmon Event ID 1)
      - Script block logging (PowerShell)
      ...

User: What about mitigations?
      [resolved to: "What about T1059 mitigations?"]
Bot:  Key mitigations for T1059 include:
      - M1049: Antivirus/Antimalware
      - M1038: Execution Prevention
      ...

User: Now tell me about T1110
Bot:  T1110 is Brute Force...
      [session updates: current_technique = "T1110"]
```

## Coreference Patterns Supported

The system resolves these patterns to the current technique context:

| Pattern | Example | Resolved |
|---------|---------|----------|
| Pronouns | "How do I detect **it**?" | "How do I detect T1059?" |
| Technique refs | "Explain **this technique**" | "Explain T1059" |
| Possessives | "What are **its** mitigations?" | "What are T1059 mitigations?" |
| Continuations | "**Tell me more**" | "Tell me more about T1059" |
| Follow-ups | "**What about** sub-techniques?" | "What about T1059 sub-techniques?" |

## Production Considerations

### Persistent Session Storage

The default implementation uses in-memory storage. For production:

```python
# Replace in session.py:
# Option 1: Redis
import redis
r = redis.Redis()

def get_or_create_session(session_id):
    data = r.get(f"session:{session_id}")
    if data:
        return ChatSession.from_dict(json.loads(data))
    ...

# Option 2: PostgreSQL
# Store sessions in a sessions table with JSON columns
```

### Session Cleanup

Run periodic cleanup to prevent memory growth:

```python
# Cron job or scheduled task
POST /chat/sessions/cleanup?max_age_hours=24
```

### Rate Limiting

Consider adding rate limiting per session_id to prevent abuse.

## Testing

```bash
# Start the server
uvicorn mitre_expert.api.main:app --reload

# Test the chat endpoint
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is T1059?"}'

# Follow up with session_id from response
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "How do I detect it?", "session_id": "YOUR_SESSION_ID"}'
```

## OpenAPI Docs

Visit `/docs` to see the interactive API documentation with the new chat endpoints.
