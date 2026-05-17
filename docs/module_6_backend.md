# PQMail FastAPI Backend (Module 6)

REST API and WebSocket server for the PQMail dashboard. Provides real-time event streaming, configuration management, and mbox audit capabilities.

## Quick Start

```bash
# Start backend server
python run_backend.py

# Server runs at http://localhost:8000
```

Then open:
- **API Docs (Swagger):** http://localhost:8000/docs
- **OpenAPI Schema:** http://localhost:8000/openapi.json

## Architecture

### Event Flow

```
Email Gateway (Module 1)
    ↓ push_event()
Event Queue (asyncio.Queue)
    ↓
Backend broadcast_events()
    ↓
WebSocket Clients ← /ws/events
    ↓
Dashboard (receives real-time updates)
```

### REST API Endpoints

#### Health & Status
- `GET /health` - Health check
- `GET /status` - Gateway status (SMTP proxy, event queue, connected clients)
- `GET /config` - Configuration (quantum timeline, supported algorithms, features)
- `GET /` - API documentation index

#### Recipients (Key Management)
- `GET /recipients` - List all recipients with stored keys
- `POST /recipients/{email}/keys` - Import public keys (ML-KEM + X25519)
- `GET /recipients/{email}/keys` - Retrieve public keys for recipient

**Import Keys Example:**
```bash
curl -X POST http://localhost:8000/recipients/alice@example.com/keys \
  -H "Content-Type: application/json" \
  -d '{
    "mlkem_public_key": "base64-encoded-1184-bytes",
    "x25519_public_key": "base64-encoded-32-bytes"
  }'
```

#### Audit
- `POST /audit/upload` - Upload and audit .mbox file
- `GET /audit/stats` - Get statistics from last audit

**Upload Example:**
```bash
curl -X POST http://localhost:8000/audit/upload \
  -F "file=@samples/mailbox.mbox"
```

Response:
```json
{
  "filename": "mailbox.mbox",
  "audit": {
    "total_emails": 54,
    "successfully_parsed": 54,
    "parse_errors": 0,
    "algorithms": {"UNENCRYPTED": 54},
    "sensitivities": {"LOW": 44, "CRITICAL": 5, "MEDIUM": 5},
    "risk_categories": {"CRITICAL": 54},
    "avg_years_of_safety": 0.0
  },
  "critical_count": 54,
  "unencrypted_count": 54
}
```

### WebSocket Endpoint

**URL:** `ws://localhost:8000/ws/events`

**Event Schema:**
```json
{
  "timestamp": "2026-05-17T10:30:45.123456",
  "message_id": "<msg@example.com>",
  "from": "alice@example.com",
  "to": ["bob@example.com"],
  "algorithm": "HYBRID",
  "sensitivity": "HIGH",
  "risk": {
    "risk_category": "MEDIUM",
    "years_of_safety_remaining": 25
  },
  "action": "FORWARD",
  "flag": null
}
```

**Python Client Example:**
```python
import asyncio
import websockets
import json

async def listen_events():
    async with websockets.connect("ws://localhost:8000/ws/events") as ws:
        while True:
            event = await ws.recv()
            data = json.loads(event)
            print(f"Event: {data['message_id']} - {data['algorithm']}")

asyncio.run(listen_events())
```

## Features

✅ **CORS Enabled** - Frontend can connect from any origin
✅ **Auto-reload** - Code changes reflect immediately during development
✅ **Event Broadcasting** - Real-time updates to all connected clients
✅ **Audit Upload** - Process .mbox files on-demand
✅ **Key Management** - Store and retrieve recipient public keys
✅ **OpenAPI Docs** - Interactive API documentation

## Testing

```bash
# Run all API tests
pytest tests/test_api.py -v

# Run specific test class
pytest tests/test_api.py::TestRecipients -v

# Run with coverage
pytest tests/test_api.py --cov=pqmail.api
```

**Test Coverage:**
- ✅ Health checks and status endpoints
- ✅ Configuration retrieval
- ✅ Recipient key import/retrieval
- ✅ Audit file upload
- ✅ Error handling (invalid formats, missing data)
- ✅ OpenAPI schema validation

## Configuration

Environment variables:
```bash
# Backend
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000

# Event queue (shared with gateway)
EVENT_QUEUE_TIMEOUT=1  # seconds
```

## Next Steps

**Module 7 - React Frontend** will connect to this backend via:
1. HTTP REST calls for configuration and audit uploads
2. WebSocket `/ws/events` for real-time email feed
3. Live risk badges and distribution charts

The backend is ready to serve a modern React SPA dashboard.
