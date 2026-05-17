# PQMail Quick Start Guide

**Get the entire PQMail system running in 3 steps.**

## Prerequisites

- Python 3.10+ with venv activated (cns-venv)
- Node.js 18+ (for frontend)
- Thunderbird or email client (optional, for testing)
- Gmail account (optional, for forwarding)

## Step 1: Start Backend (Terminal 1)

```bash
cd pqmail
python run_backend.py
```

**Expected output:**
```
🚀 Starting PQMail FastAPI Backend...
📍 http://localhost:8000
📚 API Docs: http://localhost:8000/docs
🔌 WebSocket: ws://localhost:8000/ws/events

Press Ctrl+C to stop
```

Backend runs on `http://localhost:8000`

## Step 2: Start Frontend (Terminal 2)

```bash
cd pqmail/frontend

# First time only: install dependencies
npm install

# Start dev server
npm run dev
```

**Expected output:**
```
➜  Local:   http://localhost:5173/
➜  Press h to show help
```

Frontend runs on `http://localhost:5173`

## Step 3: Open Dashboard (Browser)

Open http://localhost:5173 in your browser.

You should see:
- ✅ Green status indicator ("Connected")
- 📨 "Live Email Feed" section showing "Waiting for emails..."
- 📊 Statistics cards (0 emails initially)
- 📤 "Audit Mailbox" uploader

---

## Test the System

### Option A: Audit Sample Mailbox (Fastest)

1. On dashboard, click "Upload .mbox file"
2. Select `pqmail/samples/mailbox.mbox`
3. Wait 2-3 seconds
4. See results: 54 emails analyzed, 100% critical risk, 0 years safety

### Option B: Use Thunderbird (Real Email Interception)

1. Open Thunderbird
2. Go to **Settings → Accounts**
3. Find your email account → **Outgoing Server (SMTP)**
4. Add new server:
   - Hostname: `localhost`
   - Port: `1025`
   - Security: None
5. Compose an email and send
6. Watch it appear on dashboard in real-time

See [TESTING_WITH_THUNDERBIRD.md](TESTING_WITH_THUNDERBIRD.md) for detailed setup.

### Option C: Run Tests

```bash
cd pqmail
pytest .\tests\ -v
```

Results: **104 tests passing** ✅

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Your Email Client                            │
│                     (Thunderbird, Outlook, etc.)                 │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
                            SMTP localhost:1025
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│         PQMail SMTP Proxy Gateway (Module 1)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ Parse MIME   │→ │ Classify     │→ │ Score HNDL   │           │
│  │ (Real)       │  │ Sensitivity  │  │ Risk Model   │           │
│  │              │  │ (Real)       │  │ (Real)       │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│                                   │                               │
│                            ┌──────▼──────┐                       │
│                            │ Decide      │                       │
│                            │ Action      │                       │
│                            └──────┬──────┘                       │
│                                   │                               │
│  ┌──────────────┐  ┌──────────────▼───────────┐                 │
│  │ Re-encrypt   │  │ Forward to Gmail         │                 │
│  │ (Placeholder)│  │ (Real, requires env vars)│                 │
│  └──────────────┘  └──────────────┬───────────┘                 │
│                                   │                               │
└───────────────────────────────────┼─────────────────────────────┘
                                   │
                    Push Event to Queue
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│       PQMail FastAPI Backend (Module 6)                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │         REST Endpoints                                   │   │
│  │  GET  /health, /status, /config                         │   │
│  │  GET  /recipients, /recipients/{email}/keys            │   │
│  │  POST /audit/upload                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  WebSocket: /ws/events (Real-time event stream)         │  │
│  └──────────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬────────────────────────────┘
                                   │
                              WebSocket
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│  PQMail React Dashboard (Module 7)                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Live Email Feed (20 most recent)                        │  │
│  │  ├─ alice@example.com (UNENCRYPTED, CRITICAL)           │  │
│  │  ├─ bob@example.com (HYBRID, MEDIUM)                    │  │
│  │  └─ ...                                                  │  │
│  ├─ Statistics Cards                                        │  │
│  │  ├─ Total: 42 | Critical: 38 | Hybrid: 3 | Avg: 5 yrs  │  │
│  ├─ Algorithm Distribution Chart                           │  │
│  ├─ Risk Distribution Chart                                │  │
│  └─ Mailbox Audit Uploader                                │  │
│     └─ Results: 54 emails, 0 years safety                  │  │
│                                                             │  │
│  http://localhost:5173                                     │  │
└─────────────────────────────────────────────────────────────────┘
```

---

## What Each Module Does

| Module | Purpose | Status |
|--------|---------|--------|
| 1 | SMTP Proxy Gateway | ✅ Real, intercepts emails from Thunderbird |
| 2 | MIME + OpenPGP Parser | ✅ Real, detects encryption algorithms |
| 3 | Hybrid Cryptography | ✅ X25519 real, ML-KEM mocked (MVP) |
| 4 | Key Manager | ✅ Real, stores recipient keys |
| 5 | Auditor | ✅ Real, batch scores mailbox files |
| 6 | FastAPI Backend | ✅ Real, REST API + WebSocket |
| 7 | React Dashboard | ✅ Real, live visualization |
| 8 | HTML Report | ⏳ Not yet implemented |

---

## Configuration

### Environment Variables (Optional)

Create `.env` in project root for Gmail forwarding:

```bash
UPSTREAM_HOST=smtp.gmail.com
UPSTREAM_PORT=587
UPSTREAM_USER=your-email@gmail.com
UPSTREAM_PASSWORD=your-app-password
```

Get app password: https://myaccount.google.com/apppasswords

**Without these:** Emails still processed locally but won't forward to Gmail.

---

## What's Real vs Mocked

✅ **100% Real:**
- Email interception from Thunderbird
- MIME parsing
- PGP algorithm detection
- Sensitivity classification
- HNDL risk scoring
- Key storage/retrieval
- Batch auditing
- REST API
- WebSocket streaming

🎭 **Mocked for MVP:**
- ML-KEM-768 encryption (uses mock_oqs)
- Re-encryption in gateway (placeholder)

**Why mocked?** Real liboqs-python can't build on Windows without cmake + MSVC. Mock maintains correct interface for testing. X25519 and AES are production-ready from cryptography library.

See [TESTING_WITH_THUNDERBIRD.md](TESTING_WITH_THUNDERBIRD.md) for detailed real vs mocked breakdown.

---

## Troubleshooting

### "Connection refused" on dashboard

```bash
# Make sure backend started FIRST
python run_backend.py

# Wait 3 seconds for "Event queue initialized"

# THEN start frontend
cd frontend && npm run dev
```

### Tests failing

```bash
# Verify venv activated
.\cns-venv\Scripts\activate

# Run all tests
pytest .\tests\ -v

# Run specific test
pytest .\tests\test_parser.py::TestMimeParser::test_parse_simple_email -v
```

### Thunderbird won't connect

```bash
# Check if port 1025 is available
netstat -ano | findstr :1025

# Try different port (update Thunderbird config)
```

### "npm: command not found"

```bash
# Install Node.js from https://nodejs.org/
# Or use package manager:
choco install nodejs  # Windows

# Verify installation
node --version
npm --version
```

---

## Next Steps

1. ✅ Run backend: `python run_backend.py`
2. ✅ Run frontend: `cd frontend && npm run dev`
3. ✅ Test with mailbox audit or Thunderbird
4. 📝 Document your findings
5. 🎓 Reference real metrics in your paper

---

## Documentation

- [Module 1: SMTP Proxy Gateway](docs/implementation_plan.md)
- [Module 2: MIME + OpenPGP Parser](docs/implementation_plan.md)
- [Module 3: Hybrid Cryptography](docs/implementation_plan.md)
- [Module 4: Key Manager](docs/implementation_plan.md)
- [Module 5: Auditor](docs/implementation_plan.md)
- [Module 6: FastAPI Backend](docs/module_6_backend.md)
- [Module 7: React Dashboard](docs/module_7_frontend.md)
- [Testing with Thunderbird](docs/TESTING_WITH_THUNDERBIRD.md)
- [Implementation Status](IMPLEMENTATION_STATUS.md)

---

## Summary

🚀 **The system is ready to use.** You have:
- ✅ Real email interception gateway
- ✅ Real HNDL risk scoring
- ✅ Real auditing capabilities
- ✅ Live dashboard with WebSocket updates
- ✅ 104 passing tests

Start the backend and frontend, then test with either the sample mailbox or Thunderbird. The entire pipeline works end-to-end for your research.
