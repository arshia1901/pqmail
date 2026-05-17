# PQMail: Post-Quantum Secure Email Gateway

**SMTP proxy gateway with hybrid post-quantum cryptography (ML-KEM-768 + X25519) and HNDL (Harvest Now Decrypt Later) risk assessment.**

A research implementation for secure email processing with real-time risk visualization.

![Status: 104 Tests Passing](https://img.shields.io/badge/tests-104%20passing-brightgreen)
![Modules: 7/8 Complete](https://img.shields.io/badge/modules-7%2F8-blue)
![Python 3.13](https://img.shields.io/badge/python-3.13-blue)

---

## ⚡ Quick Start

```bash
# Terminal 1: Backend
python run_backend.py
# → http://localhost:8000

# Terminal 2: Frontend
cd frontend && npm install && npm run dev
# → http://localhost:5173

# Browser: Open http://localhost:5173
```

See [QUICKSTART.md](QUICKSTART.md) for detailed setup with Thunderbird testing.

---

## 🏗️ Architecture

```
Thunderbird/Email Client
        ↓ SMTP localhost:1025
SMTP Proxy Gateway (Module 1)
  Parse → Classify → Score → Decide → Re-encrypt → Forward
  ↓ Event Queue
FastAPI Backend (Module 6) ← REST API
  ├─ /health, /config, /status
  ├─ /recipients/{email}/keys
  ├─ /audit/upload
  └─ /ws/events (WebSocket)
        ↓ WebSocket
React Dashboard (Module 7)
  Live Email Feed + Statistics + Audit Upload
```

---

## 📦 Modules

| # | Module | Status | Details |
|---|--------|--------|---------|
| 1 | SMTP Proxy Gateway | ✅ | Intercepts emails from Thunderbird/clients on localhost:1025 |
| 2 | MIME + OpenPGP Parser | ✅ | Extracts structure, detects RSA/ECDH/hybrid encryption |
| 3 | Hybrid Cryptography | ✅ | ML-KEM-768 (mocked) + X25519 (real) + AES-256-GCM (real) |
| 4 | Key Manager | ✅ | Stores/retrieves recipient public keys with caching |
| 5 | Auditor | ✅ | Batch scores .mbox files with HNDL risk model |
| 6 | FastAPI Backend | ✅ | REST API + WebSocket server for dashboard |
| 7 | React Dashboard | ✅ | Real-time visualization with Tailwind CSS |
| 8 | HTML Report Generator | ⏳ | Jinja2 templates for risk reports |

---

## 📊 HNDL Risk Model

**Formula:** `years_of_safety = max(0, D - T + modifier)`

Where:
- **D (Defense Horizon):** Years until algorithm breaks
  - `RSA-2048`: 5 years
  - `ECDH`: 7 years
  - `Hybrid (ML-KEM-768 + X25519)`: 50 years
  - `Unencrypted`: 0 years
- **T (Timeline):** Years until quantum threat (default: 10)
- **Sensitivity Modifier:**
  - `CRITICAL`: -6 years
  - `HIGH`: -3 years
  - `MEDIUM`: 0 years
  - `LOW`: +2 years

**Result:** Risk category based on years remaining
- `years > 20`: LOW
- `10 < years ≤ 20`: MEDIUM
- `5 < years ≤ 10`: HIGH
- `years ≤ 5`: CRITICAL

---

## 🚀 Features

### ✅ Real (Production-Ready)
- Email parsing from MIME
- OpenPGP algorithm detection
- Sensitivity classification (keyword-based)
- HNDL risk scoring
- Key storage/retrieval with caching
- Batch mailbox auditing
- REST API endpoints
- WebSocket real-time events
- React dashboard with live updates
- Email forwarding to Gmail

### 🎭 Mocked (MVP)
- ML-KEM-768 key encapsulation (real liboqs unavailable on Windows)
- Re-encryption in gateway (placeholder for Phase 2)

See [TESTING_WITH_THUNDERBIRD.md](docs/TESTING_WITH_THUNDERBIRD.md) for detailed real vs mocked breakdown.

---

## 📚 Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Get running in 3 steps
- **[TESTING_WITH_THUNDERBIRD.md](docs/TESTING_WITH_THUNDERBIRD.md)** - Real email interception guide
- **[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)** - Detailed module status
- **[Module 6: FastAPI Backend](docs/module_6_backend.md)** - REST API reference
- **[Module 7: React Dashboard](docs/module_7_frontend.md)** - Frontend guide
- **[Implementation Plan](docs/implementation_plan.md)** - Full design document

---

## 🧪 Testing

```bash
# Run all tests
pytest .\tests\ -v

# Run specific module
pytest .\tests\test_crypto.py -v

# Coverage
pytest .\tests\ --cov=pqmail
```

**Results:** 104 tests passing, 14 skipped (path issues, not functionality)

---

## 🔌 API Endpoints

### Health & Status
```
GET  /health            # Health check
GET  /status            # Gateway status
GET  /config            # Configuration
GET  /                  # API docs
```

### Recipients
```
GET  /recipients                     # List all
GET  /recipients/{email}/keys        # Get keys
POST /recipients/{email}/keys        # Import keys
```

### Audit
```
POST /audit/upload   # Upload .mbox file
GET  /audit/stats    # Last audit stats
```

### WebSocket
```
WS   /ws/events      # Real-time email stream
```

---

## 🎯 Use Cases

### Test Case 1: Thunderbird Interception
1. Configure Thunderbird to use localhost:1025
2. Send email
3. Watch appear on dashboard in real-time

### Test Case 2: Mailbox Audit
1. Upload samples/mailbox.mbox to dashboard
2. See statistics: algorithm distribution, risk breakdown, safety years
3. Results: 54 emails analyzed, 100% unencrypted, 54 critical risk

### Test Case 3: Key Management
1. Import recipient keys via REST API
2. Retrieve via dashboard
3. Use for future re-encryption

---

## 📖 Example Usage

### Command Line Audit
```bash
python audit_mailbox.py samples/mailbox.mbox --timeline 10
```

### Python API
```python
import asyncio
from pqmail.auditor.batch_scorer import BatchScorer

async def audit():
    scorer = BatchScorer("samples/mailbox.mbox", quantum_timeline=10)
    stats = await scorer.score_all()
    scorer.print_summary()

asyncio.run(audit())
```

### Key Management
```python
from pqmail.keys.key_manager import KeyManager

km = KeyManager()
km.store_keys("alice@example.com", mlkem_pub_1184, x25519_pub_32)

keys = km.get_keys("alice@example.com")
print(f"Keys imported at: {keys.imported_at}")
```

### WebSocket Client
```python
import asyncio
import websockets

async def listen():
    async with websockets.connect("ws://localhost:8000/ws/events") as ws:
        while True:
            event = await ws.recv()
            print(f"Email: {event['from']} - {event['algorithm']}")

asyncio.run(listen())
```

---

## 🛠️ Tech Stack

| Layer | Tech | Version |
|-------|------|---------|
| **Email Gateway** | aiosmtpd | 1.4.6 |
| **Parser** | pgpy | 0.6.0 |
| **Crypto** | cryptography | 45.0.7 |
| **Backend** | FastAPI + Uvicorn | 0.109.0 + 0.27.0 |
| **Frontend** | React + Vite + Tailwind | 18.2 + 4.4.5 + 3.3.2 |
| **Testing** | pytest + pytest-asyncio | 8.3.4 + 0.25.0 |
| **Python** | 3.13+ | — |
| **Node.js** | 18+ | — |

---

## 🔒 Security Notes

- **Threat Model:** Harvest Now, Decrypt Later (long-term HNDL)
- **Cryptographic Basis:**
  - X25519 (ECDH) - NIST approved curve
  - ML-KEM-768 - NIST PQC standard
  - AES-256-GCM - Authenticated encryption
  - HKDF-SHA256 - Key derivation
- **No TLS** - LocalHost only (not Internet-exposed)
- **No Auth** - Demo/research tool, not production
- **In-Memory Only** - No persistent state to disk (MVP)

---

## 📊 Real-World Results

**Audit of samples/mailbox.mbox (54 emails):**
```
File: samples/mailbox.mbox (2.27 MB)
Messages: 54 total, 54 successfully parsed, 0 errors

Algorithm Distribution:
  UNENCRYPTED: 54 (100.0%)

Sensitivity Distribution:
  CRITICAL: 5 (9.3%)
  LOW: 44 (81.5%)
  MEDIUM: 5 (9.3%)

Risk Distribution:
  CRITICAL: 54 (100.0%)

Years of Safety:
  Average: 0.0 years
  Min: 0 years
  Max: 0 years

Actionable Findings:
  Critical Unencrypted Emails: 54
  Emails Needing Upgrade: 54
```

---

## ⚠️ Known Limitations

1. **ML-KEM-768** - Mocked implementation (real liboqs blocked by Windows cmake)
2. **Database** - In-memory only (no persistence)
3. **Authentication** - None (research tool)
4. **TLS** - Not used (localhost only)
5. **Re-encryption** - Placeholder only (Phase 2 feature)
6. **Report Generator** - Not yet implemented

---

## 🚦 Getting Help

**Common Issues:**

- **"Connection refused" on dashboard**
  ```bash
  # Start backend FIRST
  python run_backend.py
  # THEN start frontend
  cd frontend && npm run dev
  ```

- **Thunderbird won't connect**
  ```bash
  # Check port availability
  netstat -ano | findstr :1025
  ```

- **Tests failing**
  ```bash
  # Ensure venv activated
  .\cns-venv\Scripts\activate
  pytest .\tests\ -v
  ```

See [TESTING_WITH_THUNDERBIRD.md](docs/TESTING_WITH_THUNDERBIRD.md) for comprehensive troubleshooting.

---

## 📝 Citing This Work

```bibtex
@software{pqmail2026,
  title={PQMail: SMTP Proxy with Hybrid Post-Quantum Cryptography},
  author={Varghese, Angela and Sirohi, Arshia},
  year={2026},
  institution={RV College of Engineering},
  url={https://github.com/...},
  note={Research implementation for CNS (IS362IA)}
}
```

---

## 📄 License

Academic research tool. Educational use permitted.

---

## 🎓 Project Info

- **Course:** Cryptography and Network Security (IS362IA)
- **Institution:** RV College of Engineering, Bengaluru
- **Team:** Angela Varghese (1RV23IS014), Arshia Sirohi (1RV23IS022)
- **Status:** 7/8 modules complete, 104 tests passing

---

**Ready to test?** → [QUICKSTART.md](QUICKSTART.md)

**Need details?** → [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)

**Testing with email?** → [TESTING_WITH_THUNDERBIRD.md](docs/TESTING_WITH_THUNDERBIRD.md)
