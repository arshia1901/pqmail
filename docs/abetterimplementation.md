# PQMail — Implementation Plan
**Project:** SMTP Gateway with HNDL Risk Scoring and PQC Upgrade  
**Team:** Angela Varghese (1RV23IS014), Arshia Sirohi (1RV23IS022)  
**Institution:** RV College of Engineering, Bengaluru  
**Course:** Cryptography and Network Security — IS362IA, 2026  

---

## Quick Answers Before You Start

### Which PQC Algorithm Are You Using?

**ML-KEM-768** (defined in FIPS 203, August 2024) — this is the NIST-standardized post-quantum key encapsulation algorithm. It is based on module lattice cryptography and is quantum-resistant. You use it in a **hybrid composite** with X25519 (classical ECDH), so both must be broken simultaneously to compromise the message. This hybrid is specified in `draft-ietf-openpgp-pqc` and is what major systems (Apple PQ3, Signal SPQR) are moving toward.

| Level | Algorithm | When to use |
|---|---|---|
| Encryption (KEM) | **ML-KEM-768 + X25519** | Default — security level 2, practical overhead |
| Signing | **ML-DSA-65** | If you add signature support later |

Never use ML-KEM alone. Always use the hybrid. If ML-KEM is ever broken, X25519 still protects. If X25519 is broken by a quantum computer, ML-KEM still protects.

---

### Gmail or Thunderbird? How to Use Your Own Email

Use **both together**. Thunderbird is the email client. Gmail is the email account.

**Why Thunderbird and not just Gmail in the browser?**  
Gmail's web interface does not let you change the outgoing SMTP server. Thunderbird does — you point it to `localhost:1025` (your gateway) instead of `smtp.gmail.com`. Your gateway intercepts the email, processes it, then forwards it to Gmail's real SMTP server. Gmail itself never knows the gateway exists.

**Setup steps (do this in Week 1):**

1. **Create a Gmail App Password** — do not use your regular Gmail password for SMTP.  
   Go to: `myaccount.google.com → Security → 2-Step Verification → App Passwords`  
   Generate one for "Mail" + "Windows/Mac/Linux". Save it — you'll put it in your `.env` file.

2. **Install Thunderbird** — download from `thunderbird.net`. Add your Gmail account.

3. **Change outgoing SMTP in Thunderbird:**  
   `Account Settings → Outgoing Server (SMTP) → Edit`  
   - Server: `localhost`  
   - Port: `1025`  
   - Connection: None (your gateway handles TLS to Gmail upstream)  
   - Authentication: None  

4. **Your gateway's upstream config** (`config.toml`):
   ```toml
   [upstream]
   host = "smtp.gmail.com"
   port = 587
   user = "youraddress@gmail.com"
   password = "your-app-password-here"   # from Step 1
   ```

5. **For the mailbox auditor** — export your Gmail archive:  
   Go to `myaccount.google.com → Data & Privacy → Download your data`  
   Select only **Mail** → format: `.mbox` → download.  
   This gives you a real corpus of your own emails to scan for HNDL risk.

---

### Does the Gateway Need a Frontend? Yes — React

The gateway runs as a Python backend. The React frontend is a local web dashboard that shows:
- Live email events as they pass through the gateway (via WebSocket)
- Per-email risk scores and upgrade status
- A full audit report view for `.mbox` scanning

The backend exposes a **FastAPI** server alongside the SMTP proxy. React talks to it over HTTP + WebSocket on `localhost:8000`.

---

## Scope — What You Are and Are Not Building

### You ARE building:
1. **SMTP Proxy Gateway** — intercepts outgoing email from Thunderbird, runs the pipeline, forwards to Gmail
2. **HNDL Risk Scorer** — per-email "years of safety remaining" score
3. **Hybrid Re-encryption Engine** — upgrades RSA/ECDH encrypted emails to ML-KEM-768 + X25519
4. **React Dashboard** — live view of gateway activity and audit results
5. **Mailbox Auditor** — scans `.mbox` file (your Gmail export), generates risk report

### You are NOT building:
- A full email client (Thunderbird handles that)
- A key server or PKI (keys are local files)
- An S/MIME implementation (OpenPGP only)
- A cloud deployment (everything runs on your laptop)

---

## System Architecture

```
[Thunderbird]
     |
     | SMTP to localhost:1025
     ↓
[PQMail SMTP Proxy]  ←→  [FastAPI Backend :8000]  ←→  [React Dashboard :3000]
     |                          |                            |
     | pipeline:                | WebSocket stream           | Live events
     |  1. Parse MIME           | REST endpoints             | Risk table
     |  2. Score HNDL           |                            | Audit view
     |  3. Re-encrypt (hybrid)  |
     |  4. Forward upstream     |
     ↓
[Gmail smtp.gmail.com:587]
     ↓
[Recipient's inbox]
```

---

## Technology Stack

| Component | Library | Version | Why |
|---|---|---|---|
| SMTP Proxy | `aiosmtpd` | 1.4.4+ | Async SMTP server, intercepts email |
| OpenPGP Parsing | `pgpy` | 0.6.0+ | Parse PGP blocks, detect algorithms |
| Post-Quantum KEM | `liboqs-python` | 0.10.0+ | ML-KEM-768 keygen, encap, decap |
| Classical Crypto | `cryptography` | 41.0.0+ | X25519, AES-256-GCM, HKDF |
| API Backend | `fastapi` + `uvicorn` | 0.104.0+ | REST + WebSocket for React |
| WebSocket | `websockets` | 12.0+ | Push live events to dashboard |
| Report Templating | `jinja2` | 3.1.0+ | HTML report for audit mode |
| CLI | `click` | 8.1.0+ | `pqmail audit`, `pqmail start` commands |
| Config | `python-dotenv` | 1.0.0+ | Credentials from `.env`, never hardcoded |
| React Frontend | React 18 + Vite | Latest | Dashboard UI |
| React Styling | Tailwind CSS | 3.x | Fast styling |
| React WebSocket | native `WebSocket` API | — | Receive live gateway events |
| Testing | `pytest` + `pytest-asyncio` | 7.4.0+ | Unit + async integration tests |

---

## Folder Structure

```
pqmail/
│
├── .env.example                  # Template — NEVER commit .env
├── .gitignore                    # Includes .env, keys/, __pycache__
├── config.toml                   # Upstream SMTP, ports, timeline
├── requirements.txt
├── README.md
│
├── pqmail/                       # Python backend package
│   ├── __init__.py
│   │
│   ├── gateway/
│   │   ├── proxy.py              # aiosmtpd handler — entry point
│   │   └── forwarder.py          # Relay to Gmail upstream
│   │
│   ├── parser/
│   │   ├── mime_parser.py        # MIME structure, extract PGP blocks
│   │   └── pgp_classifier.py     # Detect RSA / ECDH / HYBRID / NONE
│   │
│   ├── scorer/
│   │   └── hndl_scorer.py        # years_of_safety = D - T + modifier
│   │
│   ├── classifier/
│   │   └── rule_classifier.py    # Keyword → LOW/MEDIUM/HIGH/CRITICAL
│   │
│   ├── crypto/
│   │   ├── mlkem.py              # ML-KEM-768 keygen / encap / decap
│   │   ├── ecdh.py               # X25519 key exchange
│   │   ├── hybrid_kem.py         # ML-KEM + X25519 → HKDF → derived key
│   │   └── symmetric.py          # AES-256-GCM encrypt/decrypt
│   │
│   ├── keys/
│   │   ├── key_manager.py        # Load, validate, lookup keys
│   │   └── store/
│   │       ├── mlkem/            # recipient@email.com.pub.bin
│   │       └── classical/        # recipient@email.com.asc
│   │
│   ├── fallback/
│   │   └── decision.py           # Route: UPGRADE / FORWARD / FLAG
│   │
│   ├── auditor/
│   │   ├── mbox_reader.py        # Parse .mbox, score every message
│   │   └── batch_scorer.py       # CLI entry point: pqmail audit
│   │
│   ├── api/
│   │   ├── app.py                # FastAPI app with REST + WebSocket
│   │   └── events.py             # Event queue between proxy and API
│   │
│   └── report/
│       ├── report_generator.py
│       └── templates/
│           └── risk_report.html.j2
│
├── frontend/                     # React dashboard (Vite)
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── App.jsx
│       ├── components/
│       │   ├── GatewayStatus.jsx     # Live gateway on/off indicator
│       │   ├── LiveEmailFeed.jsx     # Real-time table of emails passing through
│       │   ├── RiskBadge.jsx         # Color-coded CRITICAL/HIGH/MEDIUM/LOW
│       │   ├── AuditUploader.jsx     # Drop .mbox file → run audit
│       │   └── AuditReport.jsx       # Paginated sorted risk table
│       └── hooks/
│           └── useGatewaySocket.js   # WebSocket connection hook
│
├── tests/
│   ├── conftest.py               # Shared fixtures: test keys, sample emails
│   ├── test_parser.py
│   ├── test_scorer.py
│   ├── test_crypto.py
│   ├── test_fallback.py
│   └── test_auditor.py
│
└── samples/
    ├── emails/                   # .eml files: rsa.eml, ecdh.eml, hybrid.eml, plain.eml
    ├── keys/                     # Pre-generated demo key pairs
    └── mailbox.mbox              # Sample archive for demo
```

---

## Module Implementation Plan

### Module 1 — SMTP Proxy Gateway (`gateway/proxy.py`)

This is the core of the project. It is a local SMTP server that Thunderbird connects to instead of Gmail. Every outgoing email passes through it.

**What it does per email:**
1. Receive raw SMTP session from Thunderbird
2. Extract the raw email bytes
3. Pass through the processing pipeline (parse → score → decide → optionally re-encrypt)
4. Push the event to the FastAPI event queue (so React can display it)
5. Forward the final email to Gmail
6. Return `250 OK` to Thunderbird

```python
# gateway/proxy.py

import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage
from pqmail.parser.mime_parser import parse
from pqmail.scorer.hndl_scorer import score
from pqmail.classifier.rule_classifier import classify
from pqmail.fallback.decision import decide
from pqmail.crypto.hybrid_kem import re_encrypt_message
from pqmail.gateway.forwarder import forward
from pqmail.api.events import push_event

class PQMailHandler(AsyncMessage):

    async def handle_DATA(self, server, session, envelope) -> str:
        raw: bytes = envelope.content
        mail_from: str = envelope.mail_from
        rcpt_tos: list[str] = envelope.rcpt_tos

        # 1. Parse
        parsed = await parse(raw)

        # 2. Classify content sensitivity from headers only
        sensitivity = classify(parsed.headers.get("subject_hint", ""))

        # 3. Score HNDL risk
        risk = score(parsed.algorithm, sensitivity, quantum_timeline=10)

        # 4. Decide action
        action = decide(parsed, rcpt_tos)

        # 5. Re-encrypt if needed (in memory only, never to disk)
        final_bytes = raw
        if action["action"] == "UPGRADE":
            final_bytes = await re_encrypt_message(parsed, rcpt_tos)
            risk["upgraded"] = True
        else:
            risk["upgraded"] = False

        # 6. Push event to React dashboard
        await push_event({
            "message_id": parsed.headers.get("message_id", "unknown"),
            "from": mail_from,
            "to": rcpt_tos,
            "algorithm": parsed.algorithm,
            "risk": risk,
            "flag": action["flag"],
        })

        # 7. Forward to Gmail — NEVER log plaintext
        await forward(final_bytes, mail_from, rcpt_tos)
        return "250 Message accepted"


def start_gateway(config: dict):
    handler = PQMailHandler()
    controller = Controller(handler, hostname="127.0.0.1", port=config["listen_port"])
    controller.start()
    print(f"[PQMail] Gateway listening on localhost:{config['listen_port']}")
    asyncio.get_event_loop().run_forever()
```

```python
# gateway/forwarder.py — relay to Gmail with STARTTLS

import smtplib, ssl, os

def forward(message_bytes: bytes, mail_from: str, rcpt_tos: list):
    host = os.getenv("UPSTREAM_HOST", "smtp.gmail.com")
    port = int(os.getenv("UPSTREAM_PORT", 587))
    user = os.getenv("UPSTREAM_USER")
    password = os.getenv("UPSTREAM_PASSWORD")

    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ctx)
        smtp.login(user, password)
        smtp.sendmail(mail_from, rcpt_tos, message_bytes)
```

---

### Module 2 — MIME + OpenPGP Parser (`parser/`)

Reads raw email bytes and identifies what encryption algorithm is protecting it. This is purely read-only — it does not modify anything.

**Algorithm detection logic:**
- Look for `Content-Type: multipart/encrypted` or `application/pgp-encrypted` in MIME headers
- Extract the PGP armored block
- Inspect the `PublicKeyEncryptedSessionKey` (PKESK) packet's algorithm field
- Map algorithm ID → human-readable label

| PGP Algorithm ID | Maps to |
|---|---|
| 1, 2, 3 | `RSA` |
| 18 | `ECDH` |
| 25, 29 | `HYBRID` (ML-KEM composite, per draft) |
| No PGP block | `UNENCRYPTED` |

```python
# parser/pgp_classifier.py

import pgpy

def classify_algorithm(pgp_message: pgpy.PGPMessage) -> str:
    for packet in pgp_message.packets:
        if hasattr(packet, "pkalg"):
            alg = int(packet.pkalg)
            if alg in (1, 2, 3):
                return "RSA"
            elif alg == 18:
                return "ECDH"
            elif alg in (25, 29):
                return "HYBRID"
    return "SIGNED_ONLY"
```

**Output — ParsedEmail dataclass:**
```python
@dataclass
class ParsedEmail:
    raw_bytes: bytes            # Original bytes — untouched
    headers: dict               # From, To, Message-ID only (no body content)
    algorithm: str              # RSA | ECDH | HYBRID | UNENCRYPTED | SIGNED_ONLY
    pgp_message: object | None  # pgpy object for re-encryption
    is_encrypted: bool
    parse_error: str | None
```

---

### Module 3 — HNDL Risk Scorer (`scorer/hndl_scorer.py`)

Computes the concrete "years of safety remaining" metric for each email. This is the research contribution of the project — it takes three inputs and produces a single actionable number.

**The formula:**
```
years_of_safety = max(0, D - T + sensitivity_modifier)
```

Where:
- `D` = algorithm safety horizon (how many years until a CRQC breaks it)
- `T` = quantum timeline assumption (user configures: 5, 10, or 15 years)
- `sensitivity_modifier` = adjustment based on content sensitivity

**Algorithm Safety Horizons (D):**

| Algorithm | D (years) | Reasoning |
|---|---|---|
| RSA-2048 | 5 | First to fall to Shor's algorithm at scale |
| RSA-4096 | 8 | Marginally longer, same fundamental flaw |
| ECDH / X25519 | 7 | Elliptic curve discrete log → Shor's |
| ML-KEM + ECDH (Hybrid) | 50+ | PQC component defeats quantum attack |
| Unencrypted | 0 | No algorithmic protection at all |

**Sensitivity Modifier:**

| Sensitivity | Modifier | Reasoning |
|---|---|---|
| LOW | +2 years | Content expires fast, lower urgency |
| MEDIUM | 0 | Baseline, no adjustment |
| HIGH | −3 years | Confidential content, shorter safety window |
| CRITICAL | −6 years | Treat as already at risk |

**Risk Category Output:**

| years_of_safety | Category |
|---|---|
| 0 | CRITICAL |
| 1–3 | HIGH |
| 4–7 | MEDIUM |
| 8+ | LOW |

```python
# scorer/hndl_scorer.py

ALGORITHM_D = {
    "RSA": 5, "ECDH": 7, "HYBRID": 50,
    "UNENCRYPTED": 0, "SIGNED_ONLY": 0, "PARSE_ERROR": 0,
}
SENSITIVITY_MOD = {"LOW": 2, "MEDIUM": 0, "HIGH": -3, "CRITICAL": -6}

def score(algorithm: str, sensitivity: str, quantum_timeline: int = 10) -> dict:
    D = ALGORITHM_D.get(algorithm, 0)
    mod = SENSITIVITY_MOD.get(sensitivity, 0)
    years = max(0, D - quantum_timeline + mod)
    return {
        "algorithm": algorithm,
        "sensitivity": sensitivity,
        "quantum_timeline_years": quantum_timeline,
        "years_of_safety_remaining": years,
        "risk_category": _category(years),
        "recommended_action": _action(algorithm, years),
    }

def _category(years: int) -> str:
    if years == 0: return "CRITICAL"
    if years <= 3: return "HIGH"
    if years <= 7: return "MEDIUM"
    return "LOW"

def _action(algorithm: str, years: int) -> str:
    if algorithm == "HYBRID":
        return "No action required — message is quantum-safe."
    if algorithm == "UNENCRYPTED":
        return "Enable encryption immediately."
    if years == 0:
        return "URGENT: Re-encrypt with ML-KEM-768+X25519 hybrid. Assume already harvested."
    if years <= 3:
        return "Re-encrypt soon. Upgrade to PQC hybrid before quantum timeline."
    return "Monitor. Upgrade when ML-KEM key for recipient becomes available."
```

---

### Module 4 — Hybrid Cryptography Engine (`crypto/`)

This is the cryptographic core. When the gateway decides to upgrade an email, this module performs the actual hybrid ML-KEM-768 + X25519 re-encryption.

**The composite hybrid construction:**

```
Step 1: ML-KEM encapsulation
  ct_mlkem, ss_mlkem = ML-KEM-768.encap(recipient_mlkem_pubkey)

Step 2: X25519 key exchange
  eph_priv = X25519PrivateKey.generate()
  ss_ecdh = eph_priv.exchange(recipient_x25519_pubkey)

Step 3: Combine shared secrets → symmetric key
  ss_combined = ss_mlkem || ss_ecdh
  symmetric_key = HKDF-SHA256(ss_combined, info="PQMail-v1", length=32)

Step 4: Encrypt message body
  nonce = random 12 bytes
  ciphertext = AES-256-GCM(symmetric_key, nonce, plaintext)

Step 5: Package output
  output = ct_mlkem || eph_pub_x25519 || nonce || ciphertext
```

Both shared secrets must be present for decryption. Breaking only one is not enough.

```python
# crypto/mlkem.py
import oqs

def generate_keypair(variant="ML-KEM-768") -> tuple[bytes, bytes]:
    kem = oqs.KeyEncapsulation(variant)
    pub = kem.generate_keypair()
    sec = kem.export_secret_key()
    return pub, sec

def encapsulate(pub_key: bytes, variant="ML-KEM-768") -> tuple[bytes, bytes]:
    kem = oqs.KeyEncapsulation(variant)
    ct, ss = kem.encap_secret(pub_key)
    return ct, ss

def decapsulate(sec_key: bytes, ct: bytes, variant="ML-KEM-768") -> bytes:
    kem = oqs.KeyEncapsulation(variant, secret_key=sec_key)
    return kem.decap_secret(ct)
```

```python
# crypto/hybrid_kem.py
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqmail.crypto.mlkem import encapsulate

def hybrid_encrypt(plaintext: bytes, mlkem_pub: bytes, x25519_pub) -> bytes:
    # ML-KEM component
    ct_mlkem, ss_mlkem = encapsulate(mlkem_pub)

    # X25519 component
    eph = X25519PrivateKey.generate()
    ss_ecdh = eph.exchange(x25519_pub)
    eph_pub_bytes = eph.public_key().public_bytes_raw()

    # Derive symmetric key
    key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"PQMail-HybridKEM-v1"
    ).derive(ss_mlkem + ss_ecdh)

    # AES-256-GCM
    nonce = os.urandom(12)
    ct_body = AESGCM(key).encrypt(nonce, plaintext, None)

    # Package: [mlkem_ct_len(4)] [mlkem_ct] [eph_x25519_pub(32)] [nonce(12)] [ct_body]
    mlkem_len = len(ct_mlkem).to_bytes(4, "big")
    return mlkem_len + ct_mlkem + eph_pub_bytes + nonce + ct_body


def hybrid_decrypt(package: bytes, mlkem_sec: bytes, x25519_priv) -> bytes:
    from pqmail.crypto.mlkem import decapsulate
    mlkem_len = int.from_bytes(package[:4], "big")
    ct_mlkem = package[4:4+mlkem_len]
    offset = 4 + mlkem_len
    eph_pub_bytes = package[offset:offset+32]
    nonce = package[offset+32:offset+44]
    ct_body = package[offset+44:]

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)

    ss_mlkem = decapsulate(mlkem_sec, ct_mlkem)
    ss_ecdh = x25519_priv.exchange(eph_pub)

    key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"PQMail-HybridKEM-v1"
    ).derive(ss_mlkem + ss_ecdh)

    return AESGCM(key).decrypt(nonce, ct_body, None)
```

---

### Module 5 — FastAPI Backend + WebSocket (`api/app.py`)

The backend bridges the Python gateway and the React frontend. It runs alongside the SMTP proxy.

**Endpoints:**

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/status` | Gateway running status |
| `GET` | `/api/config` | Current quantum timeline setting |
| `POST` | `/api/config` | Update timeline (5/10/15 years) |
| `POST` | `/api/audit` | Upload `.mbox` file, returns risk data |
| `GET` | `/api/keys` | List known recipient ML-KEM keys |
| `WebSocket` | `/ws/events` | Real-time email event stream to React |

```python
# api/app.py
from fastapi import FastAPI, WebSocket, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pqmail.api.events import event_queue
import asyncio, json

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000"],
                   allow_methods=["*"], allow_headers=["*"])

active_websockets: list[WebSocket] = []

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    await ws.accept()
    active_websockets.append(ws)
    try:
        while True:
            event = await event_queue.get()
            await ws.send_text(json.dumps(event))
    except Exception:
        active_websockets.remove(ws)

@app.post("/api/audit")
async def audit_mbox(file: UploadFile):
    from pqmail.auditor.mbox_reader import audit_mbox
    content = await file.read()
    # Write to temp file for mailbox.mbox parsing
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".mbox") as f:
        f.write(content)
        tmp_path = f.name
    results = await audit_mbox(tmp_path)
    os.unlink(tmp_path)
    return {"results": results, "total": len(results)}
```

```python
# api/events.py
import asyncio
event_queue: asyncio.Queue = asyncio.Queue()

async def push_event(event: dict):
    await event_queue.put(event)
```

---

### Module 6 — React Dashboard (`frontend/`)

The dashboard has three views:

**View 1 — Live Gateway Feed**  
Real-time table updated via WebSocket. Every email that passes through the gateway appears here within milliseconds. Columns: From, To, Algorithm Detected, Risk Category, Action Taken (UPGRADED / FORWARDED / FLAGGED), Years Safe.

**View 2 — Mailbox Audit**  
Upload your `.mbox` file (Gmail Takeout export). The React component posts it to `/api/audit` and renders the returned sorted risk table. CRITICAL emails at top in red, LOW at bottom in green.

**View 3 — Key Manager**  
List of recipients for whom ML-KEM keys are registered. Option to add a new recipient key (paste public key bytes).

```jsx
// frontend/src/hooks/useGatewaySocket.js
import { useEffect, useState } from "react";

export function useGatewaySocket() {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8000/ws/events");
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (e) => {
      const event = JSON.parse(e.data);
      setEvents(prev => [event, ...prev].slice(0, 100)); // keep last 100
    };
    return () => ws.close();
  }, []);

  return { events, connected };
}
```

```jsx
// frontend/src/components/RiskBadge.jsx
const COLORS = {
  CRITICAL: "bg-red-900 text-red-200",
  HIGH:     "bg-orange-900 text-orange-200",
  MEDIUM:   "bg-yellow-900 text-yellow-200",
  LOW:      "bg-green-900 text-green-200",
};

export function RiskBadge({ category }) {
  return (
    <span className={`px-2 py-1 rounded text-xs font-mono font-bold ${COLORS[category]}`}>
      {category}
    </span>
  );
}
```

```jsx
// frontend/src/components/LiveEmailFeed.jsx
import { useGatewaySocket } from "../hooks/useGatewaySocket";
import { RiskBadge } from "./RiskBadge";

export function LiveEmailFeed() {
  const { events, connected } = useGatewaySocket();

  return (
    <div>
      <div className="flex items-center gap-2 mb-4">
        <div className={`w-2 h-2 rounded-full ${connected ? "bg-green-400" : "bg-red-400"}`} />
        <span className="text-sm text-gray-400">
          {connected ? "Gateway connected" : "Gateway offline"}
        </span>
      </div>
      <table className="w-full text-sm font-mono">
        <thead>
          <tr className="text-left text-blue-300 border-b border-gray-700">
            <th className="pb-2">From</th>
            <th className="pb-2">Algorithm</th>
            <th className="pb-2">Risk</th>
            <th className="pb-2">Years Safe</th>
            <th className="pb-2">Action</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={i} className="border-b border-gray-800">
              <td className="py-2">{e.from}</td>
              <td className="py-2">{e.algorithm}</td>
              <td className="py-2"><RiskBadge category={e.risk.risk_category} /></td>
              <td className="py-2">{e.risk.years_of_safety_remaining}y</td>
              <td className="py-2 text-xs">{e.flag}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

---

## Implementation Phases

### Phase 1 — Environment Setup (Days 1–2, ~6 hours)

- Install Python 3.11, Node 20, GCC, CMake
- Build and install `liboqs` from source:
  ```bash
  git clone https://github.com/open-quantum-safe/liboqs.git
  cd liboqs && mkdir build && cd build
  cmake -DBUILD_SHARED_LIBS=ON .. && make -j4 && sudo make install
  pip install liboqs-python
  ```
- Verify: `python -c "import oqs; kem = oqs.KeyEncapsulation('ML-KEM-768'); print('OK')"`
- Install all Python deps: `pip install aiosmtpd pgpy fastapi uvicorn cryptography click python-dotenv jinja2`
- Scaffold folder structure; create empty modules with docstrings
- Set up Vite React project: `npm create vite@latest frontend -- --template react && cd frontend && npm install tailwindcss`

**Deliverable:** `liboqs` verified working, all deps installed, folder structure committed

---

### Phase 2 — Thunderbird + Gmail Integration (Days 2–3, ~4 hours)

- Create Gmail App Password as described above
- Configure Thunderbird to use `localhost:1025`
- Write `config.toml` and `.env` with Gmail credentials
- Run `aiosmtpd` stub proxy on port 1025, confirm Thunderbird connects
- Confirm email is relayed to Gmail via `forwarder.py`

**Deliverable:** Thunderbird → `localhost:1025` → Gmail working end-to-end, unmodified passthrough

---

### Phase 3 — Parser + Scorer (Days 3–5, ~10 hours)

- Implement `mime_parser.py`: MIME walk, PGP block extraction
- Implement `pgp_classifier.py`: algorithm detection (RSA/ECDH/HYBRID/UNENCRYPTED)
- Implement `rule_classifier.py`: keyword sensitivity classification
- Implement `hndl_scorer.py`: full formula with all D values and modifiers
- Create fixture `.eml` files for all algorithm types in `samples/emails/`
- Write `test_parser.py` and `test_scorer.py`; run `pytest` — all green

**Deliverable:** Parser correctly identifies algorithm from any test email; scorer produces correct risk record

---

### Phase 4 — Hybrid Crypto Engine (Days 5–8, ~12 hours)

- Implement `mlkem.py`, `ecdh.py`, `hybrid_kem.py`, `symmetric.py`
- Write standalone proof-of-concept script:
  ```bash
  python scripts/crypto_poc.py
  # Should print: "Round-trip OK. Plaintext matches."
  ```
- Write `test_crypto.py` with round-trip and tamper-detection tests
- Implement `key_manager.py` + key store for local demo keys
- Generate demo ML-KEM-768 keypairs: `python scripts/keygen.py alice@example.com`

**Deliverable:** `hybrid_encrypt(plaintext)` → `hybrid_decrypt(...)` = original plaintext, verified by test

---

### Phase 5 — Full Gateway Pipeline (Days 8–11, ~10 hours)

- Wire all modules into `gateway/proxy.py` `handle_DATA`
- Implement `fallback/decision.py` with full decision matrix
- Implement `api/events.py` and `api/app.py` (FastAPI + WebSocket)
- Run SMTP proxy + FastAPI together:
  ```bash
  python -m pqmail.gateway.proxy &    # port 1025
  uvicorn pqmail.api.app:app &        # port 8000
  ```
- Send a test RSA-encrypted email from Thunderbird; confirm in console: `UPGRADED` flag appears

**Deliverable:** Full pipeline working — email enters as RSA-encrypted, exits as hybrid-encrypted

---

### Phase 6 — React Frontend (Days 11–14, ~10 hours)

- Build `LiveEmailFeed.jsx` with WebSocket hook
- Build `AuditUploader.jsx` with `.mbox` file upload
- Build `AuditReport.jsx` with sorted, color-coded risk table
- Build `GatewayStatus.jsx` and `RiskBadge.jsx`
- Connect all views in `App.jsx`
- Style with Tailwind — dark theme, monospace font (security tool aesthetic)

**Deliverable:** React dashboard showing real-time events and audit results, live demo ready

---

### Phase 7 — Mailbox Auditor (Days 14–16, ~8 hours)

- Implement `mbox_reader.py`: iterate every message in `.mbox`, run parse + score per message
- Implement `batch_scorer.py` CLI: `pqmail audit mymail.mbox --timeline 10`
- Wire auditor into `/api/audit` endpoint so React can trigger it via file upload
- Export your own Gmail via Google Takeout; run auditor on it
- Record statistics: N total, M encrypted, K vulnerable — these are your paper's empirical results

**Deliverable:** `pqmail audit` produces sorted risk list from your own Gmail export

---

### Phase 8 — Testing + Benchmarking (Days 16–19, ~8 hours)

- Run full test suite: `pytest tests/ -v --cov=pqmail` — target > 60% coverage
- Benchmark gateway latency for 50 emails: record average and max ms
- Benchmark auditor throughput: messages per second on 500-email `.mbox`
- Confirm NFR2: grep all log statements for any body/content/subject output — must be zero

**Deliverable:** Performance numbers documented (these go in your paper as Table 2)

---

### Phase 9 — Paper + Demo (Days 19–21, ~8 hours)

- Write paper sections in order: Introduction → Background → Design → Implementation → Evaluation → Related Work → Conclusion
- Prepare live demo script following the 8-step demo plan
- Record demo video as backup

**Deliverable:** Final paper draft + demo ready for evaluation

---

## Testing Plan

### Unit Tests

```bash
pytest tests/test_parser.py      # Algorithm classification on all fixture emails
pytest tests/test_scorer.py      # Risk formula: all algorithm × sensitivity × timeline combos
pytest tests/test_crypto.py      # Round-trip encrypt/decrypt; tamper detection
pytest tests/test_fallback.py    # All 7 rows of the decision matrix
pytest tests/test_auditor.py     # Correct count + sort order from sample .mbox
```

### Integration Test — Send Real Email Through Gateway

```bash
# Terminal 1: run gateway
python -m pqmail start

# Terminal 2: send test email via swaks
swaks --to alice@demo.com --from you@gmail.com \
      --server localhost:1025 \
      --attach samples/emails/rsa_encrypted.eml

# Assert in gateway console output:
# [PQMail] algorithm=RSA | risk=HIGH | years=2 | flag=UPGRADED
```

### Crypto Round-Trip Test

```python
# tests/test_crypto.py
def test_hybrid_roundtrip():
    from pqmail.crypto.mlkem import generate_keypair
    from pqmail.crypto.hybrid_kem import hybrid_encrypt, hybrid_decrypt
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    mlkem_pub, mlkem_sec = generate_keypair()
    x25519_priv = X25519PrivateKey.generate()
    x25519_pub = x25519_priv.public_key()

    plaintext = b"Sensitive financial contract — do not share."
    package = hybrid_encrypt(plaintext, mlkem_pub, x25519_pub)
    recovered = hybrid_decrypt(package, mlkem_sec, x25519_priv)

    assert recovered == plaintext
```

### Performance Benchmark

```python
# tests/test_performance.py
import time, pytest

@pytest.mark.benchmark
def test_hybrid_encrypt_latency():
    # Run 50 encryptions, assert max < 200ms
    times = []
    for _ in range(50):
        t = time.perf_counter()
        hybrid_encrypt(b"x" * 10000, mlkem_pub, x25519_pub)
        times.append((time.perf_counter() - t) * 1000)

    print(f"Avg: {sum(times)/len(times):.1f}ms | Max: {max(times):.1f}ms")
    assert max(times) < 200
```

---

## Security Rules — Non-Negotiable

These must be enforced before demo or submission:

1. **Plaintext never touches disk.** All email body content lives in memory only during `handle_DATA`. No `open()`, no `f.write()`, no temp files with email content.
2. **No content in logs.** Log only: algorithm name, message ID, risk score, flag. Never log subject, body, or key material.
3. **Passphrase from env only.** `PQMAIL_KEY_PASSPHRASE = os.getenv("PQMAIL_KEY_PASSPHRASE")`. Never hardcode.
4. **Validate keys before use.** Run `validate_mlkem_key()` before every encapsulation. Reject malformed keys — do not crash.
5. **Forward on failure.** If any step fails — parsing, scoring, crypto — catch the exception, forward the original email unchanged, log the error type only (not content).

```bash
# Security audit command — run before submission
grep -rn "print\|logger\|logging" pqmail/ | grep -iE "body|subject|plain|content|key"
# Must return zero matches
```

---

## Environment Variables (`.env`)

```env
# .env — NEVER commit this file
UPSTREAM_HOST=smtp.gmail.com
UPSTREAM_PORT=587
UPSTREAM_USER=youraddress@gmail.com
UPSTREAM_PASSWORD=xxxx-xxxx-xxxx-xxxx    # Gmail App Password

PQMAIL_KEY_PASSPHRASE=your-pgp-key-passphrase
PQMAIL_KEY_STORE=./pqmail/keys/store
PQMAIL_LISTEN_PORT=1025
PQMAIL_API_PORT=8000
QUANTUM_TIMELINE_YEARS=10
```

---

## MVP Checklist — Minimum to Pass Evaluation

| Component | Required |
|---|---|
| Thunderbird → gateway → Gmail passthrough | ✅ |
| Algorithm detection (RSA / ECDH / HYBRID / UNENCRYPTED) | ✅ |
| HNDL risk score with years-of-safety output | ✅ |
| Hybrid ML-KEM-768 + X25519 re-encryption (round-trip working) | ✅ |
| Fallback logic (no ML-KEM key → forward unchanged) | ✅ |
| FastAPI backend with WebSocket | ✅ |
| React dashboard: live email feed + risk badges | ✅ |
| `.mbox` auditor + React upload + risk table | ✅ |
| Demo with real Gmail account | ✅ |
| Pytest suite > 60% coverage | ✅ |

**Stretch goals (do after MVP is solid):**
- ML-based sensitivity classifier (TF-IDF + Naive Bayes on Enron corpus)
- Live IMAP connection for auditor (instead of `.mbox` file upload)
- Key manager UI in React (add/remove recipient ML-KEM keys from dashboard)

---

## Paper Empirical Results — What to Measure and Report

These numbers come from running your own tools. You fill them in from your experiments.

**Table 1 — Mailbox HNDL Audit Results (from your Gmail export)**

| Metric | Value |
|---|---|
| Total emails scanned | [N] |
| Encrypted emails | [M] ([M/N]%) |
| Encrypted with vulnerable algorithm (RSA or ECDH) | [K] ([K/M]%) |
| Already hybrid-encrypted | [J] |
| Unencrypted | [L] |
| Median years of safety remaining (10-year timeline) | [Y] |
| Emails with 0 years remaining (CRITICAL) | [C] |

**Table 2 — Gateway Performance Benchmarks**

| Operation | Average Latency | Max Latency |
|---|---|---|
| Parse + score (no re-encrypt) | [X] ms | [X] ms |
| Full hybrid re-encrypt (ML-KEM-768) | [X] ms | [X] ms |
| Auditor throughput | [X] msgs/sec | — |

These two tables are the experimental section of your paper.

---

## Running the Complete System

```bash
# 1. Start the gateway + API backend (one command)
python -m pqmail start
# Output:
# [PQMail] Gateway listening on localhost:1025
# [PQMail] API server on localhost:8000

# 2. Start React frontend
cd frontend && npm run dev
# Dashboard at http://localhost:3000

# 3. Send email from Thunderbird — it appears live in the dashboard

# 4. Audit your Gmail export
# Drop your .mbox file into the Audit tab in the React dashboard
# Risk table renders sorted by CRITICAL → LOW

# 5. Run auditor from CLI directly
python -m pqmail audit ~/Downloads/gmail-export.mbox --timeline 10
# Output: risk_report.html
```

---

*PQMail — Angela Varghese (1RV23IS014) and Arshia Sirohi (1RV23IS022)*  
*RV College of Engineering — Cryptography and Network Security IS362IA, 2026*
