# PQMail Implementation Plan

**Project Title:** PQMail: SMTP Proxy with Hybrid PQC (Post-Quantum Cryptography) Implementation and HNDL (Harvest Now Decrypt Later) Risk Assessment  
**Team:** Angela Varghese (1RV23IS014), Arshia Sirohi (1RV23IS022)  
**Institution:** RV College of Engineering, Bengaluru – 59  
**Department:** Information Science and Engineering  
**Course:** Cryptography and Network Security (IS362IA)  
**Document Version:** 1.0

---

## Table of Contents

1. [Assumptions](#1-assumptions)
2. [Technology Stack](#2-technology-stack)
3. [Folder Structure](#3-folder-structure)
4. [Module-wise Implementation Plan](#4-module-wise-implementation-plan)
   - 4.1 [SMTP Proxy Gateway](#41-smtp-proxy-gateway)
   - 4.2 [MIME and OpenPGP Parser](#42-mime-and-openpgp-parser)
   - 4.3 [HNDL Risk Scorer](#43-hndl-risk-scorer)
   - 4.4 [Content Sensitivity Classifier](#44-content-sensitivity-classifier)
   - 4.5 [Hybrid Cryptography Module](#45-hybrid-cryptography-module)
   - 4.6 [Key Manager](#46-key-manager)
   - 4.7 [Fallback Logic](#47-fallback-logic)
   - 4.8 [Mailbox Auditor](#48-mailbox-auditor)
   - 4.9 [HTML Risk Report Generator](#49-html-risk-report-generator)
5. [Implementation Phases](#5-implementation-phases)
6. [Testing Plan](#6-testing-plan)
7. [Security Considerations](#7-security-considerations)
8. [Performance Considerations](#8-performance-considerations)
9. [Demo Plan](#9-demo-plan)
10. [Risks and Mitigation](#10-risks-and-mitigation)
11. [Minimum Viable Product (MVP)](#11-minimum-viable-product-mvp)
12. [Final Deliverables](#12-final-deliverables)

---

## 1. Assumptions

The following assumptions apply to the design and development of PQMail:

**Email Client Configuration**

- The user's email client (e.g., Thunderbird, Mutt, or any SMTP-capable client) can be configured to use `localhost` (127.0.0.1) as the outgoing SMTP server on a custom port (e.g., 1025).
- The client is already configured to send OpenPGP-encrypted messages or plaintext; PQMail does not manage key generation for the client directly.

**Local SMTP Proxy**

- PQMail runs on the same machine as the user's email client (localhost deployment).
- The upstream external SMTP server credentials (host, port, username, password) are provided via a configuration file (`config.toml` or `.env`).
- TLS/STARTTLS is used for the connection from PQMail to the upstream SMTP server.

**Key Availability**

- Recipient ML-KEM public keys are stored locally in a key store directory (`keys/mlkem/`), indexed by email address.
- Classical (RSA/ECDH) public keys are available via GPG keyring or bundled PGP armored key files.
- The sender's classical private key is accessible to the gateway for decryption/re-encryption during hybrid upgrade; its passphrase is read from the environment variable `PQMAIL_KEY_PASSPHRASE`.

**.mbox Input**

- The mailbox auditor accepts standard `.mbox` format files (RFC 4155), as exported from email clients such as Thunderbird or downloadable from Gmail.
- The Enron email corpus or similar datasets may be used for testing and demonstration.

**Demo Environment**

- All development and testing is done on a 64-bit Linux (Ubuntu 22.04+) or macOS 13+ machine.
- Python 3.11 is used as the target runtime.
- `liboqs` is compiled from source with CMake prior to installing `liboqs-python`.
- No real production email accounts are used during demos; all test SMTP sessions use local or sandbox credentials.

---

## 2. Technology Stack

| Component           | Technology / Library        | Version  | Purpose                                                               |
| ------------------- | --------------------------- | -------- | --------------------------------------------------------------------- |
| Runtime             | Python                      | 3.11+    | Primary language for all modules                                      |
| SMTP Proxy Core     | aiosmtpd                    | 1.4.4+   | Async SMTP server; intercepts outgoing mail from email client         |
| OpenPGP Parsing     | pgpy                        | 0.6.0+   | Parse, inspect, decrypt, and construct PGP-armored messages           |
| Post-Quantum KEM    | liboqs-python               | 0.10.0+  | ML-KEM-768 / ML-KEM-1024 key generation, encapsulation, decapsulation |
| Classical Crypto    | cryptography                | 41.0.0+  | X25519 ECDH, AES-256-GCM symmetric encryption, HKDF key derivation    |
| ML Classifier       | scikit-learn                | 1.3.0+   | TF-IDF + Naive Bayes / SVM for content sensitivity classification     |
| Report Templating   | jinja2                      | 3.1.0+   | Render prioritized HTML risk reports from scored email data           |
| Async File I/O      | aiofiles                    | 23.0+    | Non-blocking reads of key stores and config files in the gateway      |
| CLI Interface       | click                       | 8.1.0+   | Command-line interface for auditor and gateway configuration          |
| IMAP Client         | imaplib2                    | 3.6+     | Optional live IMAP mailbox connection for auditor mode                |
| Testing             | pytest                      | 7.4.0+   | Unit and integration tests for all modules                            |
| Reporting Frontend  | HTML / CSS (Jinja2)         | —        | Browser-viewable risk report output                                   |
| Email Archive Input | .mbox files                 | RFC 4155 | Input format for mailbox auditor                                      |
| Configuration       | python-dotenv / TOML        | —        | Secure credential and config management                               |
| Build Tools         | GCC/Clang, CMake 3.5+, make | —        | Required to compile liboqs from source                                |

---

## 3. Folder Structure

```
pqmail/
│
├── README.md                        # Project overview, setup, and usage instructions
├── requirements.txt                 # All Python dependencies with pinned versions
├── config.toml                      # Gateway and auditor configuration (upstream SMTP, port, etc.)
├── .env.example                     # Example environment variables (key passphrase, SMTP credentials)
│
├── pqmail/                          # Main source package
│   ├── __init__.py
│   │
│   ├── gateway/                     # SMTP Proxy Gateway
│   │   ├── __init__.py
│   │   ├── proxy.py                 # aiosmtpd handler; entry point for incoming SMTP sessions
│   │   └── forwarder.py             # Forwards processed email to upstream SMTP server
│   │
│   ├── parser/                      # MIME and OpenPGP Parser
│   │   ├── __init__.py
│   │   ├── mime_parser.py           # Parses MIME structure; extracts body parts and attachments
│   │   └── pgp_classifier.py        # Identifies PGP blocks; classifies algorithm (RSA/ECDH/hybrid/none)
│   │
│   ├── scorer/                      # HNDL Risk Scorer
│   │   ├── __init__.py
│   │   ├── hndl_scorer.py           # Computes years-of-safety-remaining risk score per message
│   │   └── timeline_config.py       # Quantum timeline scenario definitions (5/10/15-year models)
│   │
│   ├── classifier/                  # Content Sensitivity Classifier
│   │   ├── __init__.py
│   │   ├── rule_classifier.py       # Keyword-based rule engine (low/medium/high/critical)
│   │   ├── ml_classifier.py         # TF-IDF + Naive Bayes/SVM classifier (optional ML upgrade)
│   │   └── models/                  # Serialized scikit-learn model files (.joblib)
│   │       └── sensitivity_model.joblib
│   │
│   ├── crypto/                      # Hybrid Cryptography Module
│   │   ├── __init__.py
│   │   ├── mlkem.py                 # ML-KEM key generation, encapsulation, decapsulation via liboqs
│   │   ├── ecdh.py                  # X25519 ECDH key exchange via cryptography library
│   │   ├── hybrid_kem.py            # Combines ML-KEM + ECDH shared secrets via HKDF
│   │   └── symmetric.py             # AES-256-GCM encrypt/decrypt with derived key
│   │
│   ├── keys/                        # Key Manager
│   │   ├── __init__.py
│   │   ├── key_manager.py           # Load, store, validate classical and ML-KEM keys
│   │   └── store/                   # Local key store directory
│   │       ├── mlkem/               # Recipient ML-KEM public keys (indexed by email address)
│   │       └── classical/           # Classical PGP public keys (armored .asc files)
│   │
│   ├── fallback/                    # Fallback Logic
│   │   ├── __init__.py
│   │   └── decision.py              # Routes message based on key availability and algorithm detection
│   │
│   ├── auditor/                     # Mailbox Auditor
│   │   ├── __init__.py
│   │   ├── mbox_reader.py           # Parses .mbox archives; iterates over messages
│   │   ├── batch_scorer.py          # Runs HNDL scoring on every message in the archive
│   │   └── imap_connector.py        # Optional: live IMAP mailbox connection
│   │
│   └── report/                      # HTML Risk Report Generator
│       ├── __init__.py
│       ├── report_generator.py      # Assembles scored results; calls Jinja2 renderer
│       └── templates/
│           └── risk_report.html.j2  # Jinja2 HTML template for the prioritized risk report
│
├── tests/                           # All test files
│   ├── conftest.py                  # Shared pytest fixtures (test keys, sample messages)
│   ├── test_proxy.py
│   ├── test_parser.py
│   ├── test_scorer.py
│   ├── test_classifier.py
│   ├── test_crypto.py
│   ├── test_key_manager.py
│   ├── test_auditor.py
│   └── test_report.py
│
├── samples/                         # Sample data for demo and testing
│   ├── keys/                        # Sample ML-KEM and classical key pairs
│   ├── emails/                      # Sample .eml files (RSA, ECDH, hybrid, plaintext)
│   └── mailbox.mbox                 # Sample .mbox archive for auditor demo
│
└── docs/                            # Documentation
    ├── implementation_plan.md       # This document
    ├── architecture_diagram.png
    └── hndl_risk_model.md           # Detailed write-up of the temporal risk model
```

---

## 4. Module-wise Implementation Plan

### 4.1 SMTP Proxy Gateway

**Purpose:**  
The gateway is the entry point of PQMail. It acts as a transparent local SMTP server that intercepts every outgoing email from the user's mail client before it reaches the external mail server. The gateway coordinates all downstream modules (parser, scorer, crypto, fallback) and then forwards the (possibly upgraded) message upstream.

**Inputs:**

- Raw SMTP session data (EHLO, MAIL FROM, RCPT TO, DATA commands)
- Email message bytes (raw MIME content)
- Gateway configuration: listen host/port, upstream SMTP host/port/credentials

**Processing Steps:**

1. Start `aiosmtpd` controller on `localhost:1025` (configurable).
2. Implement a custom `handle_DATA` coroutine in the SMTP handler class.
3. Inside `handle_DATA`:
   a. Receive the raw email bytes.
   b. Pass to `MIMEParser` → get structured message + algorithm classification.
   c. Pass to `HNDLScorer` → get risk score.
   d. Pass to `FallbackDecision` → determine action (upgrade / forward as-is / flag).
   e. If upgrade: pass to `HybridCryptographyModule` → get re-encrypted message bytes.
   f. Never write plaintext content to disk or logs at any step.
4. Forward the final message bytes to the upstream SMTP server using `aiosmtp` or `smtplib` with STARTTLS.
5. Return SMTP status code 250 to the client upon successful upstream relay.

**Outputs:**

- Relayed email (hybrid-upgraded or unchanged) sent to upstream SMTP server.
- In-memory risk record (passed to report generator if auditor mode is active).

**Important Functions/Classes:**

```python
# gateway/proxy.py

import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage

class PQMailHandler(AsyncMessage):
    def __init__(self, config: dict):
        self.config = config

    async def handle_DATA(self, server, session, envelope) -> str:
        raw_bytes: bytes = envelope.content
        mail_from: str = envelope.mail_from
        rcpt_tos: list[str] = envelope.rcpt_tos

        # Step 1: Parse
        parsed = await mime_parser.parse(raw_bytes)

        # Step 2: Score
        score = hndl_scorer.score(parsed)

        # Step 3: Fallback decision
        action = fallback_decision.decide(parsed, rcpt_tos)

        # Step 4: Optional re-encryption (in memory only)
        if action == "UPGRADE":
            raw_bytes = await hybrid_kem.re_encrypt(parsed, rcpt_tos)

        # Step 5: Forward upstream (NEVER log plaintext)
        await forwarder.send(raw_bytes, mail_from, rcpt_tos, self.config)

        return "250 Message accepted for delivery"


def start_gateway(config: dict):
    handler = PQMailHandler(config)
    controller = Controller(handler, hostname="127.0.0.1", port=config["listen_port"])
    controller.start()
    asyncio.get_event_loop().run_forever()
```

```python
# gateway/forwarder.py

import smtplib
import ssl

async def send(message_bytes: bytes, mail_from: str, rcpt_tos: list, config: dict):
    context = ssl.create_default_context()
    with smtplib.SMTP(config["upstream_host"], config["upstream_port"]) as smtp:
        smtp.starttls(context=context)
        smtp.login(config["upstream_user"], config["upstream_password"])
        smtp.sendmail(mail_from, rcpt_tos, message_bytes)
```

**Testing Approach:**

- Use `aiosmtpd`'s built-in test utilities to send test SMTP sessions.
- Assert that `handle_DATA` is called and the forwarder receives the correct bytes.
- Use a mock SMTP server (e.g., `smtpd` module or `aiosmtpd` in test mode) as the upstream.
- Test with: plaintext email, RSA-encrypted email, ECDH-encrypted email, malformed email.

---

### 4.2 MIME and OpenPGP Parser

**Purpose:**  
Parses the raw email bytes into a structured representation. Identifies whether the email contains a PGP-encrypted or PGP-signed payload, and if so, classifies the encryption algorithm used (RSA, ECDH, existing hybrid, or unencrypted/signed-only).

**Inputs:**

- Raw email bytes (from `handle_DATA`)

**Processing Steps:**

1. Use Python's `email` standard library to parse MIME structure.
2. Walk MIME parts to find `Content-Type: multipart/encrypted` or `application/pgp-encrypted`.
3. Extract PGP armored blocks from the MIME body.
4. Use `pgpy` to load the PGP message object:
   ```python
   pgp_msg, _ = pgpy.PGPMessage.from_blob(armored_block)
   ```
5. Inspect packet headers:
   - Check for `PublicKeyEncryptedSessionKey` (PKESK) packets.
   - Read the algorithm field: `RSA` → algorithm ID 1/2/3; `ECDH` → algorithm ID 18.
   - Check for existing hybrid: look for multiple PKESK packets or known hybrid fingerprint markers.
6. Return a structured `ParsedEmail` dataclass.

**Outputs:**

```python
@dataclass
class ParsedEmail:
    raw_bytes: bytes           # Original message bytes (never logged)
    headers: dict              # From, To, Subject (for report metadata only)
    algorithm: str             # "RSA" | "ECDH" | "HYBRID" | "UNENCRYPTED" | "SIGNED_ONLY"
    pgp_message: pgpy.PGPMessage | None
    is_encrypted: bool
    parse_error: str | None    # Error message if parsing failed
```

**Important Functions/Classes:**

```python
# parser/mime_parser.py

import email
import pgpy
from dataclasses import dataclass

@dataclass
class ParsedEmail:
    raw_bytes: bytes
    headers: dict
    algorithm: str
    pgp_message: object
    is_encrypted: bool
    parse_error: str | None

async def parse(raw_bytes: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw_bytes)
    headers = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "message_id": msg.get("Message-ID", ""),
        # Subject intentionally omitted from logs to avoid content leakage
    }

    pgp_block = _extract_pgp_block(msg)
    if pgp_block is None:
        return ParsedEmail(raw_bytes, headers, "UNENCRYPTED", None, False, None)

    try:
        pgp_message, _ = pgpy.PGPMessage.from_blob(pgp_block)
        algorithm = _classify_algorithm(pgp_message)
        return ParsedEmail(raw_bytes, headers, algorithm, pgp_message, True, None)
    except Exception as e:
        return ParsedEmail(raw_bytes, headers, "PARSE_ERROR", None, False, str(e))

def _extract_pgp_block(msg) -> str | None:
    for part in msg.walk():
        ct = part.get_content_type()
        payload = part.get_payload(decode=True)
        if payload and b"-----BEGIN PGP MESSAGE-----" in payload:
            return payload.decode("utf-8", errors="replace")
    return None

def _classify_algorithm(pgp_message) -> str:
    # Inspect PKESK packets for algorithm field
    for packet in pgp_message.packets:
        if hasattr(packet, "pkalg"):
            alg_id = packet.pkalg
            if alg_id in (1, 2, 3):    # RSA Encrypt or Sign
                return "RSA"
            elif alg_id == 18:          # ECDH
                return "ECDH"
            elif alg_id in (25, 29):    # Draft PQC algorithm IDs (ML-KEM composite)
                return "HYBRID"
    return "SIGNED_ONLY"
```

**Testing Approach:**

- Create fixture `.eml` files with known algorithm types.
- Assert correct `algorithm` field for each fixture.
- Test with malformed PGP block → assert `parse_error` is populated and no exception propagates.
- Test with multipart email containing non-PGP attachments.

---

### 4.3 HNDL Risk Scorer

**Purpose:**  
Computes a per-email HNDL risk score, expressed as **"estimated years of safety remaining"** — how many years from now the email's encryption is expected to remain secure against a quantum adversary.

**Inputs:**

- `ParsedEmail` (specifically `algorithm` field)
- `SensitivityLevel` (from Content Sensitivity Classifier)
- `quantum_timeline_years` (user-configured scenario: 5, 10, or 15 years)

**Risk Scoring Formula:**

The core formula is:

```
years_of_safety = max(0, D - T)
```

Where:

- `D` = **Algorithm Safety Horizon** — estimated years until the algorithm is broken by quantum attack
- `T` = **Quantum Timeline** — user-configured estimate of when a cryptographically relevant quantum computer (CRQC) will exist (5, 10, or 15 years from now)

**Algorithm Safety Horizons (D values):**

| Algorithm                     | D (years) | Rationale                                               |
| ----------------------------- | --------- | ------------------------------------------------------- |
| RSA-2048                      | 5         | Vulnerable to Shor's algorithm; considered broken first |
| RSA-4096                      | 8         | Slightly longer, but same fundamental vulnerability     |
| ECDH / X25519                 | 7         | Vulnerable to Shor's algorithm on elliptic curves       |
| Existing Hybrid (ML-KEM+ECDH) | 50+       | PQC component makes quantum attack infeasible           |
| Unencrypted                   | 0         | Already exposed; no algorithmic protection              |

**Sensitivity Multiplier:**

Content sensitivity adjusts the effective risk window:

| Sensitivity | Score Modifier | Effect                                      |
| ----------- | -------------- | ------------------------------------------- |
| Low         | +2 years       | Low-sensitivity content has more time       |
| Medium      | 0 years        | Baseline                                    |
| High        | -3 years       | High-sensitivity content is at greater risk |
| Critical    | -6 years       | Critical content treated as already at risk |

```
years_of_safety = max(0, D - T + sensitivity_modifier)
risk_category = classify(years_of_safety)
```

**Risk Category Classification:**

```
if years_of_safety == 0:
    risk_category = "CRITICAL"
elif years_of_safety <= 3:
    risk_category = "HIGH"
elif years_of_safety <= 7:
    risk_category = "MEDIUM"
else:
    risk_category = "LOW"
```

**Important Functions/Classes:**

```python
# scorer/hndl_scorer.py

ALGORITHM_SAFETY_HORIZON = {
    "RSA": 5,
    "ECDH": 7,
    "HYBRID": 50,
    "UNENCRYPTED": 0,
    "SIGNED_ONLY": 0,
    "PARSE_ERROR": 0,
}

SENSITIVITY_MODIFIER = {
    "LOW": 2,
    "MEDIUM": 0,
    "HIGH": -3,
    "CRITICAL": -6,
}

def score(algorithm: str, sensitivity: str, quantum_timeline: int = 10) -> dict:
    D = ALGORITHM_SAFETY_HORIZON.get(algorithm, 0)
    modifier = SENSITIVITY_MODIFIER.get(sensitivity, 0)
    years_remaining = max(0, D - quantum_timeline + modifier)
    risk_category = _classify_risk(years_remaining)
    return {
        "algorithm": algorithm,
        "sensitivity": sensitivity,
        "quantum_timeline": quantum_timeline,
        "years_of_safety_remaining": years_remaining,
        "risk_category": risk_category,
    }

def _classify_risk(years: int) -> str:
    if years == 0:
        return "CRITICAL"
    elif years <= 3:
        return "HIGH"
    elif years <= 7:
        return "MEDIUM"
    else:
        return "LOW"
```

**Testing Approach:**

- Parameterized pytest tests across all algorithm + sensitivity + timeline combinations.
- Assert that RSA + HIGH sensitivity + 10-year timeline → years ≤ 3, category HIGH or CRITICAL.
- Assert HYBRID → LOW risk regardless of sensitivity.
- Assert Unencrypted → CRITICAL always.

---

### 4.4 Content Sensitivity Classifier

**Purpose:**  
Classifies the sensitivity of email content into one of four levels: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. This feeds directly into the HNDL risk score modifier.

**Inputs:**

- Email plaintext body (decrypted in memory, never written to disk)
- Email subject line (optional metadata; handle carefully)

**Two-Stage Implementation:**

**Stage 1: Rule-Based Classifier (Initial Implementation)**

Define keyword dictionaries for each sensitivity tier:

```python
# classifier/rule_classifier.py

CRITICAL_KEYWORDS = [
    "top secret", "classified", "national security", "nuclear",
    "patient record", "ssn", "social security number", "passport number",
    "account number", "routing number", "private key", "seed phrase"
]

HIGH_KEYWORDS = [
    "confidential", "legal", "attorney", "lawsuit", "settlement",
    "diagnosis", "prescription", "financial", "merger", "acquisition",
    "salary", "credit card", "tax return", "contract"
]

MEDIUM_KEYWORDS = [
    "internal", "proprietary", "draft", "nda", "not for distribution",
    "meeting notes", "project", "budget", "forecast"
]

def classify(text: str) -> str:
    text_lower = text.lower()
    if any(kw in text_lower for kw in CRITICAL_KEYWORDS):
        return "CRITICAL"
    elif any(kw in text_lower for kw in HIGH_KEYWORDS):
        return "HIGH"
    elif any(kw in text_lower for kw in MEDIUM_KEYWORDS):
        return "MEDIUM"
    else:
        return "LOW"
```

**Stage 2: ML Classifier (Optional Upgrade)**

For improved accuracy, train a TF-IDF + Naive Bayes / SVM classifier:

```python
# classifier/ml_classifier.py

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import joblib

def train_model(texts: list[str], labels: list[str]) -> Pipeline:
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=10000)),
        ("clf", MultinomialNB())
    ])
    pipeline.fit(texts, labels)
    return pipeline

def save_model(pipeline: Pipeline, path: str):
    joblib.dump(pipeline, path)

def load_model(path: str) -> Pipeline:
    return joblib.load(path)

def classify_ml(text: str, model: Pipeline) -> str:
    return model.predict([text])[0]
```

Training data can be sourced from:

- The Enron email corpus (labeled by keyword heuristics for bootstrapping)
- Manually curated sensitivity examples

**Outputs:**

- Sensitivity label: `"LOW"` | `"MEDIUM"` | `"HIGH"` | `"CRITICAL"`

**Testing Approach:**

- Unit tests for rule classifier: feed known keyword-containing texts, assert correct label.
- For ML classifier: train on a small labeled set, test precision/recall per class.
- Ensure classifier is called only on in-memory plaintext; test that no file I/O occurs.

---

### 4.5 Hybrid Cryptography Module

**Purpose:**  
Implements the composite ML-KEM + ECDH hybrid key encapsulation and symmetric encryption scheme per `draft-ietf-openpgp-pqc`. This module upgrades classical OpenPGP-encrypted emails to quantum-resistant hybrid encryption.

**Inputs:**

- Plaintext email bytes (decrypted from original PGP message, in memory)
- Recipient's ML-KEM public key (from Key Manager)
- Recipient's classical ECDH public key (from Key Manager)

**Hybrid Encryption Pseudocode:**

```
# Key Generation (done once per key pair, not per message)
function generate_mlkem_keypair(variant="ML-KEM-768"):
    kem = oqs.KeyEncapsulation(variant)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key

# Encapsulation and Shared Secret Combination
function hybrid_encapsulate(mlkem_public_key, ecdh_public_key):
    # Post-quantum component
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    mlkem_ciphertext, mlkem_shared_secret = kem.encap_secret(mlkem_public_key)

    # Classical component
    ecdh_private_ephemeral = X25519PrivateKey.generate()
    ecdh_shared_secret = ecdh_private_ephemeral.exchange(ecdh_public_key)
    ecdh_public_ephemeral = ecdh_private_ephemeral.public_key()

    # Combine shared secrets via HKDF
    combined_secret = mlkem_shared_secret + ecdh_shared_secret
    derived_key = HKDF(
        algorithm=SHA256,
        length=32,
        salt=None,
        info=b"PQMail-HybridKEM-v1"
    ).derive(combined_secret)

    return derived_key, mlkem_ciphertext, ecdh_public_ephemeral

# Symmetric Encryption
function encrypt_message(plaintext_bytes, derived_key):
    nonce = os.urandom(12)
    aesgcm = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
    return nonce + ciphertext

# Full Hybrid Encryption Flow
function hybrid_encrypt(plaintext_bytes, mlkem_public_key, ecdh_public_key):
    derived_key, mlkem_ct, ecdh_pub_ephemeral = hybrid_encapsulate(
        mlkem_public_key, ecdh_public_key
    )
    encrypted_payload = encrypt_message(plaintext_bytes, derived_key)
    # Package: mlkem_ct + ecdh_pub_ephemeral + encrypted_payload → PGP packet
    return build_pgp_packet(mlkem_ct, ecdh_pub_ephemeral, encrypted_payload)

# Decryption (for demo/testing only)
function hybrid_decrypt(packet, mlkem_secret_key, ecdh_private_key):
    mlkem_ct, ecdh_pub_ephemeral, encrypted_payload = unpack_pgp_packet(packet)

    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=mlkem_secret_key)
    mlkem_shared_secret = kem.decap_secret(mlkem_ct)

    ecdh_shared_secret = ecdh_private_key.exchange(ecdh_pub_ephemeral)

    combined_secret = mlkem_shared_secret + ecdh_shared_secret
    derived_key = HKDF(...).derive(combined_secret)

    nonce = encrypted_payload[:12]
    ciphertext = encrypted_payload[12:]
    plaintext = AESGCM(derived_key).decrypt(nonce, ciphertext, None)
    return plaintext
```

**Important Files:**

```python
# crypto/mlkem.py
import oqs

def generate_keypair(variant: str = "ML-KEM-768") -> tuple[bytes, bytes]:
    kem = oqs.KeyEncapsulation(variant)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key

def encapsulate(public_key: bytes, variant: str = "ML-KEM-768") -> tuple[bytes, bytes]:
    kem = oqs.KeyEncapsulation(variant)
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret

def decapsulate(secret_key: bytes, ciphertext: bytes, variant: str = "ML-KEM-768") -> bytes:
    kem = oqs.KeyEncapsulation(variant, secret_key=secret_key)
    return kem.decap_secret(ciphertext)
```

```python
# crypto/hybrid_kem.py
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from .mlkem import encapsulate

def hybrid_encapsulate(mlkem_pub: bytes, ecdh_pub) -> tuple[bytes, bytes, object]:
    mlkem_ct, mlkem_ss = encapsulate(mlkem_pub)
    eph_private = X25519PrivateKey.generate()
    ecdh_ss = eph_private.exchange(ecdh_pub)
    combined = mlkem_ss + ecdh_ss
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PQMail-HybridKEM-v1"
    ).derive(combined)
    return derived_key, mlkem_ct, eph_private.public_key()
```

**Testing Approach:**

- Test round-trip: encrypt with public keys → decrypt with secret keys → assert plaintext matches.
- Test that `liboqs` is correctly installed and `oqs.KeyEncapsulation("ML-KEM-768")` initializes without error.
- Test HKDF output is deterministic given same inputs.
- Test AESGCM encryption/decryption with known vectors.

---

### 4.6 Key Manager

**Purpose:**  
Manages the loading, storage, validation, and lookup of both classical (RSA/ECDH) and post-quantum (ML-KEM) keys for senders and recipients. Ensures private key material is never written to logs.

**Inputs:**

- Recipient email address
- Key store directory paths (from config)
- Passphrase for sender's private key (from environment variable)

**Key Store Layout:**

```
keys/
├── mlkem/
│   ├── alice@example.com.pub.bin     # ML-KEM public key (raw bytes)
│   └── alice@example.com.sk.bin      # ML-KEM secret key (raw bytes, sender only)
└── classical/
    ├── alice@example.com.asc         # Armored PGP public key
    └── sender_private.asc            # Sender's classical private key (passphrase protected)
```

**Important Functions/Classes:**

```python
# keys/key_manager.py

import os
import pgpy
from pathlib import Path

KEY_STORE = Path(os.getenv("PQMAIL_KEY_STORE", "./keys"))

def get_mlkem_public_key(recipient_email: str) -> bytes | None:
    path = KEY_STORE / "mlkem" / f"{recipient_email}.pub.bin"
    if path.exists():
        return path.read_bytes()
    return None

def get_classical_public_key(recipient_email: str) -> pgpy.PGPKey | None:
    path = KEY_STORE / "classical" / f"{recipient_email}.asc"
    if path.exists():
        key, _ = pgpy.PGPKey.from_file(str(path))
        return key
    return None

def load_sender_private_key(passphrase: str) -> pgpy.PGPKey:
    path = KEY_STORE / "classical" / "sender_private.asc"
    key, _ = pgpy.PGPKey.from_file(str(path))
    # Unlock with passphrase; never log the passphrase or unlocked key
    with key.unlock(passphrase):
        return key

def validate_mlkem_key(key_bytes: bytes, variant: str = "ML-KEM-768") -> bool:
    import oqs
    try:
        kem = oqs.KeyEncapsulation(variant)
        # Attempt encapsulation as a validation check
        ct, _ = kem.encap_secret(key_bytes)
        return ct is not None
    except Exception:
        return False

def has_mlkem_key(recipient_email: str) -> bool:
    return get_mlkem_public_key(recipient_email) is not None
```

**Security Notes:**

- Private key passphrase read exclusively from `os.getenv("PQMAIL_KEY_PASSPHRASE")`.
- Never include passphrase or key bytes in log output.
- Validate ML-KEM key length/format before use.
- Store ML-KEM keys as raw binary (not base64 in logs).

**Testing Approach:**

- Generate test key pairs in `tests/conftest.py` as fixtures; write to a temp directory.
- Assert `get_mlkem_public_key` returns correct bytes for known email.
- Assert `has_mlkem_key` returns False for unknown email.
- Assert `validate_mlkem_key` returns False for garbage input.
- Mock environment variable for passphrase in tests.

---

### 4.7 Fallback Logic

**Purpose:**  
Determines what action to take for each outgoing email based on the detected algorithm and the availability of recipient keys. Ensures graceful handling of all cases without breaking email delivery.

**Decision Matrix:**

| Condition                                                            | Action                                                   | Report Flag           |
| -------------------------------------------------------------------- | -------------------------------------------------------- | --------------------- |
| Recipient has ML-KEM key + email is classically encrypted (RSA/ECDH) | Re-encrypt with Hybrid ML-KEM+ECDH                       | `UPGRADED`            |
| Recipient has ML-KEM key + email is already HYBRID                   | Forward unchanged                                        | `ALREADY_HYBRID`      |
| Recipient has ML-KEM key + email is unencrypted                      | Forward unchanged (can't encrypt without consent)        | `UNENCRYPTED_FLAGGED` |
| Recipient has no ML-KEM key + email is classically encrypted         | Forward unchanged with risk flag                         | `NO_MLKEM_KEY`        |
| Recipient has no ML-KEM key + email is unencrypted                   | Forward unchanged                                        | `UNENCRYPTED_NO_KEY`  |
| Parsing failed                                                       | Forward original bytes unchanged                         | `PARSE_ERROR`         |
| Any unexpected exception                                             | Forward original bytes unchanged; log error (no content) | `ERROR`               |

**Important Functions/Classes:**

```python
# fallback/decision.py

from keys.key_manager import has_mlkem_key

def decide(parsed_email, recipient_emails: list[str]) -> dict:
    if parsed_email.parse_error:
        return {"action": "FORWARD_UNCHANGED", "flag": "PARSE_ERROR"}

    algorithm = parsed_email.algorithm
    all_have_mlkem = all(has_mlkem_key(r) for r in recipient_emails)
    any_have_mlkem = any(has_mlkem_key(r) for r in recipient_emails)

    if algorithm == "HYBRID":
        return {"action": "FORWARD_UNCHANGED", "flag": "ALREADY_HYBRID"}

    if algorithm in ("RSA", "ECDH") and all_have_mlkem:
        return {"action": "UPGRADE", "flag": "UPGRADED"}

    if algorithm in ("RSA", "ECDH") and not all_have_mlkem:
        return {"action": "FORWARD_UNCHANGED", "flag": "NO_MLKEM_KEY"}

    if algorithm == "UNENCRYPTED":
        return {
            "action": "FORWARD_UNCHANGED",
            "flag": "UNENCRYPTED_FLAGGED" if any_have_mlkem else "UNENCRYPTED_NO_KEY"
        }

    return {"action": "FORWARD_UNCHANGED", "flag": "UNKNOWN"}
```

**Testing Approach:**

- Test all rows of the decision matrix with mocked `has_mlkem_key`.
- Assert correct `action` and `flag` for each scenario.
- Test with multiple recipients where only some have ML-KEM keys.

---

### 4.8 Mailbox Auditor

**Purpose:**  
Scans `.mbox` archive files, extracts each message, runs the MIME parser and HNDL scorer on every message, and accumulates results for the report generator. This enables users to assess their historical quantum exposure.

**Inputs:**

- Path to `.mbox` file (CLI argument)
- Quantum timeline scenario (CLI option: `--timeline 10`)
- Output path for the HTML report

**Processing Steps:**

1. Open the `.mbox` file using Python's `mailbox.mbox` standard library class.
2. Iterate over all messages.
3. For each message:
   a. Convert to bytes using `message.as_bytes()`.
   b. Pass to `MIMEParser.parse()`.
   c. Run `ContentSensitivityClassifier.classify()` on headers only (body may be encrypted and inaccessible without private key).
   d. Run `HNDLScorer.score()`.
   e. Collect the score record.
4. Sort results by `years_of_safety_remaining` (ascending = highest risk first).
5. Pass sorted results to `ReportGenerator`.

**Important Functions/Classes:**

```python
# auditor/mbox_reader.py

import mailbox
from parser.mime_parser import parse
from scorer.hndl_scorer import score
from classifier.rule_classifier import classify

async def audit_mbox(mbox_path: str, quantum_timeline: int = 10) -> list[dict]:
    mbox = mailbox.mbox(mbox_path)
    results = []

    for i, message in enumerate(mbox):
        raw_bytes = message.as_bytes()
        parsed = await parse(raw_bytes)

        # Classify based on headers only (body may be encrypted)
        subject_hint = message.get("Subject", "")
        sensitivity = classify(subject_hint)

        risk_record = score(parsed.algorithm, sensitivity, quantum_timeline)
        risk_record["message_id"] = message.get("Message-ID", f"msg-{i}")
        risk_record["from"] = message.get("From", "")
        risk_record["to"] = message.get("To", "")
        risk_record["subject_placeholder"] = "[Subject Hidden]"  # Never log real subject
        results.append(risk_record)

    # Sort by risk: CRITICAL first, then LOW last
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results.sort(key=lambda r: risk_order.get(r["risk_category"], 4))
    return results
```

```python
# auditor/batch_scorer.py — CLI entry point

import click
import asyncio
from auditor.mbox_reader import audit_mbox
from report.report_generator import generate_report

@click.command()
@click.argument("mbox_path")
@click.option("--timeline", default=10, help="Quantum timeline in years (5, 10, 15)")
@click.option("--output", default="risk_report.html", help="Output HTML report path")
def audit(mbox_path: str, timeline: int, output: str):
    """Scan an .mbox archive and generate an HNDL risk report."""
    results = asyncio.run(audit_mbox(mbox_path, timeline))
    generate_report(results, output)
    click.echo(f"Report generated: {output}")
```

**Testing Approach:**

- Create a sample `.mbox` file in `tests/` with 5–10 messages of varying algorithm types.
- Assert `audit_mbox` returns one record per message.
- Assert results are sorted by risk (CRITICAL first).
- Assert no sensitive content appears in returned records.

---

### 4.9 HTML Risk Report Generator

**Purpose:**  
Renders the scored and sorted email audit results into a professional, browser-viewable HTML report using Jinja2. The report is prioritized by risk (highest risk at the top) and includes per-email details and recommended actions.

**Inputs:**

- List of risk record dicts (from Mailbox Auditor or gateway session)
- Output file path

**Report Fields per Message:**

| Field                     | Source           | Notes                              |
| ------------------------- | ---------------- | ---------------------------------- |
| Message ID                | Email header     | Unique identifier                  |
| From                      | Email header     | Sender address                     |
| To                        | Email header     | Recipient address                  |
| Subject                   | Placeholder only | Real subject never shown in report |
| Detected Algorithm        | MIME Parser      | RSA / ECDH / HYBRID / UNENCRYPTED  |
| Sensitivity Level         | Classifier       | LOW / MEDIUM / HIGH / CRITICAL     |
| Years of Safety Remaining | HNDL Scorer      | Integer                            |
| Risk Category             | HNDL Scorer      | CRITICAL / HIGH / MEDIUM / LOW     |
| Recommended Action        | Logic            | Based on algorithm + risk          |

**Recommended Action Logic:**

```python
def get_recommended_action(algorithm: str, risk_category: str, has_mlkem_key: bool) -> str:
    if algorithm == "HYBRID":
        return "No action required. Message is already quantum-safe."
    if algorithm == "UNENCRYPTED":
        return "Enable encryption immediately. This message has no cryptographic protection."
    if risk_category == "CRITICAL":
        return "Urgent: Re-encrypt using ML-KEM hybrid scheme. Assume this message may already be harvested."
    if risk_category == "HIGH":
        return "Re-encrypt soon. Upgrade to hybrid PQC encryption before the quantum timeline."
    if has_mlkem_key:
        return "Upgrade available: PQMail can re-encrypt this message with ML-KEM+ECDH."
    return "Monitor: Obtain recipient ML-KEM public key to enable hybrid re-encryption."
```

**Jinja2 Template (excerpt):**

```html
<!-- report/templates/risk_report.html.j2 -->
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>PQMail HNDL Risk Report</title>
    <style>
      body {
        font-family: monospace;
        background: #0d0d0d;
        color: #e0e0e0;
      }
      table {
        width: 100%;
        border-collapse: collapse;
      }
      th {
        background: #1a1a2e;
        color: #a0c4ff;
        padding: 8px;
      }
      td {
        padding: 8px;
        border-bottom: 1px solid #333;
      }
      .CRITICAL {
        background: #3a0000;
        color: #ff4444;
        font-weight: bold;
      }
      .HIGH {
        background: #2a1500;
        color: #ff8800;
      }
      .MEDIUM {
        background: #1a1a00;
        color: #ffdd00;
      }
      .LOW {
        background: #001a00;
        color: #44ff44;
      }
    </style>
  </head>
  <body>
    <h1>PQMail — HNDL Risk Report</h1>
    <p>
      Generated: {{ generated_at }} | Quantum Timeline: {{ quantum_timeline }}
      years
    </p>
    <table>
      <tr>
        <th>Message ID</th>
        <th>From</th>
        <th>To</th>
        <th>Algorithm</th>
        <th>Sensitivity</th>
        <th>Years Safe</th>
        <th>Risk</th>
        <th>Action</th>
      </tr>
      {% for msg in messages %}
      <tr class="{{ msg.risk_category }}">
        <td>{{ msg.message_id }}</td>
        <td>{{ msg.from }}</td>
        <td>{{ msg.to }}</td>
        <td>{{ msg.algorithm }}</td>
        <td>{{ msg.sensitivity }}</td>
        <td>{{ msg.years_of_safety_remaining }}</td>
        <td>{{ msg.risk_category }}</td>
        <td>{{ msg.recommended_action }}</td>
      </tr>
      {% endfor %}
    </table>
  </body>
</html>
```

**Important Functions:**

```python
# report/report_generator.py

from jinja2 import Environment, FileSystemLoader
from datetime import datetime

def generate_report(results: list[dict], output_path: str):
    env = Environment(loader=FileSystemLoader("pqmail/report/templates"))
    template = env.get_template("risk_report.html.j2")
    html = template.render(
        messages=results,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        quantum_timeline=results[0].get("quantum_timeline", 10) if results else 10
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
```

**Testing Approach:**

- Pass a known list of mock risk records; assert the output file is valid HTML.
- Assert CRITICAL records appear before LOW records in the output.
- Assert subject placeholder `[Subject Hidden]` appears instead of real subjects.
- Test with zero records (empty .mbox).

---

## 5. Implementation Phases

### Phase 1: Environment Setup and Project Skeleton

**Tasks:**

- Install Python 3.11, pip, GCC, CMake
- Clone and compile `liboqs` from source
- Install `liboqs-python` and verify with `python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"`
- Install all other dependencies from `requirements.txt`
- Scaffold the full folder structure as defined in Section 3
- Create empty module files with docstrings
- Initialize git repository

**Deliverables:** Working Python environment, verified `liboqs` installation, project skeleton committed to git

**Estimated Effort:** 4–6 hours

**Dependencies:** None

---

### Phase 2: SMTP Proxy Prototype

**Tasks:**

- Implement `PQMailHandler` with `handle_DATA` using `aiosmtpd`
- Implement `forwarder.py` with STARTTLS upstream relay
- Test with Thunderbird or `swaks` sending to `localhost:1025`
- Confirm email is received by a local test SMTP sink (e.g., `python -m smtpd -n -c DebuggingServer`)

**Deliverables:** Working SMTP proxy that receives and relays email without modification

**Estimated Effort:** 6–8 hours

**Dependencies:** Phase 1

---

### Phase 3: MIME/OpenPGP Parsing

**Tasks:**

- Implement `mime_parser.py` and `pgp_classifier.py`
- Create fixture `.eml` files for RSA, ECDH, hybrid, plaintext, and malformed email
- Write `test_parser.py` with parameterized tests
- Verify algorithm classification accuracy on all fixtures

**Deliverables:** `ParsedEmail` dataclass produced correctly for all email types; all parser tests passing

**Estimated Effort:** 8–10 hours

**Dependencies:** Phase 2

---

### Phase 4: HNDL Risk Scoring

**Tasks:**

- Implement `hndl_scorer.py` with all algorithm horizons and sensitivity modifiers
- Implement `timeline_config.py` for scenario management
- Write `test_scorer.py` with full combinatorial test coverage
- Validate formula against MDPI Telecom (2025) temporal risk model

**Deliverables:** Risk scorer returning correct `years_of_safety_remaining` and `risk_category` for all inputs

**Estimated Effort:** 6–8 hours

**Dependencies:** Phase 3

---

### Phase 5: Content Sensitivity Classifier

**Tasks:**

- Implement rule-based `rule_classifier.py`
- Define and finalize keyword dictionaries for all four sensitivity levels
- (Optional) Train and serialize `ml_classifier.py` on Enron corpus subset
- Write `test_classifier.py`

**Deliverables:** Classifier correctly labeling test emails; integration with scorer confirmed

**Estimated Effort:** 8–12 hours (rule-based: 4h; ML upgrade: additional 4–8h)

**Dependencies:** Phase 4

---

### Phase 6: Hybrid Cryptography Proof of Concept

**Tasks:**

- Implement `mlkem.py` (keygen, encapsulate, decapsulate)
- Implement `ecdh.py` (X25519 keygen and exchange)
- Implement `hybrid_kem.py` (HKDF combination)
- Implement `symmetric.py` (AES-256-GCM)
- Write standalone POC script: generate keys → encrypt → decrypt → assert plaintext matches
- Write `test_crypto.py` with round-trip tests

**Deliverables:** Passing round-trip encrypt/decrypt test using ML-KEM-768 + X25519 + HKDF + AES-256-GCM

**Estimated Effort:** 10–14 hours

**Dependencies:** Phase 1 (liboqs), Phase 3

---

### Phase 7: Key Manager and Fallback Logic

**Tasks:**

- Implement `key_manager.py` with all load/validate functions
- Generate sample key pairs; store in `keys/` directory
- Implement `decision.py` with full decision matrix
- Write `test_key_manager.py` and `test_fallback.py`
- Integrate key manager with gateway handler

**Deliverables:** Key manager correctly loading keys; fallback routing all scenarios correctly

**Estimated Effort:** 6–8 hours

**Dependencies:** Phase 6

---

### Phase 8: Mailbox Auditor

**Tasks:**

- Implement `mbox_reader.py` using `mailbox.mbox`
- Implement `batch_scorer.py` as a Click CLI command
- Create sample `.mbox` file in `samples/` with varied message types
- Run auditor on sample mailbox; confirm all messages scored
- Write `test_auditor.py`

**Deliverables:** `pqmail audit samples/mailbox.mbox --timeline 10 --output report.html` produces a sorted risk list

**Estimated Effort:** 6–8 hours

**Dependencies:** Phase 4, Phase 5

---

### Phase 9: HTML Report Generation

**Tasks:**

- Design and implement `risk_report.html.j2` Jinja2 template
- Implement `report_generator.py`
- Verify HTML output is valid and correctly prioritized
- Write `test_report.py`

**Deliverables:** Browser-viewable HTML risk report from sample `.mbox` audit

**Estimated Effort:** 4–6 hours

**Dependencies:** Phase 8

---

### Phase 10: Integration and Testing

**Tasks:**

- Wire all modules together in the gateway `handle_DATA` pipeline
- Run end-to-end test: send classically encrypted email through proxy → confirm hybrid upgrade → confirm upstream relay
- Run full test suite: `pytest tests/ -v --cov=pqmail`
- Fix integration bugs

**Deliverables:** End-to-end integration working; test coverage > 70%

**Estimated Effort:** 10–14 hours

**Dependencies:** All previous phases

---

### Phase 11: Performance and Security Validation

**Tasks:**

- Benchmark `handle_DATA` latency using `time.perf_counter()` with 50 test messages
- Confirm < 200ms per message for hybrid re-encryption on target hardware
- Review all logging statements; confirm no plaintext content in any log
- Run `grep` for debug print statements that may expose email content
- Profile memory usage during batch auditing

**Deliverables:** Latency benchmark results documented; security checklist completed

**Estimated Effort:** 6–8 hours

**Dependencies:** Phase 10

---

### Phase 12: Final Documentation and Demo Preparation

**Tasks:**

- Write `README.md` with setup, configuration, and usage instructions
- Record demo video (or prepare live demo script)
- Finalize all sample files in `samples/`
- Package `requirements.txt` with all pinned versions
- Prepare final project report

**Deliverables:** All final deliverables listed in Section 12

**Estimated Effort:** 8–10 hours

**Dependencies:** Phase 11

---

## 6. Testing Plan

### Unit Testing

- **Framework:** pytest 7.4.0+
- **Scope:** Each module tested in isolation with mocked dependencies
- **Coverage target:** > 70% line coverage (`pytest --cov=pqmail`)
- Key unit tests:
  - `test_parser.py`: Algorithm classification for all email types
  - `test_scorer.py`: Risk formula correctness for all combinations
  - `test_classifier.py`: Keyword classifier on known inputs
  - `test_crypto.py`: Round-trip encrypt/decrypt correctness
  - `test_key_manager.py`: Key load/validate with temp directories
  - `test_fallback.py`: All decision matrix cases

### Integration Testing

- Test the full pipeline from raw email bytes → parsed → scored → decided → (upgraded) → forwarded
- Use `tests/conftest.py` to provide shared fixtures (sample keys, test emails)
- Assert that `ParsedEmail.algorithm` flows correctly into `HNDLScorer.score()` output

### SMTP Proxy Testing

- Use `swaks` (Swiss Army Knife SMTP) to send test emails to `localhost:1025`
  ```bash
  swaks --to recipient@example.com --from sender@example.com \
        --server localhost:1025 --body "Test message"
  ```
- Use a local SMTP sink as the upstream (e.g., MailHog) to capture forwarded messages
- Assert forwarded message arrives at the sink
- Assert hybrid-upgraded messages contain ML-KEM packet markers

### Cryptography Testing

- Round-trip tests: generate keys → encrypt → decrypt → assert plaintext equality
- Test with both ML-KEM-768 and ML-KEM-1024 variants
- Test that decryption with wrong secret key raises an exception (not silently returns garbage)
- Test HKDF determinism: same inputs → same derived key
- Test AES-GCM authentication tag failure on tampered ciphertext

### Auditor Testing

- Feed a known `.mbox` file with 10 messages (4 RSA, 3 ECDH, 2 HYBRID, 1 plaintext)
- Assert output list has exactly 10 records
- Assert all CRITICAL records appear before HIGH, which appear before MEDIUM and LOW
- Assert no `None` values in required fields

### Report Generation Testing

- Assert generated HTML is parseable (use `html.parser` to validate)
- Assert `[Subject Hidden]` appears for all messages (not real subjects)
- Assert color-coded CSS classes (CRITICAL, HIGH, MEDIUM, LOW) appear in output
- Test with empty input (zero messages) → graceful empty-table output

### Security Testing

- Grep all log statements for any plaintext content patterns
  ```bash
  grep -rn "log\|print\|logger" pqmail/ | grep -i "body\|content\|plaintext\|subject"
  ```
- Assert `PQMAIL_KEY_PASSPHRASE` environment variable is never printed
- Test that a failed upstream SMTP connection raises an error but does not log email content
- Test that a parsing failure forwards original bytes unchanged without logging content

### Performance Testing

- Benchmark `handle_DATA` for hybrid re-encryption:
  ```python
  import time
  times = []
  for _ in range(50):
      start = time.perf_counter()
      await handler.handle_DATA(server, session, test_envelope)
      times.append(time.perf_counter() - start)
  assert max(times) < 0.200  # 200ms SLA
  ```
- Benchmark `.mbox` auditing throughput: records processed per second on a 500-message mailbox

---

## 7. Security Considerations

| Consideration                   | Implementation                                                                                                               |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **No plaintext to disk**        | All plaintext email content exists only in memory during `handle_DATA`. No file writes of body content.                      |
| **No plaintext in logs**        | All logging statements use only metadata (algorithm type, message ID, risk score). Never log body, subject, or key material. |
| **Private key protection**      | Sender's private key passphrase loaded exclusively from `os.getenv("PQMAIL_KEY_PASSPHRASE")`. Never hardcoded.               |
| **No hardcoded credentials**    | Upstream SMTP credentials stored in `config.toml` or `.env`. `.env` is in `.gitignore`.                                      |
| **Environment variable safety** | Use `python-dotenv` for local dev; use OS-level secrets management for any deployment.                                       |
| **Recipient key validation**    | ML-KEM public keys validated (attempt encapsulation) before use. Reject malformed keys.                                      |
| **Parse failure safety**        | If parsing fails for any reason, original email bytes are forwarded unchanged. No exception propagates to the SMTP client.   |
| **Memory clearing**             | After re-encryption, overwrite intermediate plaintext variables (set to `None`, call `gc.collect()`).                        |
| **TLS for upstream**            | STARTTLS enforced for all connections to the upstream SMTP server.                                                           |
| **Key store permissions**       | `keys/` directory set to `chmod 700`; key files set to `chmod 600`.                                                          |

---

## 8. Performance Considerations

**Target SLA:** Gateway hybrid re-encryption processing must add **≤ 200ms latency** per message, measured on a mid-range laptop (dual-core, 2.0 GHz, 4 GB RAM).

**Expected Bottlenecks:**

- `liboqs` ML-KEM-768 encapsulation: typically 1–5ms per operation
- AES-256-GCM encryption: negligible for typical email sizes
- `pgpy` PGP packet construction: 10–50ms depending on message size
- SMTP upstream connection/TLS handshake: 50–150ms (network-dependent)

**Measurement Approach:**

```python
# Benchmark in tests/test_performance.py
import time, pytest

@pytest.mark.benchmark
async def test_hybrid_reencrypt_latency(handler, test_envelope_rsa):
    times = []
    for _ in range(50):
        start = time.perf_counter()
        await handler.handle_DATA(None, None, test_envelope_rsa)
        times.append((time.perf_counter() - start) * 1000)  # convert to ms

    avg_ms = sum(times) / len(times)
    max_ms = max(times)
    print(f"Avg: {avg_ms:.1f}ms | Max: {max_ms:.1f}ms")
    assert max_ms < 200, f"Latency SLA violated: {max_ms:.1f}ms"
```

**Optimization Strategies:**

- Use `asyncio` throughout to avoid blocking I/O during key reads
- Use `aiofiles` for non-blocking key store reads
- Pre-load sender's classical private key at gateway startup (cache in memory for session duration, not per message)
- Use ML-KEM-768 (not ML-KEM-1024) for lower latency when security level allows
- Profile with `cProfile` or `line_profiler` if SLA is not met; optimize the slowest function

---

## 9. Demo Plan

The following is a step-by-step demo flow suitable for academic presentation:

**Step 1: Start PQMail Gateway**

```bash
export PQMAIL_KEY_PASSPHRASE="demo-passphrase"
python -m pqmail.gateway.proxy --config config.toml
# Output: PQMail gateway listening on localhost:1025
```

**Step 2: Configure Email Client**

- In Thunderbird (or any SMTP client): set outgoing SMTP server to `localhost`, port `1025`, no authentication.

**Step 3: Send a Classically Encrypted Test Email**

- Use `swaks` to simulate:
  ```bash
  swaks --to alice@example.com --from sender@example.com \
        --server localhost:1025 \
        --attach-type application/pgp-encrypted \
        --attach samples/emails/rsa_encrypted.eml
  ```

**Step 4: Show Algorithm Detection**

- Console output:
  ```
  [PQMail] Detected algorithm: RSA | Message-ID: <test-001@example.com>
  ```

**Step 5: Show HNDL Risk Score**

- Console output:
  ```
  [PQMail] Risk: HIGH | Years of safety remaining: 2 | Sensitivity: MEDIUM
  ```

**Step 6: Show Hybrid Encryption Upgrade**

- Console output:
  ```
  [PQMail] ML-KEM key found for alice@example.com. Upgrading to hybrid ML-KEM-768+X25519.
  [PQMail] Re-encryption complete. Forwarding to upstream SMTP.
  ```

**Step 7: Run Mailbox Auditor on Sample .mbox**

```bash
python -m pqmail.auditor.batch_scorer samples/mailbox.mbox \
    --timeline 10 --output samples/risk_report.html
# Output: Audited 47 messages. Report saved to samples/risk_report.html
```

**Step 8: Open HTML Risk Report in Browser**

```bash
xdg-open samples/risk_report.html   # Linux
open samples/risk_report.html       # macOS
```

- Show the prioritized table: CRITICAL messages at top (RSA-encrypted), LOW at bottom (hybrid-encrypted).

---

## 10. Risks and Mitigation

| Risk                                                | Impact                                               | Mitigation                                                                                                            |
| --------------------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `liboqs` installation fails (CMake/GCC build error) | HIGH — blocks all PQC operations                     | Follow official OQS build guide exactly; test on Ubuntu 22.04 LTS in a Docker container; pre-build for demo machine   |
| `draft-ietf-openpgp-pqc` packet format complexity   | HIGH — hybrid PGP packet construction is non-trivial | Focus on custom binary packet format for demo; skip full PGP spec compliance if time-constrained; document divergence |
| `pgpy` cannot parse all real-world PGP messages     | MEDIUM — some emails may fail classification         | Implement robust try/except in parser; fall back to `PARSE_ERROR` action; test on diverse email samples               |
| SMTP forwarding issues (TLS errors, auth failures)  | HIGH — demo breaks if email cannot be relayed        | Use MailHog locally as upstream sink for demo; test real upstream separately                                          |
| Recipient key mismatch (wrong ML-KEM key format)    | MEDIUM — re-encryption silently fails                | Implement `validate_mlkem_key()` before every use; surface validation errors to console                               |
| Time constraints prevent full implementation        | HIGH — academic deadline risk                        | Prioritize MVP scope (Section 11) first; defer ML classifier and IMAP auditor to optional extras                      |
| Memory leak during batch auditing of large .mbox    | LOW — performance degradation                        | Process messages one at a time; call `gc.collect()` after each batch; test with 1000-message .mbox                    |
| Private key exposure through exception tracebacks   | CRITICAL — security vulnerability                    | Wrap all key operations in try/except; never include key bytes in exception messages; test error paths                |

---

## 11. Minimum Viable Product (MVP)

The following constitutes the MVP for academic submission. All listed items must be complete and demonstrable:

| MVP Component                                                                 | Modules Involved                                    | Status Target |
| ----------------------------------------------------------------------------- | --------------------------------------------------- | ------------- |
| Local SMTP proxy prototype receiving and relaying email                       | `gateway/proxy.py`, `gateway/forwarder.py`          | Required      |
| Email parsing with MIME structure extraction                                  | `parser/mime_parser.py`                             | Required      |
| Algorithm detection (RSA / ECDH / HYBRID / UNENCRYPTED)                       | `parser/pgp_classifier.py`                          | Required      |
| Rule-based HNDL risk scoring with years-of-safety formula                     | `scorer/hndl_scorer.py`                             | Required      |
| Rule-based content sensitivity classifier                                     | `classifier/rule_classifier.py`                     | Required      |
| Hybrid encryption proof of concept (ML-KEM-768 + X25519 + HKDF + AES-256-GCM) | `crypto/`                                           | Required      |
| Key manager using local files                                                 | `keys/key_manager.py`                               | Required      |
| Fallback logic (all decision matrix cases)                                    | `fallback/decision.py`                              | Required      |
| `.mbox` auditor scanning and batch scoring                                    | `auditor/mbox_reader.py`, `auditor/batch_scorer.py` | Required      |
| Prioritized HTML risk report with Jinja2                                      | `report/report_generator.py`, `report/templates/`   | Required      |
| Pytest test suite with > 60% coverage                                         | `tests/`                                            | Required      |

**Out of scope for MVP (optional stretch goals):**

- ML-based sensitivity classifier (TF-IDF + Naive Bayes)
- Live IMAP mailbox auditing (`auditor/imap_connector.py`)
- Full conformance to `draft-ietf-openpgp-pqc` packet format (custom binary format acceptable for demo)
- GUI or web interface

---

## 12. Final Deliverables

| Deliverable                | File/Location                 | Description                                                 |
| -------------------------- | ----------------------------- | ----------------------------------------------------------- |
| Source code                | `pqmail/`                     | Complete Python package with all modules                    |
| Dependency file            | `requirements.txt`            | All dependencies with pinned versions                       |
| Setup and usage guide      | `README.md`                   | Installation, configuration, and usage instructions         |
| This document              | `docs/implementation_plan.md` | Full implementation plan                                    |
| Test suite                 | `tests/`                      | All pytest test files with fixtures                         |
| Sample ML-KEM key pairs    | `samples/keys/`               | Pre-generated ML-KEM-768 public/secret key pairs for demo   |
| Sample classical PGP keys  | `samples/keys/`               | Armored RSA and ECDH PGP key pairs for demo                 |
| Sample email files         | `samples/emails/`             | `.eml` files for RSA, ECDH, hybrid, and plaintext scenarios |
| Sample .mbox archive       | `samples/mailbox.mbox`        | 20–50 message .mbox file for auditor demo                   |
| Generated HTML risk report | `samples/risk_report.html`    | Pre-generated report from sample mailbox                    |
| Final project report       | `docs/final_report.pdf`       | Written report covering design, implementation, results     |
| Demo video (if required)   | `docs/demo_video.mp4`         | Screen recording of live demo per Section 9                 |

---

_Document prepared by Angela Varghese (1RV23IS014) and Arshia Sirohi (1RV23IS022)_  
_RV College of Engineering, Department of Information Science and Engineering_  
_Cryptography and Network Security — IS362IA, 2026_
