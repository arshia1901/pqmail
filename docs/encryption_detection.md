# Encryption Algorithm Detection

## Why We Can't Always Detect the Exact Algorithm

When a PGP message is **encrypted**, the system can only detect it contains encryption, but **cannot determine RSA vs ECDH vs HYBRID** without the private key.

### The Problem

PGP messages are structured like this:
```
MIME Message
  ├─ Control Part (metadata, algorithm hints)
  ├─ Encrypted Data Packet (encrypted with recipient's public key)
  │   └─ [ENCRYPTED - CANNOT READ WITHOUT PRIVATE KEY]
  └─ Signature (optional)
```

**To inspect algorithm**, PGP needs to:
1. Decrypt the message using **the recipient's private key**
2. Read the packet headers inside
3. Extract algorithm ID from PKESK (Public Key Encrypted Session Key) packet

**We don't have the private key** — PQMail is a gateway that intercepts, it's not a mail client with decryption keys.

---

## What We CAN Detect

### ✅ Encrypted Messages (No Decryption Needed)
- PGP armor headers: `-----BEGIN PGP MESSAGE-----`
- MIME content-type: `multipart/encrypted`
- Returns: `"ENCRYPTED"` (generic, not specific algorithm)

### ✅ Signed-Only Messages (No Decryption Needed)
- PGP armor headers: `-----BEGIN PGP SIGNED MESSAGE-----`
- Returns: `"SIGNED_ONLY"`

### ✅ Unencrypted Messages
- No PGP blocks found
- Returns: `"UNENCRYPTED"`

### ✅ Algorithm from Armor Headers (Heuristic)
- Some PGP tools include algorithm hints in armor headers
- Example: `-----BEGIN PGP MESSAGE-----\nAlgorithm: RSA-2048`
- Returns: `"RSA"`, `"ECDH"`, or `"HYBRID"` if headers present

---

## Full Algorithm Detection (With Private Key)

If PQMail were deployed as a **server with recipient keys**, we could:

1. **Store recipient's ML-KEM / X25519 private keys** in the system
2. **Decrypt each message** as it arrives
3. **Inspect PKESK packet** to determine algorithm
4. **Re-encrypt** with upgraded keys if needed

This requires:
- ✅ pgpy library (installed)
- ✅ cryptography library (installed)
- ❌ **Recipient private keys** (security risk, not implemented)

---

## Scoring With ENCRYPTED vs Specific Algorithm

### Current Behavior
```
Algorithm: ENCRYPTED (can't determine which)
Risk Score: Uses default (UNENCRYPTED defense horizon = 0 years)
```

### Recommended Approach
When algorithm is unknown but encryption is detected:
- Assume **HYBRID** (most secure, 50-year defense horizon)
- This avoids under-scoring encrypted emails
- User gets accurate risk even without full details

---

## Testing With Real Encryption

To test with **specific algorithms**, you need:

### Option A: Generate PGP Keys in Thunderbird
1. Settings → Privacy & Security → End-to-End Encryption
2. Create key pair (RSA-4096 by default)
3. Send signed email → PQMail detects "SIGNED_ONLY"
4. Ask recipient to send you encrypted email → PQMail sees encryption

### Option B: Use External PGP Tool
```bash
gpg --genkey  # Generate key locally
gpg --armor --encrypt -r alice@example.com message.txt
# Send encrypted message through Thunderbird to PQMail
```

### Option C: Include Algorithm Hints
When creating test messages, include armor header hints:
```
-----BEGIN PGP MESSAGE-----
Algorithm: RSA-2048
Version: OpenPGP v2.0

[encrypted data...]
-----END PGP MESSAGE-----
```

---

## Future: Full Algorithm Detection

To enable full algorithm detection:

1. **Store recipient keys securely** (encrypted at rest)
2. **Decrypt intercepted messages** during pipeline
3. **Inspect PKESK packets** in pgpy
4. **Re-encrypt with upgraded keys**

This requires significant security infrastructure (key management, encrypted storage, audit logging).
