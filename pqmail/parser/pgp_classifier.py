"""
OpenPGP Algorithm Classifier for PQMail.

Detects the encryption algorithm used in a PGP message:
- RSA (algorithm ID 1, 2, 3)
- ECDH (algorithm ID 18)
- HYBRID (algorithm ID 25, 29 — ML-KEM composite per draft-ietf-openpgp-pqc)
- SIGNED_ONLY (no encryption, signature only)
- UNENCRYPTED (no PGP at all)

Security: This module reads PGP headers only — never logs or stores plaintext content.
"""

from typing import Optional


def extract_pgp_block(mime_payload: str) -> Optional[str]:
    """
    Extract PGP armored block from MIME payload string.

    Returns the armored text (-----BEGIN PGP MESSAGE-----) or None if not found.
    """
    if not mime_payload:
        return None

    if "-----BEGIN PGP MESSAGE-----" in mime_payload:
        start = mime_payload.find("-----BEGIN PGP MESSAGE-----")
        end = mime_payload.find("-----END PGP MESSAGE-----")
        if end != -1:
            end += len("-----END PGP MESSAGE-----")
            return mime_payload[start:end]

    return None


def classify_algorithm_from_pgp(pgp_message) -> str:
    """
    Classify algorithm by inspecting PGP message packet headers.

    Expects a pgpy.PGPMessage object. Inspects PublicKeyEncryptedSessionKey (PKESK)
    packets for the algorithm ID field.

    Algorithm mapping:
        1, 2, 3  → RSA
        18       → ECDH
        25, 29   → HYBRID (ML-KEM composite)
        None     → SIGNED_ONLY (no PKESK means signature only)

    Returns: "RSA" | "ECDH" | "HYBRID" | "SIGNED_ONLY" | "UNKNOWN"
    """
    if pgp_message is None:
        return "UNKNOWN"

    try:
        # pgpy structure: pgp_message.packets is a list of packet objects
        for packet in pgp_message.packets:
            # PKESK (PublicKeyEncryptedSessionKey) packet has pkalg attribute
            if hasattr(packet, "pkalg"):
                alg_id = int(packet.pkalg)

                if alg_id in (1, 2, 3):
                    return "RSA"
                elif alg_id == 18:
                    return "ECDH"
                elif alg_id in (25, 29):
                    return "HYBRID"

        # No PKESK found → signature only
        return "SIGNED_ONLY"

    except Exception as e:
        # Malformed packet structure
        return "UNKNOWN"


def classify_algorithm_from_mime(message_obj) -> str:
    """
    Classify algorithm by inspecting MIME content-type and looking for PGP blocks.

    For MVP, this is a heuristic approach:
    - If Content-Type is multipart/encrypted → likely PGP
    - If body contains -----BEGIN PGP MESSAGE----- → extract and parse

    Returns: "RSA" | "ECDH" | "HYBRID" | "UNENCRYPTED" | "SIGNED_ONLY" | "UNKNOWN"
    """
    if message_obj is None:
        return "UNENCRYPTED"

    try:
        content_type = message_obj.get_content_type()

        # multipart/encrypted is the standard for PGP-encrypted MIME
        if content_type == "multipart/encrypted":
            # Walk parts to find the encrypted body part
            for part in message_obj.walk():
                ct = part.get_content_type()
                if ct in ("application/octet-stream", "application/pgp-encrypted"):
                    try:
                        payload = part.get_payload(decode=True)
                        if payload and b"-----BEGIN PGP MESSAGE-----" in payload:
                            # We found an encrypted block, but can't parse without pgpy
                            # Return a placeholder; full parsing happens in pgp_classifier.py
                            return "ENCRYPTED_BLOCK_FOUND"
                    except Exception:
                        continue

        # Check body for PGP block
        try:
            if message_obj.is_multipart():
                for part in message_obj.walk():
                    try:
                        content = part.get_content()
                        if content and "-----BEGIN PGP MESSAGE-----" in content:
                            return "ENCRYPTED_BLOCK_FOUND"
                    except Exception:
                        continue
            else:
                content = message_obj.get_content()
                if content and "-----BEGIN PGP MESSAGE-----" in content:
                    return "ENCRYPTED_BLOCK_FOUND"
        except Exception:
            pass

        # No PGP block found
        return "UNENCRYPTED"

    except Exception:
        return "UNKNOWN"
