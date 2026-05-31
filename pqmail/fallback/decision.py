"""
Fallback decision logic for PQMail gateway.

Determines the action to take per email based on:
- Detected algorithm
- Content sensitivity
- Availability of recipient ML-KEM keys

Actions:
- UPGRADE: Re-encrypt with hybrid ML-KEM-768 + X25519
- FORWARD: Send as-is (no keys available, or already hybrid)
- FLAG: Mark for manual review (parse error, etc.)

Security: No plaintext content logged — only algorithm and key status.
"""

from typing import Dict, Any, List
from pqmail.parser.mime_parser import ParsedEmail


def decide(parsed: ParsedEmail, rcpt_tos: List[str], has_recipient_keys: bool = False) -> Dict[str, Any]:
    """
    Decide action for an email based on algorithm and recipient availability.

    Decision matrix:

    | Algorithm    | Has ML-KEM keys? | Action     | Reason                                    |
    |---|---|---|---|
    | RSA          | Yes              | UPGRADE    | Vulnerable algorithm, keys available     |
    | RSA          | No               | FORWARD    | Vulnerable but no keys; can't upgrade     |
    | ECDH         | Yes              | UPGRADE    | Vulnerable algorithm, keys available     |
    | ECDH         | No               | FORWARD    | Vulnerable but no keys; can't upgrade     |
    | HYBRID       | —                | FORWARD    | Already quantum-safe, no action needed    |
    | UNENCRYPTED  | Yes              | UPGRADE    | Plaintext email, keys available for re-encryption |
    | UNENCRYPTED  | No               | FLAG       | Plaintext email; security concern         |
    | SIGNED_ONLY  | Yes              | UPGRADE    | Sign + encrypt hybrid for complete PQC    |
    | SIGNED_ONLY  | No               | FORWARD    | Sign-only, no keys; send as-is            |
    | PARSE_ERROR  | —                | FLAG       | Can't understand; manual review           |
    | UNKNOWN      | —                | FLAG       | Unknown algorithm; manual review          |

    Args:
        parsed: ParsedEmail from parser
        rcpt_tos: List of recipient email addresses
        has_recipient_keys: Whether recipient has ML-KEM keys available

    Returns:
        Dict with action and reason:
            {
                "action": "UPGRADE" | "FORWARD" | "FLAG",
                "flag": "reason string",
                "upgrade_reason": "explanation if action=UPGRADE"
            }
    """
    algorithm = parsed.algorithm

    if algorithm == "PARSE_ERROR":
        return {
            "action": "FLAG",
            "flag": f"Parse error: {parsed.parse_error}",
        }

    if algorithm == "UNKNOWN":
        return {
            "action": "FLAG",
            "flag": "Unknown algorithm; cannot proceed safely",
        }

    if algorithm == "UNENCRYPTED":
        if has_recipient_keys:
            return {
                "action": "UPGRADE",
                "flag": "Plaintext email; upgrading to hybrid encryption",
                "upgrade_reason": "Email is unencrypted; ML-KEM keys available for recipient",
            }
        else:
            return {
                "action": "FLAG",
                "flag": "Plaintext email; recommend enabling encryption",
            }

    if algorithm == "HYBRID":
        return {
            "action": "FORWARD",
            "flag": "Already quantum-safe (hybrid); no action needed",
        }

    if algorithm in ("RSA", "ECDH", "SIGNED_ONLY"):
        if has_recipient_keys:
            return {
                "action": "UPGRADE",
                "flag": f"Upgrading {algorithm} to hybrid ML-KEM-768+X25519",
                "upgrade_reason": f"Algorithm {algorithm} vulnerable; ML-KEM keys available",
            }
        else:
            return {
                "action": "FORWARD",
                "flag": f"No ML-KEM keys for recipients; cannot upgrade {algorithm}",
            }

    return {
        "action": "FLAG",
        "flag": f"Unknown algorithm state: {algorithm}",
    }
