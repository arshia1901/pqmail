"""Tests for fallback decision logic."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
ROOT_STR = str(ROOT)

if ROOT_STR not in sys.path:
    sys.path.insert(0, ROOT_STR)

import pytest

from pqmail.fallback.decision import decide
from pqmail.parser.mime_parser import ParsedEmail


@pytest.fixture
def sample_parsed_rsa():
    """ParsedEmail with RSA algorithm."""
    return ParsedEmail(
        raw_bytes=b"dummy",
        headers={"message_id": "<test@example.com>"},
        body_text="Test",
        algorithm="RSA",
        is_encrypted=True,
        parse_error=None,
    )


@pytest.fixture
def sample_parsed_hybrid():
    """ParsedEmail with HYBRID algorithm."""
    return ParsedEmail(
        raw_bytes=b"dummy",
        headers={"message_id": "<test@example.com>"},
        body_text="Test",
        algorithm="HYBRID",
        is_encrypted=True,
        parse_error=None,
    )


@pytest.fixture
def sample_parsed_unencrypted():
    """ParsedEmail with no encryption."""
    return ParsedEmail(
        raw_bytes=b"dummy",
        headers={"message_id": "<test@example.com>"},
        body_text="Test",
        algorithm="UNENCRYPTED",
        is_encrypted=False,
        parse_error=None,
    )


@pytest.fixture
def sample_parsed_error():
    """ParsedEmail with parse error."""
    return ParsedEmail(
        raw_bytes=b"dummy",
        headers={},
        body_text="",
        algorithm="PARSE_ERROR",
        is_encrypted=False,
        parse_error="Invalid PGP format",
    )


def test_decide_rsa_upgrade():
    """RSA algorithm with keys available → UPGRADE."""
    parsed = ParsedEmail(
        raw_bytes=b"",
        headers={},
        body_text="",
        algorithm="RSA",
        is_encrypted=True,
    )
    result = decide(parsed, ["alice@example.com"], has_recipient_keys=True)

    assert result["action"] == "UPGRADE"
    assert "upgrade_reason" in result


def test_decide_hybrid_forward(sample_parsed_hybrid):
    """Hybrid already quantum-safe → FORWARD (no action)."""
    result = decide(sample_parsed_hybrid, ["alice@example.com"])

    assert result["action"] == "FORWARD"
    assert "quantum-safe" in result["flag"].lower()


def test_decide_unencrypted_flag(sample_parsed_unencrypted):
    """Unencrypted plaintext email without keys → FLAG for review."""
    result = decide(sample_parsed_unencrypted, ["alice@example.com"], has_recipient_keys=False)

    assert result["action"] == "FLAG"
    assert "plaintext" in result["flag"].lower()


def test_decide_parse_error_flag(sample_parsed_error):
    """Parse error → FLAG for manual review."""
    result = decide(sample_parsed_error, ["alice@example.com"])

    assert result["action"] == "FLAG"
    assert "parse error" in result["flag"].lower()


def test_decide_ecdh_upgrade():
    """ECDH vulnerable algorithm → UPGRADE."""
    parsed = ParsedEmail(
        raw_bytes=b"",
        headers={},
        body_text="",
        algorithm="ECDH",
        is_encrypted=True,
    )
    result = decide(parsed, ["alice@example.com"], has_recipient_keys=True)

    assert result["action"] == "UPGRADE"


def test_decide_signed_only_upgrade():
    """Signature-only message with keys → upgrade to hybrid."""
    parsed = ParsedEmail(
        raw_bytes=b"",
        headers={},
        body_text="",
        algorithm="SIGNED_ONLY",
        is_encrypted=False,
    )
    result = decide(parsed, ["alice@example.com"], has_recipient_keys=True)

    assert result["action"] == "UPGRADE"


def test_decide_unknown_flag():
    """Unknown algorithm → FLAG."""
    parsed = ParsedEmail(
        raw_bytes=b"",
        headers={},
        body_text="",
        algorithm="UNKNOWN",
        is_encrypted=False,
    )
    result = decide(parsed, ["alice@example.com"])

    assert result["action"] == "FLAG"
