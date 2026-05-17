"""Tests for PGP algorithm classification."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
ROOT_STR = str(ROOT)

if ROOT_STR not in sys.path:
    sys.path.insert(0, ROOT_STR)

import pytest

from pqmail.parser.pgp_classifier import (
    extract_pgp_block,
    classify_algorithm_from_mime,
)


class MockPGPMessage:
    """Mock pgpy.PGPMessage for testing."""

    def __init__(self, packets):
        self.packets = packets


class MockPacket:
    """Mock packet with pkalg attribute."""

    def __init__(self, pkalg):
        self.pkalg = pkalg


def test_extract_pgp_block_found():
    """Extract PGP block from payload."""
    payload = """Some text before
-----BEGIN PGP MESSAGE-----
Version: 1.0

jA0ECQMI...encrypted...
-----END PGP MESSAGE-----
Some text after"""

    result = extract_pgp_block(payload)

    assert result is not None
    assert "-----BEGIN PGP MESSAGE-----" in result
    assert "-----END PGP MESSAGE-----" in result


def test_extract_pgp_block_not_found():
    """No PGP block in payload."""
    payload = "Just some plain text without encryption"

    result = extract_pgp_block(payload)

    assert result is None


def test_extract_pgp_block_empty():
    """Empty payload."""
    result = extract_pgp_block("")

    assert result is None


def test_extract_pgp_block_none():
    """None payload."""
    result = extract_pgp_block(None)

    assert result is None


def test_classify_mime_unencrypted():
    """Plain MIME message without PGP → UNENCRYPTED."""
    # Create mock EmailMessage
    class MockMessage:
        def get_content_type(self):
            return "text/plain"

        def is_multipart(self):
            return False

        def get_content(self):
            return "Just plain text"

        def walk(self):
            return []

    msg = MockMessage()
    result = classify_algorithm_from_mime(msg)

    assert result == "UNENCRYPTED"


def test_classify_mime_none():
    """None message."""
    result = classify_algorithm_from_mime(None)

    assert result == "UNENCRYPTED"


def test_classify_mime_exception():
    """Exception during classification."""
    class BadMessage:
        def get_content_type(self):
            raise ValueError("Boom")

    msg = BadMessage()
    result = classify_algorithm_from_mime(msg)

    assert result == "UNKNOWN"
