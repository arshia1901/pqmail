from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
ROOT_STR = str(ROOT)

if ROOT_STR not in sys.path:
    sys.path.insert(0, ROOT_STR)

from pqmail.parser.mime_parser import (
    extract_addresses,
    get_header,
    parse_email_metadata,
    parse_raw_email,
)


SIMPLE_EMAIL = b"""From: alice@example.com
To: bob@example.com
Subject: Test Email
Message-ID: <test-1@example.com>
Content-Type: text/plain; charset=utf-8

Hello Bob,
This is a test email.
"""


MULTIPART_EMAIL = b"""From: alice@example.com
To: bob@example.com, charlie@example.com
Cc: dave@example.com
Subject: Multipart Test
Message-ID: <test-2@example.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=utf-8

Plain text version.

--boundary123
Content-Type: text/html; charset=utf-8

<html><body><p>HTML version.</p></body></html>

--boundary123--
"""


def test_parse_raw_email_requires_bytes():
    with pytest.raises(TypeError):
        parse_raw_email("not bytes")


def test_parse_simple_email_metadata():
    result = parse_email_metadata(SIMPLE_EMAIL)

    assert result["from"] == "alice@example.com"
    assert result["to"] == ["bob@example.com"]
    assert result["subject"] == "Test Email"
    assert result["message_id"] == "<test-1@example.com>"
    assert "Hello Bob" in result["plain_text"]
    assert result["html"] == ""
    assert result["is_multipart"] is False


def test_parse_multipart_email_metadata():
    result = parse_email_metadata(MULTIPART_EMAIL)

    assert result["from"] == "alice@example.com"
    assert result["to"] == ["bob@example.com", "charlie@example.com"]
    assert result["cc"] == ["dave@example.com"]
    assert result["subject"] == "Multipart Test"
    assert "Plain text version" in result["plain_text"]
    assert "HTML version" in result["html"]
    assert result["is_multipart"] is True


def test_get_header_default_value():
    message = parse_raw_email(SIMPLE_EMAIL)

    assert get_header(message, "X-Missing", "default") == "default"


def test_extract_addresses_empty_header():
    message = parse_raw_email(SIMPLE_EMAIL)

    assert extract_addresses(message, "Bcc") == []


@pytest.mark.asyncio
async def test_parse_simple_email_async():
    """Test the new async parse() function with ParsedEmail output."""
    from pqmail.parser.mime_parser import parse

    result = await parse(SIMPLE_EMAIL)

    assert isinstance(result.raw_bytes, bytes)
    assert result.headers["from"] == "alice@example.com"
    assert result.algorithm == "UNENCRYPTED"
    assert result.is_encrypted is False
    assert result.parse_error is None


@pytest.mark.asyncio
async def test_parse_multipart_email_async():
    """Test async parse with multipart email."""
    from pqmail.parser.mime_parser import parse

    result = await parse(MULTIPART_EMAIL)

    assert result.algorithm == "UNENCRYPTED"
    assert "Plain text version" in result.body_text
    assert result.is_encrypted is False


@pytest.mark.asyncio
async def test_parse_invalid_bytes():
    """Test parse with non-bytes input."""
    from pqmail.parser.mime_parser import parse

    # Should not raise, returns ParsedEmail with error
    result = await parse("not bytes")

    assert result.parse_error is not None
    assert "must be bytes" in result.parse_error