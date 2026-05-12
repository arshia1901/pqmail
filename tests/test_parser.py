import pytest

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