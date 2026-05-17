"""
MIME Parser for PQMail.

This module parses raw email messages and extracts safe metadata and body parts.
Integrates with pgp_classifier to detect encryption algorithm.

Security rule:
- Do not write plaintext email content to disk or logs.
- Keep extracted body content in memory only.
"""

from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from pqmail.parser.pgp_classifier import classify_algorithm_from_mime


@dataclass
class ParsedEmail:
    """
    Structured representation of a parsed email.

    Attributes:
        raw_bytes: Original message bytes (untouched, never logged)
        headers: Safe metadata (From, To, Message-ID only — no body/subject)
        body_text: Plaintext body (in memory only)
        algorithm: Detected encryption algorithm (RSA|ECDH|HYBRID|UNENCRYPTED|SIGNED_ONLY|UNKNOWN)
        is_encrypted: Boolean flag whether encryption was detected
        parse_error: Error message if parsing failed, else None
    """
    raw_bytes: bytes
    headers: Dict[str, Any]
    body_text: str
    algorithm: str
    is_encrypted: bool
    parse_error: Optional[str] = None


def parse_raw_email(raw_data: bytes) -> EmailMessage:
    """
    Parse raw email bytes into an EmailMessage object.
    """
    if not isinstance(raw_data, bytes):
        raise TypeError("raw_data must be bytes")

    return BytesParser(policy=policy.default).parsebytes(raw_data)


def get_header(message: EmailMessage, header_name: str, default: str = "") -> str:
    """
    Safely fetch a header from an EmailMessage.
    """
    value = message.get(header_name)

    if value is None:
        return default

    return str(value)


def extract_addresses(message: EmailMessage, header_name: str) -> List[str]:
    """
    Extract addresses from To, Cc, or Bcc header.

    For MVP, this returns a simple comma-split list.
    Later, we can replace this with email.utils.getaddresses.
    """
    raw_value = get_header(message, header_name)

    if not raw_value:
        return []

    return [item.strip() for item in raw_value.split(",") if item.strip()]


def extract_body_parts(message: EmailMessage) -> Dict[str, str]:
    """
    Extract plain text and HTML body content from an email.

    Attachments are skipped.
    """
    plain_text_parts = []
    html_parts = []

    if message.is_multipart():
        for part in message.walk():
            content_disposition = part.get_content_disposition()
            content_type = part.get_content_type()

            if content_disposition == "attachment":
                continue

            if content_type == "text/plain":
                plain_text_parts.append(part.get_content())
            elif content_type == "text/html":
                html_parts.append(part.get_content())
    else:
        content_type = message.get_content_type()

        if content_type == "text/plain":
            plain_text_parts.append(message.get_content())
        elif content_type == "text/html":
            html_parts.append(message.get_content())

    return {
        "plain_text": "\n".join(plain_text_parts).strip(),
        "html": "\n".join(html_parts).strip(),
    }


def extract_attachments(message: EmailMessage) -> List[Dict[str, Any]]:
    """
    Extract attachment metadata only.

    Attachment content is not stored.
    """
    attachments = []

    for part in message.walk():
        if part.get_content_disposition() == "attachment":
            attachments.append(
                {
                    "filename": part.get_filename(),
                    "content_type": part.get_content_type(),
                    "size_bytes": len(part.get_payload(decode=True) or b""),
                }
            )

    return attachments


def parse_email_metadata(raw_data: bytes) -> Dict[str, Any]:
    """
    Parse raw email bytes and return metadata + body parts.
    """
    message = parse_raw_email(raw_data)
    body_parts = extract_body_parts(message)
    attachments = extract_attachments(message)

    return {
        "message_id": get_header(message, "Message-ID"),
        "from": get_header(message, "From"),
        "to": extract_addresses(message, "To"),
        "cc": extract_addresses(message, "Cc"),
        "bcc": extract_addresses(message, "Bcc"),
        "subject": get_header(message, "Subject", "(no subject)"),
        "date": get_header(message, "Date"),
        "content_type": message.get_content_type(),
        "plain_text": body_parts["plain_text"],
        "html": body_parts["html"],
        "attachments": attachments,
        "is_multipart": message.is_multipart(),
    }


async def parse(raw_data: bytes) -> ParsedEmail:
    """
    Parse raw email bytes into structured ParsedEmail with algorithm detection.

    Steps:
        1. Parse MIME structure
        2. Extract headers and body
        3. Detect PGP blocks and classify algorithm
        4. Return ParsedEmail dataclass

    Never writes content to disk or logs plaintext.

    Args:
        raw_data: Raw email bytes

    Returns:
        ParsedEmail: Structured representation with algorithm field
    """
    if not isinstance(raw_data, bytes):
        return ParsedEmail(
            raw_bytes=b"",
            headers={},
            body_text="",
            algorithm="UNKNOWN",
            is_encrypted=False,
            parse_error="Input must be bytes",
        )

    try:
        message = parse_raw_email(raw_data)

        # Extract safe headers (no subject to avoid content leakage)
        headers = {
            "message_id": get_header(message, "Message-ID"),
            "from": get_header(message, "From"),
            "to": extract_addresses(message, "To"),
            "cc": extract_addresses(message, "Cc"),
            "bcc": extract_addresses(message, "Bcc"),
            "date": get_header(message, "Date"),
        }

        # Extract body (in memory only)
        body_parts = extract_body_parts(message)
        body_text = body_parts.get("plain_text", "")

        # Detect algorithm
        algorithm = classify_algorithm_from_mime(message)
        is_encrypted = algorithm != "UNENCRYPTED" and algorithm != "UNKNOWN"

        return ParsedEmail(
            raw_bytes=raw_data,
            headers=headers,
            body_text=body_text,
            algorithm=algorithm,
            is_encrypted=is_encrypted,
            parse_error=None,
        )

    except Exception as e:
        return ParsedEmail(
            raw_bytes=raw_data,
            headers={},
            body_text="",
            algorithm="PARSE_ERROR",
            is_encrypted=False,
            parse_error=str(e),
        )