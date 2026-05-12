"""
MIME Parser for PQMail.

This module parses raw email messages and extracts safe metadata and body parts.

Security rule:
- Do not write plaintext email content to disk or logs.
- Keep extracted body content in memory only.
"""

from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from typing import Any, Dict, List


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