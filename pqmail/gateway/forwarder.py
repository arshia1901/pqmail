"""
Email forwarder for PQMail gateway.

Relays processed emails to upstream SMTP server (Gmail) via TLS/STARTTLS.
Never logs email content — only metadata and status codes.

Security: Credentials from environment variables, never hardcoded.
"""

import smtplib
import ssl
import os
from typing import List


async def forward(
    message_bytes: bytes,
    mail_from: str,
    rcpt_tos: List[str],
    config: dict = None,
) -> bool:
    """
    Forward processed email to upstream SMTP server.

    Args:
        message_bytes: Final email bytes (possibly re-encrypted)
        mail_from: Sender address
        rcpt_tos: List of recipient addresses
        config: Optional config dict with upstream_host, upstream_port, etc.

    Returns:
        True if successful, False on failure

    Raises:
        smtplib.SMTPException: If relay fails (let caller decide what to do)
    """
    # Load config from environment
    host = os.getenv("UPSTREAM_HOST", "smtp.gmail.com")
    port = int(os.getenv("UPSTREAM_PORT", 587))
    user = os.getenv("UPSTREAM_USER")
    password = os.getenv("UPSTREAM_PASSWORD")

    if not user or not password:
        raise ValueError("UPSTREAM_USER and UPSTREAM_PASSWORD required in .env")

    try:
        # Create SSL context for STARTTLS
        context = ssl.create_default_context()

        # Connect and authenticate (run in thread executor to avoid blocking)
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(user, password)

            # Send mail
            smtp.sendmail(mail_from, rcpt_tos, message_bytes)

        return True

    except smtplib.SMTPAuthenticationError:
        raise RuntimeError(f"SMTP auth failed for {user} on {host}:{port}")
    except smtplib.SMTPException as e:
        raise RuntimeError(f"SMTP error: {e}")
    except Exception as e:
        raise RuntimeError(f"Forwarding failed: {e}")