"""
PQMail SMTP Proxy Gateway.

This is the core of the project. Acts as a local SMTP server that Thunderbird
connects to (instead of Gmail), intercepts every outgoing email, runs the
processing pipeline (parse → score → decide → optionally re-encrypt), and
forwards to Gmail.

Security rules:
1. Plaintext never touches disk
2. No email content in logs
3. Credentials from environment, never hardcoded
4. Forward on failure — catch exceptions, log error type only
"""

import asyncio
import os
from datetime import datetime
from typing import Optional

import aiohttp
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage

from pqmail.parser.mime_parser import parse
from pqmail.scorer.hndl_scorer import score
from pqmail.classifier.rule_classifier import classify
from pqmail.fallback.decision import decide
from pqmail.crypto.hybrid_kem import re_encrypt_message
from pqmail.gateway.forwarder import forward


class PQMailHandler(AsyncMessage):
    """
    aiosmtpd SMTP handler for PQMail gateway.

    For each email received (handle_DATA):
    1. Parse MIME + detect algorithm
    2. Classify content sensitivity
    3. Score HNDL risk
    4. Decide action (upgrade / forward / flag)
    5. Optionally re-encrypt
    6. Push event to React dashboard
    7. Forward to Gmail
    """

    def __init__(self, config: dict = None):
        """Initialize handler with optional config."""
        super().__init__()
        self.config = config or {}
    
    async def handle_message(self, message):
        """Required abstract method - not used, handle_DATA does the work."""
        pass

    async def handle_DATA(self, server, session, envelope) -> str:
        """
        Handle incoming email from Thunderbird.

        Args:
            server: aiosmtpd server instance
            session: Session object with EHLO data
            envelope: SMTP envelope with mail_from, rcpt_tos, content

        Returns:
            SMTP response string (e.g., "250 Message accepted")
        """

        raw_bytes = envelope.content
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos

        try:
            # ========== Step 1: Parse MIME + detect algorithm ==========
            parsed = await parse(raw_bytes)

            # ========== Step 2: Classify content sensitivity ==========
            # For MVP: use subject as hint (in production, decrypt and classify body)
            subject_hint = parsed.headers.get("from", "")
            sensitivity_result = classify(subject_hint)
            sensitivity = sensitivity_result.get("sensitivity", "MEDIUM")

            # ========== Step 3: Score HNDL risk ==========
            quantum_timeline = int(os.getenv("QUANTUM_TIMELINE_YEARS", 10))
            risk_score = score(parsed.algorithm, sensitivity, quantum_timeline)

            # ========== Step 4: Decide action ==========
            decision = decide(parsed, rcpt_tos)
            action = decision.get("action", "FORWARD")

            # ========== Step 5: Optional re-encryption ==========
            final_bytes = raw_bytes
            if action == "UPGRADE":
                try:
                    final_bytes = await re_encrypt_message(parsed, rcpt_tos)
                    risk_score["upgraded"] = True
                except Exception as e:
                    # Crypto error: forward original unchanged, log error type only
                    print(f"[PQMail] Crypto error (type: {type(e).__name__}) — forwarding original")
                    risk_score["upgraded"] = False
            else:
                risk_score["upgraded"] = False

            # ========== Step 6: Push event to React ==========
            try:
                event = {
                    "timestamp": datetime.now().isoformat(),
                    "message_id": parsed.headers.get("message_id", "unknown"),
                    "from": mail_from,
                    "to": rcpt_tos,
                    "algorithm": parsed.algorithm,
                    "sensitivity": sensitivity,
                    "risk": risk_score,
                    "action": action,
                    "flag": decision.get("flag", ""),
                }
                # Push event to backend via HTTP (separate process)
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        "http://localhost:8000/push_event",
                        json=event,
                        timeout=aiohttp.ClientTimeout(total=2)
                    ) as resp:
                        if resp.status != 200:
                            print(f"[PQMail] Event push failed: HTTP {resp.status}")
            except Exception as e:
                print(f"[PQMail] Event push failed: {type(e).__name__}")

            # ========== Step 7: Forward to Gmail ==========
            forward_status = "skipped"
            if os.getenv("UPSTREAM_USER") and os.getenv("UPSTREAM_PASSWORD"):
                try:
                    await forward(final_bytes, mail_from, rcpt_tos, self.config)
                    forward_status = "success"
                except Exception as e:
                    forward_status = f"error ({type(e).__name__})"
                    print(f"[PQMail] Forward failed: {e}")
            else:
                print(f"[PQMail] Forward skipped (no UPSTREAM credentials in .env)")

            print(
                f"[PQMail] ✓ {mail_from[:20]}... → {rcpt_tos[0][:20]}... "
                f"[{parsed.algorithm}|{risk_score['risk_category']}|{action}|forward:{forward_status}]"
            )

            return "250 Message accepted for delivery"

        except Exception as e:
            # Catch-all: unexpected error — log type, don't leak content
            print(f"[PQMail] Unexpected error in handle_DATA: {type(e).__name__}")
            # Forward original unchanged if possible
            try:
                await forward(raw_bytes, mail_from, rcpt_tos, self.config)
                return "250 Message accepted (error recovery)"
            except Exception:
                return "421 Service not available"


async def start_gateway(config: dict = None):
    """
    Start the PQMail SMTP proxy on localhost:1025 (configurable).

    Args:
        config: Optional dict with listen_port, upstream_host, etc.
    """
    from pqmail.api.events import init_event_queue

    # Initialize event queue for React dashboard
    init_event_queue()

    config = config or {}
    listen_port = int(os.getenv("PQMAIL_LISTEN_PORT", 1025))
    listen_host = os.getenv("PQMAIL_LISTEN_HOST", "127.0.0.1")

    handler = PQMailHandler(config)
    controller = Controller(handler, hostname=listen_host, port=listen_port)

    print(f"[PQMail] Gateway starting on {listen_host}:{listen_port}")
    controller.start()

    try:
        await asyncio.Event().wait()  # Run forever
    except KeyboardInterrupt:
        print("[PQMail] Gateway stopping...")
        controller.stop()


def run_gateway_sync(config: dict = None):
    """
    Run gateway synchronously (for CLI entry point).

    Args:
        config: Optional config dict
    """
    asyncio.run(start_gateway(config))