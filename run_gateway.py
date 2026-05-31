#!/usr/bin/env python
"""
Launch PQMail SMTP Proxy Gateway.

Starts the SMTP server on localhost:1025
Listens for emails from Thunderbird/email clients
Processes through the full pipeline (parse → classify → score → decide → forward)
"""

import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import asyncio
from dotenv import load_dotenv
from pqmail.gateway.proxy import run_gateway_sync

# Load environment variables from .env
load_dotenv(ROOT / ".env")

if __name__ == "__main__":
    print("🚀 Starting PQMail SMTP Proxy Gateway...")
    print("📍 Listening on: localhost:1025")
    print("📧 Forwarding to: Gmail SMTP")
    print("\nConfigure your email client to use:")
    print("   Host: localhost")
    print("   Port: 1025")
    print("   Security: None")
    print("\nPress Ctrl+C to stop\n")
    
    try:
        run_gateway_sync()
    except KeyboardInterrupt:
        print("\n✓ Gateway stopped")
        sys.exit(0)
