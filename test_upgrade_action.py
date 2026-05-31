#!/usr/bin/env python3
"""
Send a test unencrypted email to angeleo.angelei@gmail.com through the gateway.
This should trigger UPGRADE action since we have keys stored for that recipient.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


def send_test_email():
    """Send unencrypted test email to recipient with keys."""
    
    # Email details
    sender = "test@local.com"
    recipient = "angeleo.angelei@gmail.com"
    subject = f"UPGRADE TEST - {datetime.now().isoformat()}"
    body = """This is a plaintext test email.

It should trigger the UPGRADE action in the gateway because:
1. Email is UNENCRYPTED
2. Recipient (angeleo.angelei@gmail.com) has ML-KEM + X25519 keys stored
3. Gateway will re-encrypt with hybrid KEM before forwarding

Expected flow:
  UNENCRYPTED → KEY CHECK → HAS KEYS → UPGRADE → HYBRID ENCRYPT → FORWARD

Check the dashboard at http://localhost:5173 to see:
- algorithm: UNENCRYPTED (original)
- upgraded: true (action taken)
- risk: CRITICAL (unencrypted email)
"""
    
    # Create message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    
    part = MIMEText(body, "plain")
    msg.attach(part)
    
    # Send via gateway on localhost:1025
    print(f"📧 Sending test email:")
    print(f"   From: {sender}")
    print(f"   To: {recipient}")
    print(f"   Subject: {subject}")
    print(f"   Body: Plaintext (unencrypted)")
    print()
    
    try:
        server = smtplib.SMTP("localhost", 1025, timeout=5)
        server.sendmail(sender, [recipient], msg.as_string())
        server.quit()
        print("✅ Email sent successfully to gateway")
        print()
        print("🔍 Check the dashboard at http://localhost:5173")
        print("   Look for:")
        print("   - algorithm: UNENCRYPTED")
        print("   - upgraded: true")
        print("   - action: UPGRADE")
        return True
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False


if __name__ == "__main__":
    success = send_test_email()
    exit(0 if success else 1)
