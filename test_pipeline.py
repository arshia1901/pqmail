#!/usr/bin/env python
"""
Quick test script to run emails from mailbox.mbox through the PQMail pipeline.

Usage:
    python test_pipeline.py [--limit N]

Shows parse results, classification, scoring, and decision routing for each email.
"""

import sys
from pathlib import Path
import asyncio
from mailbox import mbox

# Bootstrap path for direct execution
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pqmail.parser.mime_parser import parse
from pqmail.classifier.rule_classifier import classify
from pqmail.scorer.hndl_scorer import score
from pqmail.fallback.decision import decide


async def test_email_pipeline(mbox_path: str, limit: int = None):
    """Test pipeline on emails from mbox file."""
    mbox_file = mbox(mbox_path)
    
    print(f"\n📬 Reading emails from: {mbox_path}")
    print("=" * 80)
    
    count = 0
    for msg_key, msg in mbox_file.items():
        if limit and count >= limit:
            break
        
        count += 1
        
        # Get raw email bytes
        msg_bytes = msg.as_bytes()
        
        print(f"\n[Email {count}]")
        print("-" * 80)
        
        # Step 1: Parse
        parsed = await parse(msg_bytes)
        print(f"✓ Parsed: algorithm={parsed.algorithm}, from={parsed.headers.get('from', 'unknown')}")
        
        if parsed.parse_error:
            print(f"  ⚠ Parse error: {parsed.parse_error}")
            continue
        
        # Step 2: Classify sensitivity
        sensitivity_result = classify(parsed.body_text)
        sensitivity = sensitivity_result.get('sensitivity', 'MEDIUM')
        print(f"✓ Classified: sensitivity={sensitivity}")
        
        # Step 3: Score risk (assume 10-year timeline)
        result = score(parsed.algorithm, sensitivity, quantum_timeline=10)
        print(f"✓ Scored: risk_category={result['risk_category']}, years_safe={result['years_of_safety_remaining']}")
        
        # Step 4: Decide action (MVP assumes all recipients have keys)
        decision = decide(parsed, ["recipient@example.com"])
        print(f"✓ Decision: action={decision['action']}, reason={decision.get('flag', decision.get('upgrade_reason', 'N/A'))}")
        
        # Show email metadata
        to_addrs = parsed.headers.get('to', 'unknown')
        msg_id = parsed.headers.get('message_id', 'unknown')
        print(f"  Message-ID: {msg_id[:60] if msg_id else 'N/A'}...")
        print(f"  To: {to_addrs[:60] if to_addrs else 'N/A'}...")
    
    print("\n" + "=" * 80)
    print(f"✅ Processed {count} emails")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test PQMail pipeline on mbox file")
    parser.add_argument("--mbox", default="samples/mailbox.mbox", help="Path to .mbox file")
    parser.add_argument("--limit", type=int, default=5, help="Max emails to process")
    
    args = parser.parse_args()
    
    asyncio.run(test_email_pipeline(args.mbox, args.limit))
