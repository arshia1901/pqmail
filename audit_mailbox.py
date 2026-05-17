#!/usr/bin/env python
"""
Auditor CLI for PQMail.

Usage:
    python audit_mailbox.py [mbox_path] [--timeline N]

Scores all emails in an mbox file and generates a risk report.
"""

import sys
from pathlib import Path
import asyncio
import json

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pqmail.auditor.batch_scorer import BatchScorer


async def main():
    """Run auditor on mailbox file."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Audit mailbox for quantum-safe encryption")
    parser.add_argument("mbox", nargs='?', default="samples/mailbox.mbox", 
                       help="Path to .mbox file")
    parser.add_argument("--timeline", type=int, default=10,
                       help="Quantum threat timeline in years (default: 10)")
    parser.add_argument("--json", action="store_true",
                       help="Output results as JSON")
    
    args = parser.parse_args()
    
    mbox_path = Path(args.mbox)
    
    if not mbox_path.exists():
        print(f"❌ Mailbox file not found: {mbox_path}")
        sys.exit(1)
    
    print(f"\n🔍 Starting audit of {mbox_path.name}...")
    
    scorer = BatchScorer(str(mbox_path), quantum_timeline=args.timeline)
    
    # Progress callback
    async def show_progress(current, total):
        pct = (current / total * 100) if total > 0 else 0
        print(f"   Progress: {current}/{total} ({pct:.0f}%)", end='\r')
    
    stats = await scorer.score_all(progress_callback=show_progress)
    
    if args.json:
        # Output as JSON
        output = {
            "stats": stats.to_dict(),
            "critical_emails": [
                {
                    "message_id": r.message_id,
                    "from": r.from_addr,
                    "algorithm": r.algorithm,
                    "risk": r.risk_category,
                }
                for r in scorer.get_results_by_risk("CRITICAL")[:10]
            ]
        }
        print(json.dumps(output, indent=2))
    else:
        # Print summary
        scorer.print_summary()
        
        # Show critical emails
        critical = scorer.get_results_by_risk("CRITICAL")
        if critical:
            print(f"🚨 Top 5 Critical Risk Emails:")
            print("-" * 80)
            for i, r in enumerate(critical[:5], 1):
                print(f"{i}. From: {r.from_addr}")
                print(f"   Algorithm: {r.algorithm}")
                print(f"   Message-ID: {r.message_id[:70]}...")
                print()


if __name__ == "__main__":
    asyncio.run(main())
