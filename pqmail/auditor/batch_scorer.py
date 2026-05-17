"""
Batch Scorer for PQMail Auditor.

Scores all emails in an mbox file against the HNDL risk model
and generates empirical statistics.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List
from pathlib import Path

from pqmail.auditor.mbox_reader import MboxReader
from pqmail.parser.mime_parser import parse
from pqmail.classifier.rule_classifier import classify
from pqmail.scorer.hndl_scorer import score


@dataclass
class EmailScore:
    """Individual email score result."""
    message_id: str
    from_addr: str
    to_addrs: List[str]
    algorithm: str
    sensitivity: str
    risk_category: str
    years_of_safety: int
    parse_error: str = None


@dataclass
class AuditStats:
    """Statistics from batch audit."""
    total_emails: int = 0
    successfully_parsed: int = 0
    parse_errors: int = 0
    
    # Algorithm distribution
    algorithms: Dict[str, int] = field(default_factory=dict)
    
    # Sensitivity distribution
    sensitivities: Dict[str, int] = field(default_factory=dict)
    
    # Risk distribution
    risk_categories: Dict[str, int] = field(default_factory=dict)
    
    # Statistics
    avg_years_of_safety: float = 0.0
    min_years_of_safety: int = 0
    max_years_of_safety: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_emails": self.total_emails,
            "successfully_parsed": self.successfully_parsed,
            "parse_errors": self.parse_errors,
            "algorithms": self.algorithms,
            "sensitivities": self.sensitivities,
            "risk_categories": self.risk_categories,
            "avg_years_of_safety": self.avg_years_of_safety,
            "min_years_of_safety": self.min_years_of_safety,
            "max_years_of_safety": self.max_years_of_safety,
        }


class BatchScorer:
    """Score all emails in an mbox file."""
    
    def __init__(self, mbox_path: str, quantum_timeline: int = 10):
        """
        Initialize batch scorer.
        
        Args:
            mbox_path: Path to .mbox file
            quantum_timeline: Assumed years until quantum threat (default: 10)
        """
        self.mbox_path = mbox_path
        self.quantum_timeline = quantum_timeline
        self.reader = MboxReader(mbox_path)
        self.results: List[EmailScore] = []
        self.stats = AuditStats()
    
    async def score_all(self, progress_callback=None) -> AuditStats:
        """
        Score all emails in the mbox file.
        
        Args:
            progress_callback: Optional async function(current, total) for progress
        
        Returns:
            AuditStats with aggregate results
        """
        self.results = []
        self.stats = AuditStats()
        
        total = self.reader.count_messages()
        self.stats.total_emails = total
        
        years_of_safety_values = []
        
        for idx, (msg_id, msg_bytes) in enumerate(self.reader.read_all()):
            if progress_callback:
                await progress_callback(idx + 1, total)
            
            try:
                # Parse email
                parsed = await parse(msg_bytes)
                
                if parsed.parse_error:
                    self.stats.parse_errors += 1
                    self.results.append(EmailScore(
                        message_id=msg_id,
                        from_addr=parsed.headers.get('from', 'unknown'),
                        to_addrs=parsed.headers.get('to', []),
                        algorithm="PARSE_ERROR",
                        sensitivity="UNKNOWN",
                        risk_category="UNKNOWN",
                        years_of_safety=0,
                        parse_error=parsed.parse_error,
                    ))
                    continue
                
                self.stats.successfully_parsed += 1
                
                # Classify
                classify_result = classify(parsed.body_text)
                sensitivity = classify_result.get('sensitivity', 'MEDIUM')
                
                # Score
                score_result = score(
                    parsed.algorithm,
                    sensitivity,
                    quantum_timeline=self.quantum_timeline,
                )
                
                # Record result
                email_score = EmailScore(
                    message_id=msg_id,
                    from_addr=parsed.headers.get('from', 'unknown'),
                    to_addrs=parsed.headers.get('to', []),
                    algorithm=score_result['algorithm'],
                    sensitivity=score_result['sensitivity'],
                    risk_category=score_result['risk_category'],
                    years_of_safety=score_result['years_of_safety_remaining'],
                )
                self.results.append(email_score)
                
                # Accumulate statistics
                alg = score_result['algorithm']
                self.stats.algorithms[alg] = self.stats.algorithms.get(alg, 0) + 1
                
                sens = score_result['sensitivity']
                self.stats.sensitivities[sens] = self.stats.sensitivities.get(sens, 0) + 1
                
                risk = score_result['risk_category']
                self.stats.risk_categories[risk] = self.stats.risk_categories.get(risk, 0) + 1
                
                years_of_safety_values.append(score_result['years_of_safety_remaining'])
            
            except Exception as e:
                self.stats.parse_errors += 1
                self.results.append(EmailScore(
                    message_id=msg_id,
                    from_addr="unknown",
                    to_addrs=[],
                    algorithm="UNKNOWN",
                    sensitivity="UNKNOWN",
                    risk_category="UNKNOWN",
                    years_of_safety=0,
                    parse_error=str(e),
                ))
        
        # Compute aggregate statistics
        if years_of_safety_values:
            self.stats.avg_years_of_safety = sum(years_of_safety_values) / len(years_of_safety_values)
            self.stats.min_years_of_safety = min(years_of_safety_values)
            self.stats.max_years_of_safety = max(years_of_safety_values)
        
        return self.stats
    
    def get_results_by_risk(self, risk_category: str = "CRITICAL") -> List[EmailScore]:
        """Get all emails matching a specific risk category."""
        return [r for r in self.results if r.risk_category == risk_category]
    
    def get_results_by_algorithm(self, algorithm: str) -> List[EmailScore]:
        """Get all emails using a specific algorithm."""
        return [r for r in self.results if r.algorithm == algorithm]
    
    def get_critical_unencrypted_count(self) -> int:
        """Get count of critical unencrypted emails."""
        return len([r for r in self.results 
                   if r.algorithm == "UNENCRYPTED" and r.risk_category == "CRITICAL"])
    
    def get_upgradeworthy_count(self) -> int:
        """Get count of emails that could be upgraded from RSA to HYBRID."""
        return len([r for r in self.results 
                   if r.algorithm in ("RSA", "ECDH") and r.risk_category in ("HIGH", "CRITICAL")])
    
    def print_summary(self) -> None:
        """Print human-readable audit summary."""
        print("\n" + "=" * 80)
        print("📊 PQMAIL AUDIT SUMMARY")
        print("=" * 80)
        
        print(f"\n📬 File: {self.mbox_path}")
        print(f"   Size: {self.reader.get_file_size_mb():.2f} MB")
        print(f"   Messages: {self.stats.total_emails}")
        print(f"   Parsed: {self.stats.successfully_parsed}")
        print(f"   Errors: {self.stats.parse_errors}")
        
        print(f"\n🔐 Algorithm Distribution:")
        for alg, count in sorted(self.stats.algorithms.items()):
            pct = (count / self.stats.successfully_parsed * 100) if self.stats.successfully_parsed else 0
            print(f"   {alg:15} {count:6} ({pct:5.1f}%)")
        
        print(f"\n⚠️  Sensitivity Distribution:")
        for sens, count in sorted(self.stats.sensitivities.items()):
            pct = (count / self.stats.successfully_parsed * 100) if self.stats.successfully_parsed else 0
            print(f"   {sens:15} {count:6} ({pct:5.1f}%)")
        
        print(f"\n🎯 Risk Distribution:")
        for risk, count in sorted(self.stats.risk_categories.items()):
            pct = (count / self.stats.successfully_parsed * 100) if self.stats.successfully_parsed else 0
            print(f"   {risk:15} {count:6} ({pct:5.1f}%)")
        
        print(f"\n📈 Years of Safety (Timeline: {self.quantum_timeline} years):")
        print(f"   Average: {self.stats.avg_years_of_safety:.1f} years")
        print(f"   Min: {self.stats.min_years_of_safety} years")
        print(f"   Max: {self.stats.max_years_of_safety} years")
        
        critical_unenc = self.get_critical_unencrypted_count()
        upgrade_worthy = self.get_upgradeworthy_count()
        print(f"\n🚨 Actionable Findings:")
        print(f"   Critical Unencrypted: {critical_unenc}")
        print(f"   Upgrade-worthy (RSA/ECDH): {upgrade_worthy}")
        
        print("\n" + "=" * 80 + "\n")
