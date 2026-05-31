"""
HTML Report Generator for PQMail.

Generates static HTML security reports from email audit data.
Used for academic papers, compliance documentation, and risk dashboards.

Example:
    reporter = ReportGenerator("samples/mailbox.mbox", output_dir="reports/")
    report_path = await reporter.generate()
    # Output: reports/report_2026-05-18_14-32-45.html
"""

import asyncio
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from jinja2 import Environment, FileSystemLoader

from pqmail.auditor.batch_scorer import BatchScorer


@dataclass
class ReportData:
    """Data structure for HTML template."""
    generated_at: str
    mailbox_path: str
    total_emails: int
    
    # Aggregates
    by_algorithm: Dict[str, int]
    by_sensitivity: Dict[str, int]
    by_risk_category: Dict[str, int]
    
    # Risk Metrics
    avg_years_of_safety: float
    critical_count: int
    hybrid_count: int
    defense_horizon_total_years: int
    
    # Email samples (top emails by risk)
    critical_emails: List[Dict]
    unencrypted_emails: List[Dict]
    hybrid_emails: List[Dict]
    
    # Metadata
    quantum_timeline_years: int


class ReportGenerator:
    """Generate HTML security reports from email audits."""
    
    def __init__(
        self,
        mbox_path: str,
        output_dir: Optional[str] = None,
        quantum_timeline_years: int = 10
    ):
        """
        Initialize report generator.
        
        Args:
            mbox_path: Path to .mbox mailbox file
            output_dir: Directory to save report (default: current directory)
            quantum_timeline_years: Years until quantum threat (default: 10)
        """
        self.mbox_path = Path(mbox_path)
        self.output_dir = Path(output_dir or Path.cwd())
        self.quantum_timeline_years = quantum_timeline_years
        
        if not self.mbox_path.exists():
            raise FileNotFoundError(f"Mailbox not found: {self.mbox_path}")
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def generate(self) -> Path:
        """
        Generate HTML report from mailbox.
        
        Returns:
            Path to generated report file
        """
        # Step 1: Score mailbox
        scorer = BatchScorer(str(self.mbox_path), quantum_timeline=self.quantum_timeline_years)
        stats = await scorer.score_all()
        
        # Step 2: Extract results and calculate aggregates
        report_data = self._calculate_aggregates(scorer, stats)
        
        # Step 3: Render template
        html_content = self._render_template(report_data)
        
        # Step 4: Save to disk
        report_path = self._save_report(html_content)
        
        return report_path
    
    def _calculate_aggregates(self, scorer: BatchScorer, stats: any) -> ReportData:
        """Calculate statistics from scoring results."""
        
        # Get all results from scorer
        results = scorer.results  # EmailScore objects
        
        # Initialize counters
        by_algorithm = {}
        by_sensitivity = {}
        by_risk_category = {}
        critical_emails = []
        unencrypted_emails = []
        hybrid_emails = []
        
        total_years_of_safety = 0.0
        hybrid_count = 0
        critical_count = 0
        
        # Process each email result
        for result in results:
            algorithm = result.algorithm
            sensitivity = result.sensitivity
            risk_category = result.risk_category
            years_of_safety = result.years_of_safety
            from_addr = result.from_addr
            to_addr = result.to_addrs[0] if result.to_addrs else "unknown"
            
            # Count by algorithm
            by_algorithm[algorithm] = by_algorithm.get(algorithm, 0) + 1
            
            # Count by sensitivity
            by_sensitivity[sensitivity] = by_sensitivity.get(sensitivity, 0) + 1
            
            # Count by risk category
            by_risk_category[risk_category] = by_risk_category.get(risk_category, 0) + 1
            
            # Accumulate metrics
            total_years_of_safety += years_of_safety
            if algorithm == "HYBRID":
                hybrid_count += 1
            if risk_category == "CRITICAL":
                critical_count += 1
            
            # Collect samples
            email_sample = {
                "from": from_addr,
                "to": to_addr,
                "algorithm": algorithm,
                "risk_category": risk_category,
                "years_of_safety": years_of_safety,
                "sensitivity": sensitivity,
            }
            
            if risk_category == "CRITICAL":
                critical_emails.append(email_sample)
            if algorithm == "UNENCRYPTED":
                unencrypted_emails.append(email_sample)
            if algorithm == "HYBRID":
                hybrid_emails.append(email_sample)
        
        # Sort and limit samples
        critical_emails = sorted(
            critical_emails,
            key=lambda x: x["years_of_safety"]
        )[:20]
        unencrypted_emails = sorted(
            unencrypted_emails,
            key=lambda x: x["years_of_safety"]
        )[:20]
        hybrid_emails = sorted(
            hybrid_emails,
            key=lambda x: x["years_of_safety"],
            reverse=True
        )[:20]
        
        # Calculate averages
        avg_years_of_safety = (
            total_years_of_safety / len(results) if results else 0.0
        )
        
        defense_horizon_total = sum(
            result.years_of_safety
            for result in results
        )
        
        return ReportData(
            generated_at=datetime.now().isoformat(),
            mailbox_path=str(self.mbox_path),
            total_emails=len(results),
            by_algorithm=by_algorithm,
            by_sensitivity=by_sensitivity,
            by_risk_category=by_risk_category,
            avg_years_of_safety=round(avg_years_of_safety, 2),
            critical_count=critical_count,
            hybrid_count=hybrid_count,
            defense_horizon_total_years=defense_horizon_total,
            critical_emails=critical_emails,
            unencrypted_emails=unencrypted_emails,
            hybrid_emails=hybrid_emails,
            quantum_timeline_years=self.quantum_timeline_years,
        )
    
    def _render_template(self, data: ReportData) -> str:
        """Render Jinja2 template with report data."""
        template_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        template = env.get_template("risk_report.html.j2")
        
        # Convert dataclass to dict for Jinja2
        return template.render(**asdict(data))
    
    def _save_report(self, html_content: str) -> Path:
        """Save HTML report to disk with timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"report_{timestamp}.html"
        report_path = self.output_dir / filename
        
        report_path.write_text(html_content, encoding='utf-8')
        print(f"✅ Report saved: {report_path}")
        
        return report_path
