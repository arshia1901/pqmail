"""Tests for PQMail Auditor (batch scoring)."""

from pathlib import Path
import sys
import asyncio

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from pqmail.auditor.mbox_reader import MboxReader
from pqmail.auditor.batch_scorer import BatchScorer, EmailScore, AuditStats


# Use the real mailbox for testing
MAILBOX_PATH = Path(__file__).parents[2] / "samples" / "mailbox.mbox"


class TestMboxReader:
    """Tests for MBOX file reading."""
    
    def test_mbox_file_not_found(self):
        """Test error on non-existent file."""
        with pytest.raises(FileNotFoundError):
            MboxReader("/nonexistent/path/mail.mbox")
    
    def test_mbox_is_directory_error(self, tmp_path):
        """Test error when path is a directory."""
        with pytest.raises(ValueError):
            MboxReader(str(tmp_path))


@pytest.mark.skipif(not MAILBOX_PATH.exists(), reason="Real mailbox not available")
class TestBatchScorer:
    """Tests for batch email scoring with real mailbox."""
    
    def test_batch_scorer_init(self):
        """Test initializing batch scorer."""
        scorer = BatchScorer(str(MAILBOX_PATH), quantum_timeline=10)
        assert scorer.quantum_timeline == 10
        assert len(scorer.results) == 0
    
    @pytest.mark.asyncio
    async def test_batch_scorer_score_all(self):
        """Test scoring all emails."""
        scorer = BatchScorer(str(MAILBOX_PATH), quantum_timeline=10)
        stats = await scorer.score_all()
        
        assert stats.total_emails > 0
        assert stats.successfully_parsed > 0
        assert len(scorer.results) > 0
    
    @pytest.mark.asyncio
    async def test_batch_scorer_algorithm_distribution(self):
        """Test algorithm distribution tracking."""
        scorer = BatchScorer(str(MAILBOX_PATH))
        stats = await scorer.score_all()
        
        # Should have at least one algorithm in results
        assert len(stats.algorithms) > 0
        total_alg = sum(stats.algorithms.values())
        assert total_alg == stats.successfully_parsed
    
    @pytest.mark.asyncio
    async def test_batch_scorer_sensitivity_distribution(self):
        """Test sensitivity distribution tracking."""
        scorer = BatchScorer(str(MAILBOX_PATH))
        stats = await scorer.score_all()
        
        # Should have at least one sensitivity
        assert len(stats.sensitivities) > 0
        total_sens = sum(stats.sensitivities.values())
        assert total_sens == stats.successfully_parsed
    
    @pytest.mark.asyncio
    async def test_batch_scorer_risk_distribution(self):
        """Test risk category distribution."""
        scorer = BatchScorer(str(MAILBOX_PATH))
        stats = await scorer.score_all()
        
        # All successfully parsed emails should have risk category
        assert len(stats.risk_categories) > 0
        total_risk = sum(stats.risk_categories.values())
        assert total_risk == stats.successfully_parsed
    
    @pytest.mark.asyncio
    async def test_batch_scorer_years_of_safety(self):
        """Test years of safety statistics."""
        scorer = BatchScorer(str(MAILBOX_PATH), quantum_timeline=10)
        stats = await scorer.score_all()
        
        assert stats.min_years_of_safety >= 0
        assert stats.max_years_of_safety >= stats.min_years_of_safety
    
    @pytest.mark.asyncio
    async def test_get_results_by_risk(self):
        """Test filtering results by risk category."""
        scorer = BatchScorer(str(MAILBOX_PATH))
        await scorer.score_all()
        
        # Get all critical results
        critical = scorer.get_results_by_risk("CRITICAL")
        assert len(critical) > 0
        assert all(r.risk_category == "CRITICAL" for r in critical)
    
    @pytest.mark.asyncio
    async def test_get_results_by_algorithm(self):
        """Test filtering results by algorithm."""
        scorer = BatchScorer(str(MAILBOX_PATH))
        await scorer.score_all()
        
        # Should have unencrypted emails
        unenc = scorer.get_results_by_algorithm("UNENCRYPTED")
        assert len(unenc) > 0
        assert all(r.algorithm == "UNENCRYPTED" for r in unenc)
    
    @pytest.mark.asyncio
    async def test_get_critical_unencrypted_count(self):
        """Test counting critical unencrypted emails."""
        scorer = BatchScorer(str(MAILBOX_PATH))
        await scorer.score_all()
        
        count = scorer.get_critical_unencrypted_count()
        assert count > 0
    
    @pytest.mark.asyncio
    async def test_email_score_attributes(self):
        """Test that EmailScore has all required attributes."""
        scorer = BatchScorer(str(MAILBOX_PATH))
        await scorer.score_all()
        
        assert len(scorer.results) > 0
        result = scorer.results[0]
        
        assert isinstance(result, EmailScore)
        assert hasattr(result, 'message_id')
        assert hasattr(result, 'from_addr')
        assert hasattr(result, 'to_addrs')
        assert hasattr(result, 'algorithm')
        assert hasattr(result, 'sensitivity')
        assert hasattr(result, 'risk_category')
        assert hasattr(result, 'years_of_safety')
    
    @pytest.mark.asyncio
    async def test_audit_stats_to_dict(self):
        """Test converting audit stats to dictionary."""
        scorer = BatchScorer(str(MAILBOX_PATH))
        stats = await scorer.score_all()
        
        stats_dict = stats.to_dict()
        
        assert 'total_emails' in stats_dict
        assert 'successfully_parsed' in stats_dict
        assert 'algorithms' in stats_dict
        assert 'sensitivities' in stats_dict
        assert 'risk_categories' in stats_dict
        assert 'avg_years_of_safety' in stats_dict
    
    @pytest.mark.asyncio
    async def test_progress_callback(self):
        """Test progress callback during scoring."""
        progress_calls = []
        
        async def progress_callback(current, total):
            progress_calls.append((current, total))
        
        scorer = BatchScorer(str(MAILBOX_PATH))
        await scorer.score_all(progress_callback=progress_callback)
        
        # Should have at least one progress update
        assert len(progress_calls) > 0
        # Last update should show completion
        assert progress_calls[-1][0] == progress_calls[-1][1]
    
    def test_print_summary(self, capsys):
        """Test print_summary doesn't crash."""
        scorer = BatchScorer(str(MAILBOX_PATH))
        # Run sync wrapper
        asyncio.run(scorer.score_all())
        
        # This should not raise
        scorer.print_summary()
        
        captured = capsys.readouterr()
        assert "AUDIT SUMMARY" in captured.out
        assert "Algorithm Distribution" in captured.out
    
    @pytest.mark.asyncio
    async def test_real_mailbox_metrics(self):
        """Test specific metrics from real mailbox."""
        scorer = BatchScorer(str(MAILBOX_PATH), quantum_timeline=10)
        stats = await scorer.score_all()
        
        # Real mailbox should have unencrypted emails (critical risk)
        assert stats.risk_categories.get("CRITICAL", 0) > 0
        
        # Average years of safety should reflect unencrypted emails
        assert stats.avg_years_of_safety >= 0
