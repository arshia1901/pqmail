"""
Tests for Module 8: HTML Report Generator
"""

import asyncio
import pytest
from pathlib import Path
from pqmail.report.report_generator import ReportGenerator


@pytest.mark.asyncio
async def test_report_generation():
    """Test HTML report generation from real mailbox."""
    mbox_path = Path("samples/mailbox.mbox")
    
    if not mbox_path.exists():
        pytest.skip("samples/mailbox.mbox not found")
    
    reporter = ReportGenerator(str(mbox_path), output_dir="/tmp")
    report_path = await reporter.generate()
    
    assert report_path.exists()
    assert report_path.name.startswith("report_")
    assert report_path.suffix == ".html"
    
    # Verify HTML content (read with UTF-8 encoding)
    content = report_path.read_text(encoding='utf-8')
    assert "PQMail Security Risk Report" in content
    assert "54" in content  # samples/mailbox.mbox has 54 emails
    assert "CRITICAL" in content
    assert "UNENCRYPTED" in content
    
    # Cleanup
    report_path.unlink()


@pytest.mark.asyncio
async def test_report_contains_statistics():
    """Verify report contains expected statistics."""
    mbox_path = Path("samples/mailbox.mbox")
    
    if not mbox_path.exists():
        pytest.skip("samples/mailbox.mbox not found")
    
    reporter = ReportGenerator(str(mbox_path), output_dir="/tmp")
    report_path = await reporter.generate()
    
    content = report_path.read_text(encoding='utf-8')
    
    # Check for key sections
    assert "Executive Summary" in content
    assert "Encryption Algorithm Distribution" in content
    assert "Risk Categories" in content
    assert "Content Sensitivity" in content
    assert "Recommendations" in content
    
    # Cleanup
    report_path.unlink()
