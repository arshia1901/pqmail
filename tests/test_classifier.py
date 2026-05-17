from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
ROOT_STR = str(ROOT)

if ROOT_STR not in sys.path:
    sys.path.insert(0, ROOT_STR)

from pqmail.classifier.rule_classifier import classify, normalize_text


def test_normalize_text_lowercases_input():
    assert normalize_text("Confidential Salary") == "confidential salary"


def test_normalize_text_handles_none():
    assert normalize_text(None) == ""


def test_classify_critical_password():
    result = classify("Please do not share this password with anyone.")

    assert result["sensitivity"] == "CRITICAL"
    assert "password" in result["matched_keywords"]


def test_classify_critical_aadhaar():
    result = classify("My Aadhaar details are attached.")

    assert result["sensitivity"] == "CRITICAL"
    assert "aadhaar" in result["matched_keywords"]


def test_classify_high_confidential():
    result = classify("This is a confidential internal report.")

    assert result["sensitivity"] == "HIGH"
    assert "confidential" in result["matched_keywords"]


def test_classify_medium_deadline():
    result = classify("The assignment deadline is tomorrow.")

    assert result["sensitivity"] == "MEDIUM"
    assert "deadline" in result["matched_keywords"]


def test_classify_low_general_message():
    result = classify("Hi, hope you are doing well.")

    assert result["sensitivity"] == "LOW"
    assert result["matched_keywords"] == []


def test_critical_takes_priority_over_high():
    result = classify("This confidential email contains a password.")

    assert result["sensitivity"] == "CRITICAL"
    assert "password" in result["matched_keywords"]
    