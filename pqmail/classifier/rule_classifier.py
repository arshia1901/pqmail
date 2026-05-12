"""
Rule-based Content Sensitivity Classifier for PQMail.

This module classifies email text into sensitivity levels:
LOW, MEDIUM, HIGH, or CRITICAL.

The classifier intentionally uses simple keyword rules for the MVP.
No email content is written to disk or logs.
"""

from typing import Dict, List


SENSITIVITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


KEYWORD_RULES: Dict[str, List[str]] = {
    "CRITICAL": [
        "password",
        "private key",
        "secret key",
        "otp",
        "one time password",
        "bank account",
        "credit card",
        "debit card",
        "aadhaar",
        "pan card",
        "medical record",
        "diagnosis",
        "confidential contract",
        "legal notice",
    ],
    "HIGH": [
        "confidential",
        "salary",
        "invoice",
        "financial",
        "project proposal",
        "source code",
        "api key",
        "access token",
        "meeting minutes",
        "internal report",
    ],
    "MEDIUM": [
        "meeting",
        "schedule",
        "assignment",
        "submission",
        "deadline",
        "marks",
        "attendance",
        "review",
        "feedback",
    ],
}


def normalize_text(text: str | None) -> str:
    """
    Normalize text for keyword matching.
    """
    if not text:
        return ""

    return text.lower()


def classify(text: str | None) -> dict:
    """
    Classify email content sensitivity using keyword rules.

    Priority:
    CRITICAL > HIGH > MEDIUM > LOW
    """
    normalized_text = normalize_text(text)

    matched_keywords = []

    for level in ["CRITICAL", "HIGH", "MEDIUM"]:
        for keyword in KEYWORD_RULES[level]:
            if keyword in normalized_text:
                matched_keywords.append(keyword)

        if matched_keywords:
            return {
                "sensitivity": level,
                "matched_keywords": matched_keywords,
                "method": "rule-based",
            }

    return {
        "sensitivity": "LOW",
        "matched_keywords": [],
        "method": "rule-based",
    }