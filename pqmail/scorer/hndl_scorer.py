"""
HNDL Risk Scorer for PQMail.

This module computes the estimated years of safety remaining for an email
based on:
1. Detected encryption algorithm
2. Content sensitivity level
3. User-configured quantum timeline scenario
"""

from typing import Dict


ALGORITHM_SAFETY_HORIZON: Dict[str, int] = {
    "RSA": 5,
    "RSA-2048": 5,
    "RSA-4096": 8,
    "ECDH": 7,
    "X25519": 7,
    "HYBRID": 50,
    "UNENCRYPTED": 0,
    "SIGNED_ONLY": 0,
    "PARSE_ERROR": 0,
    "UNKNOWN": 0,
}

SENSITIVITY_MODIFIER: Dict[str, int] = {
    "LOW": 2,
    "MEDIUM": 0,
    "HIGH": -3,
    "CRITICAL": -6,
}


def normalize_algorithm(algorithm: str | None) -> str:
    """
    Normalize algorithm names to uppercase known labels.
    """
    if not algorithm:
        return "UNKNOWN"

    return algorithm.strip().upper()


def normalize_sensitivity(sensitivity: str | None) -> str:
    """
    Normalize sensitivity labels to uppercase known labels.
    """
    if not sensitivity:
        return "MEDIUM"

    sensitivity = sensitivity.strip().upper()

    if sensitivity not in SENSITIVITY_MODIFIER:
        return "MEDIUM"

    return sensitivity


def classify_risk(years_remaining: int) -> str:
    """
    Convert years of safety remaining into a risk category.
    """
    if years_remaining == 0:
        return "CRITICAL"
    if years_remaining <= 3:
        return "HIGH"
    if years_remaining <= 7:
        return "MEDIUM"
    return "LOW"


def score(
    algorithm: str,
    sensitivity: str = "MEDIUM",
    quantum_timeline: int = 10,
) -> dict:
    """
    Compute HNDL risk score.

    Formula:
        years_of_safety_remaining = max(0, D - T + sensitivity_modifier)

    Where:
        D = algorithm safety horizon
        T = quantum timeline in years
    """
    normalized_algorithm = normalize_algorithm(algorithm)
    normalized_sensitivity = normalize_sensitivity(sensitivity)

    safety_horizon = ALGORITHM_SAFETY_HORIZON.get(normalized_algorithm, 0)
    sensitivity_modifier = SENSITIVITY_MODIFIER.get(normalized_sensitivity, 0)

    years_remaining = max(
        0,
        safety_horizon - quantum_timeline + sensitivity_modifier,
    )

    risk_category = classify_risk(years_remaining)

    return {
        "algorithm": normalized_algorithm,
        "sensitivity": normalized_sensitivity,
        "quantum_timeline": quantum_timeline,
        "algorithm_safety_horizon": safety_horizon,
        "sensitivity_modifier": sensitivity_modifier,
        "years_of_safety_remaining": years_remaining,
        "risk_category": risk_category,
    }