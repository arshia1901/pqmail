from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
ROOT_STR = str(ROOT)

if ROOT_STR not in sys.path:
    sys.path.insert(0, ROOT_STR)

from pqmail.scorer.hndl_scorer import (
    classify_risk,
    normalize_algorithm,
    normalize_sensitivity,
    score,
)
from pqmail.scorer.timeline_config import validate_timeline


def test_normalize_algorithm_known_value():
    assert normalize_algorithm("rsa") == "RSA"


def test_normalize_algorithm_empty_value():
    assert normalize_algorithm(None) == "UNKNOWN"


def test_normalize_sensitivity_known_value():
    assert normalize_sensitivity("high") == "HIGH"


def test_normalize_sensitivity_unknown_defaults_to_medium():
    assert normalize_sensitivity("very secret") == "MEDIUM"


@pytest.mark.parametrize(
    "years, expected",
    [
        (0, "CRITICAL"),
        (1, "HIGH"),
        (3, "HIGH"),
        (4, "MEDIUM"),
        (7, "MEDIUM"),
        (8, "LOW"),
    ],
)
def test_classify_risk(years, expected):
    assert classify_risk(years) == expected


def test_score_rsa_medium_ten_year_timeline():
    result = score("RSA", "MEDIUM", 10)

    assert result["algorithm"] == "RSA"
    assert result["sensitivity"] == "MEDIUM"
    assert result["years_of_safety_remaining"] == 0
    assert result["risk_category"] == "CRITICAL"


def test_score_ecdh_low_five_year_timeline():
    result = score("ECDH", "LOW", 5)

    assert result["years_of_safety_remaining"] == 4
    assert result["risk_category"] == "MEDIUM"


def test_score_hybrid_is_low_risk():
    result = score("HYBRID", "CRITICAL", 15)

    assert result["years_of_safety_remaining"] > 7
    assert result["risk_category"] == "LOW"


def test_score_unencrypted_is_critical():
    result = score("UNENCRYPTED", "LOW", 5)

    assert result["years_of_safety_remaining"] == 0
    assert result["risk_category"] == "CRITICAL"


def test_validate_timeline_accepts_valid_value():
    assert validate_timeline(10) == 10


def test_validate_timeline_rejects_invalid_value():
    with pytest.raises(ValueError):
        validate_timeline(20)