"""Tests for scoring engine and classification."""

from backend.services.scoring_engine import classify, compute_score
from backend.services.password_analyzer import analyze_password


def test_classification_bands():
    assert classify(0) == "VERY WEAK"
    assert classify(20) == "VERY WEAK"
    assert classify(21) == "WEAK"
    assert classify(40) == "WEAK"
    assert classify(41) == "MODERATE"
    assert classify(60) == "MODERATE"
    assert classify(61) == "STRONG"
    assert classify(80) == "STRONG"
    assert classify(81) == "VERY STRONG"
    assert classify(100) == "VERY STRONG"


def test_common_password_cap():
    result = analyze_password("password123")
    assert result["score"] <= 15


def test_strong_password_scores_high():
    # Synthetic example generated for this test only.
    result = analyze_password("vT7#qLm2$Xz9!Rw4@Bk8")
    assert result["score"] >= 61


def test_score_never_exceeds_bounds():
    for pw in ["", "a" * 300, "!@#$%^&*()", "Password123!"]:
        result = analyze_password(pw)
        assert 0 <= result["score"] <= 100


def test_password123_is_not_very_strong():
    result = analyze_password("Password123!")
    assert result["score"] < 81