"""
password_analyzer.py
--------------------
The orchestrator. Receives a password (in memory), runs every analysis module,
and returns a structured result.

SECURITY CONTRACT
-----------------
* The password is never logged.
* The password is never written to the database.
* The password is never returned in the response.
* Only short matched fragments (e.g. '1234') may appear in findings, for
  educational feedback.
"""

import os
from functools import lru_cache
from typing import Dict, List, Optional

from backend.config import COMMON_PASSWORDS_FILE, ENABLE_COMMON_PASSWORD_CHECK
from backend.services import pattern_detector as pd
from backend.services.entropy_estimator import estimate_practical_entropy
from backend.services.scoring_engine import compute_score
from backend.services.suggestion_engine import generate_suggestions
from backend.services.policy_checker import check_policy


# ---------------------------------------------------------------------------
# Common-password list loading (cached, read once)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def load_common_passwords() -> frozenset:
    """Load the educational common-password list from disk (cached)."""
    path = COMMON_PASSWORDS_FILE
    if not os.path.exists(path):
        return frozenset()
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return frozenset(
            line.strip().lower() for line in handle if line.strip()
        )


def is_common_password(password: str) -> bool:
    """
    Check whether the password (or the password with trailing digits removed)
    appears in the educational common-password list.
    """
    if not ENABLE_COMMON_PASSWORD_CHECK or not password:
        return False

    common = load_common_passwords()
    lowered = password.lower()

    if lowered in common:
        return True

    # 'password12345' -> also check the alphabetic root 'password'
    stripped = "".join(ch for ch in lowered if not ch.isdigit())
    if stripped and stripped in common:
        return True

    return False


# ---------------------------------------------------------------------------
# Length analysis
# ---------------------------------------------------------------------------

LENGTH_BANDS = [
    (0, 7, "Very short",
     "Passwords under 8 characters are trivial to guess with modern tooling."),
    (8, 11, "Short",
     "8-11 characters is below current recommended guidance for important accounts."),
    (12, 15, "Better length",
     "12-15 characters is a reasonable length when combined with unpredictability."),
    (16, 10_000, "Strong length contribution",
     "16+ characters contributes strongly to resistance against guessing."),
]


def analyze_length(password: str) -> Dict:
    length = len(password)
    band_label = "Very short"
    band_note = LENGTH_BANDS[0][3]
    for low, high, label, note in LENGTH_BANDS:
        if low <= length <= high:
            band_label, band_note = label, note
            break

    return {
        "length": length,
        "band": band_label,
        "note": band_note,
        "reminder": (
            "Length alone does not make a password secure. "
            "'aaaaaaaaaaaaaaaaaaaa' is 20 characters long and still very weak."
        ),
    }


# ---------------------------------------------------------------------------
# Character analysis
# ---------------------------------------------------------------------------

def analyze_characters(password: str) -> Dict:
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    has_space = " " in password

    type_count = sum([has_lower, has_upper, has_digit, has_symbol])
    unique_count = len(set(password))
    unique_ratio = (unique_count / len(password)) if password else 0.0

    return {
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "has_space": has_space,
        "character_type_count": type_count,
        "unique_character_count": unique_count,
        "unique_character_ratio": round(unique_ratio, 4),
        "note": (
            "Character variety helps, but it is not the only metric. "
            "'Password123!' has variety and is still highly predictable."
        ),
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_password(password: str, context: Optional[Dict] = None) -> Dict:
    """
    Analyze a password and return a structured result.

    Args:
        password: The password string (processed in memory only).
        context:  Optional voluntary demo context, e.g.
                  {"first_name": "Demo", "birth_year": "1990"}.
                  Never stored.

    Returns:
        {
            "score": int,
            "classification": str,
            "findings": list,
            "suggestions": list,
            "metrics": dict,
            "policy": dict
        }
    """
    context = context or {}
    findings: List[Dict] = []

    # 1. Length
    length_info = analyze_length(password)

    # 2. Characters
    character_info = analyze_characters(password)

    # 3. Common password
    common = is_common_password(password)
    if common:
        findings.append({
            "type": "common_password",
            "severity": "critical",
            "description": (
                "Your password matches a commonly used password pattern and "
                "should not be used."
            ),
        })

    # 4. Patterns (sequence, keyboard, repetition, predictable, personal info)
    pattern_findings = pd.run_all_pattern_checks(
        password,
        common_words=set(load_common_passwords()),
        context=context,
    )
    findings.extend(pattern_findings)

    # 5. Entropy-style estimation
    entropy_info = estimate_practical_entropy(password, findings)

    # 6. Score
    metrics = {
        "length": length_info,
        "characters": character_info,
        "entropy": entropy_info,
        "pattern_finding_count": len(pattern_findings),
    }

    score, classification, breakdown = compute_score(
        metrics=metrics,
        findings=findings,
        is_common=common,
        practical_bits=entropy_info["practical_bits"],
    )
    metrics["score_breakdown"] = breakdown

    # 7. Suggestions
    suggestions = generate_suggestions(findings, metrics, score, classification)

    # 8. Policy
    policy_result = check_policy(password, is_common=common)

    # IMPORTANT: `password` goes out of scope here. It is not returned,
    # not logged, and not persisted.
    return {
        "score": score,
        "classification": classification,
        "findings": findings,
        "suggestions": suggestions,
        "metrics": metrics,
        "policy": policy_result,
    }