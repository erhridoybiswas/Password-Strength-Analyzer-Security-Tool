"""
scoring_engine.py
-----------------
Turns metrics + findings into a 0-100 score and a classification.

Score composition (project-defined, documented, not a universal standard):

    Length contribution ......... up to +35
    Character diversity ......... up to +15
    Unique-character ratio ...... up to +10
    Pattern resistance .......... up to +20
    Non-common password ......... up to +10
    Additional unpredictability . up to +10

Hard rules:
    * A known common password is capped at 15/100 regardless of everything else.
    * Final score is always clamped to 0..100.
"""

from typing import Dict, List, Tuple

CLASSIFICATION_BANDS = [
    (0, 20, "VERY WEAK"),
    (21, 40, "WEAK"),
    (41, 60, "MODERATE"),
    (61, 80, "STRONG"),
    (81, 100, "VERY STRONG"),
]

# How much each finding type subtracts from the pattern-resistance pool.
PATTERN_PENALTIES = {
    "sequence": 10,
    "keyboard_pattern": 12,
    "repetition_chars": 10,
    "repetition_substring": 12,
    "predictable_structure": 10,
    "year_pattern": 6,
    "dictionary_word": 8,
    "personal_info": 15,
    "common_password": 25,
}

# Extra penalties applied to the final score (after the component sum).
EXTRA_PENALTIES = {
    "personal_info": 15,
    "common_password": 0,   # handled by the hard cap
}


def _length_score(length: int) -> int:
    if length == 0:
        return 0
    if length < 8:
        return min(12, length * 2)
    if length < 12:
        return 18
    if length < 16:
        return 26
    return 35


def _diversity_score(character_type_count: int) -> int:
    return min(15, character_type_count * 3)


def _uniqueness_score(unique_ratio: float) -> int:
    return int(round(unique_ratio * 10))


def _pattern_resistance(findings: List[Dict]) -> int:
    penalty = 0
    for finding in findings:
        penalty += PATTERN_PENALTIES.get(finding.get("type", ""), 0)
    return max(0, 20 - penalty)


def _unpredictability_bonus(practical_bits: float, findings: List[Dict]) -> int:
    """Reward genuinely high practical entropy with no serious patterns."""
    serious = {"keyboard_pattern", "sequence", "repetition_chars",
               "repetition_substring", "predictable_structure", "personal_info"}
    if any(f.get("type") in serious for f in findings):
        return 0
    if practical_bits >= 80:
        return 10
    if practical_bits >= 60:
        return 7
    if practical_bits >= 40:
        return 4
    return 0


def classify(score: int) -> str:
    for low, high, label in CLASSIFICATION_BANDS:
        if low <= score <= high:
            return label
    return "VERY WEAK"


def compute_score(
    metrics: Dict,
    findings: List[Dict],
    is_common: bool,
    practical_bits: float,
) -> Tuple[int, str, Dict]:
    """Return (score, classification, breakdown)."""
    length = metrics.get("length", {}).get("length", 0)
    type_count = metrics.get("characters", {}).get("character_type_count", 0)
    unique_ratio = metrics.get("characters", {}).get("unique_character_ratio", 0.0)

    components = {
        "length": _length_score(length),
        "diversity": _diversity_score(type_count),
        "uniqueness": _uniqueness_score(unique_ratio),
        "pattern_resistance": _pattern_resistance(findings),
        "non_common": 0 if is_common else 10,
        "unpredictability": _unpredictability_bonus(practical_bits, findings),
    }

    raw = sum(components.values())

    # Extra penalties
    extra = 0
    for finding in findings:
        extra += EXTRA_PENALTIES.get(finding.get("type", ""), 0)
    raw -= extra

    # Hard rule: a known common password can never score well.
    if is_common:
        raw = min(raw, 15)

    score = max(0, min(100, int(round(raw))))

    breakdown = {
        "components": components,
        "extra_penalties": extra,
        "common_password_cap_applied": is_common,
        "raw_before_clamp": int(round(raw)),
    }

    return score, classify(score), breakdown