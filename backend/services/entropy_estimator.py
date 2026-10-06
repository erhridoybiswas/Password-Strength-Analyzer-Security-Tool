"""
entropy_estimator.py
---------------------
Educational entropy estimation.

We compute TWO numbers:

1. theoretical_bits  ->  L * log2(N)   (assumes uniform random characters)
2. practical_bits    ->  theoretical_bits reduced by detected predictability

The theoretical number is optimistic for human-chosen passwords. The practical
number is a *heuristic* and is clearly labelled as an educational estimate.
"""

import math
from typing import Dict, List


def _character_pool_size(password: str) -> int:
    """Estimate the size of the character pool the password draws from."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 33  # common printable symbols + space
    return pool


def estimate_theoretical_entropy(password: str) -> Dict:
    """
    Entropy ~= L * log2(N).

    LIMITATION: this assumes every character was chosen uniformly at random.
    Human-chosen passwords are NOT random, so this value can be wildly
    optimistic (e.g. for 'Password123!').
    """
    if not password:
        return {"bits": 0.0, "pool_size": 0, "length": 0}

    pool = _character_pool_size(password)
    bits = len(password) * math.log2(pool) if pool > 1 else 0.0

    return {
        "bits": round(bits, 2),
        "pool_size": pool,
        "length": len(password),
    }


def estimate_practical_entropy(password: str, findings: List[Dict]) -> Dict:
    """
    Reduce the theoretical estimate based on detected patterns.

    Each finding applies a multiplicative penalty. This is a heuristic for
    education, NOT a guarantee of guessing resistance.
    """
    theoretical = estimate_theoretical_entropy(password)
    bits = theoretical["bits"]

    penalty_factor = 1.0
    for finding in findings:
        ftype = finding.get("type", "")
        if ftype == "keyboard_pattern":
            penalty_factor *= 0.45
        elif ftype == "sequence":
            penalty_factor *= 0.55
        elif ftype == "repetition_chars":
            penalty_factor *= 0.35
        elif ftype == "repetition_substring":
            penalty_factor *= 0.45
        elif ftype == "predictable_structure":
            penalty_factor *= 0.55
        elif ftype == "year_pattern":
            penalty_factor *= 0.80
        elif ftype == "personal_info":
            penalty_factor *= 0.50
        elif ftype == "dictionary_word":
            penalty_factor *= 0.60

    practical_bits = bits * penalty_factor

    return {
        "theoretical_bits": theoretical["bits"],
        "practical_bits": round(practical_bits, 2),
        "pool_size": theoretical["pool_size"],
        "penalty_factor": round(penalty_factor, 3),
        "note": (
            "Educational estimate only. Real guessing resistance depends on the "
            "attacker model, hashing algorithm, work factor, rate limiting, and "
            "whether the attack is online or offline."
        ),
    }