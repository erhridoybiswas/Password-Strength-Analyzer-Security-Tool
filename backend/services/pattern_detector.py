"""
pattern_detector.py
-------------------
Pure functions that detect predictable structures inside a password.

Everything here is IN-MEMORY. Nothing is logged, stored or transmitted.
Each function receives a password string and returns a list of "finding"
dictionaries of the shape:

    {
        "type": "sequence",
        "severity": "medium",
        "description": "Ascending character sequence detected.",
        "fragment": "abcd"        # short matched fragment (never the whole password)
    }
"""

import re
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Keyboard walk data (educational, local, no external calls)
# ---------------------------------------------------------------------------

_KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

_KEYBOARD_COLUMNS = [
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb",
    "6yhn", "7ujm", "8ik,", "9ol.", "0p;/",
]


def _build_keyboard_sequences(min_len: int = 4) -> set:
    """Generate every keyboard-walk substring of length >= min_len."""
    bases = list(_KEYBOARD_ROWS) + list(_KEYBOARD_COLUMNS)
    sequences = set()
    for base in bases:
        for variant in (base, base[::-1]):
            n = len(variant)
            for i in range(n):
                for j in range(i + min_len, n + 1):
                    sequences.add(variant[i:j])
    # A few classic short walks
    sequences.update({"qwer", "asdf", "zxcv", "qaz", "wsx", "edc"})
    return sequences


_KEYBOARD_SEQUENCES = _build_keyboard_sequences(min_len=4)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _char_class(ch: str) -> str:
    """Return a coarse class for sequence detection."""
    if ch.isdigit():
        return "digit"
    if ch.islower():
        return "lower"
    if ch.isupper():
        return "upper"
    return "other"


# ---------------------------------------------------------------------------
# 1. Sequence detection
# ---------------------------------------------------------------------------

def detect_sequences(password: str, min_run: int = 3) -> List[Dict]:
    """
    Detect ascending or descending character runs.

    Examples caught: 'abcd', '1234', '9876', 'dcba', 'xyza' (no), 'cba'.
    Runs shorter than `min_run` are ignored to reduce false positives.
    """
    findings: List[Dict] = []
    if len(password) < min_run:
        return findings

    i = 0
    n = len(password)
    while i < n - 1:
        cls = _char_class(password[i])
        nxt_cls = _char_class(password[i + 1])
        if cls == nxt_cls and cls != "other":
            diff = ord(password[i + 1]) - ord(password[i])
            if diff in (1, -1):
                j = i + 1
                while (
                    j < n - 1
                    and _char_class(password[j + 1]) == cls
                    and ord(password[j + 1]) - ord(password[j]) == diff
                ):
                    j += 1
                run_len = j - i + 1
                if run_len >= min_run:
                    direction = "Ascending" if diff == 1 else "Descending"
                    fragment = password[i : j + 1]
                    findings.append({
                        "type": "sequence",
                        "severity": "medium",
                        "description": (
                            f"{direction} character sequence detected "
                            f"({run_len} characters in a row)."
                        ),
                        "fragment": fragment,
                    })
                i = j
                continue
        i += 1

    return findings


# ---------------------------------------------------------------------------
# 2. Keyboard pattern detection
# ---------------------------------------------------------------------------

def detect_keyboard_patterns(password: str) -> List[Dict]:
    """Detect keyboard walks such as 'qwerty', 'asdf', 'zxcv', 'qwerty123'."""
    findings: List[Dict] = []
    lowered = password.lower()

    matches = []
    for seq in _KEYBOARD_SEQUENCES:
        if seq in lowered:
            matches.append(seq)

    if not matches:
        return findings

    # Report only the longest match to avoid noisy output
    longest = max(matches, key=len)
    findings.append({
        "type": "keyboard_pattern",
        "severity": "medium",
        "description": (
            "Keyboard-walk pattern detected. Attackers try keyboard "
            "sequences such as 'qwerty' and 'asdf' very early."
        ),
        "fragment": longest,
    })
    return findings


# ---------------------------------------------------------------------------
# 3. Repetition detection
# ---------------------------------------------------------------------------

def detect_repetition(password: str) -> List[Dict]:
    """Detect repeated characters ('aaaa') and repeated substrings ('abcabc')."""
    findings: List[Dict] = []

    # 3a. Repeated single characters (run length >= 3)
    for match in re.finditer(r"(.)\1{2,}", password):
        findings.append({
            "type": "repetition_chars",
            "severity": "medium",
            "description": (
                f"Character '{match.group(1)}' is repeated "
                f"{len(match.group(0))} times in a row."
            ),
            "fragment": match.group(0),
        })

    # 3b. Repeated multi-character substrings
    seen = set()
    for match in re.finditer(r"(.{2,}?)\1+", password):
        unit = match.group(1)
        # Ignore units made of a single repeated character (handled above)
        if len(set(unit)) == 1:
            continue
        if unit in seen:
            continue
        seen.add(unit)
        findings.append({
            "type": "repetition_substring",
            "severity": "medium",
            "description": (
                f"Repeated block '{unit}' detected. Repetition makes a "
                f"password far more predictable than its length suggests."
            ),
            "fragment": match.group(0),
        })

    return findings


# ---------------------------------------------------------------------------
# 4. Predictable word + number / year structures
# ---------------------------------------------------------------------------

_YEAR_RE = re.compile(r"(19|20)\d{2}")


def detect_predictable_structure(password: str, common_words: Optional[set] = None) -> List[Dict]:
    """
    Detect structures such as 'welcome123', 'admin2026', 'hello1234'.

    `common_words` is an optional set of lowercase dictionary words supplied
    by the caller (we reuse the common-password list as a light dictionary).
    """
    findings: List[Dict] = []
    lowered = password.lower()

    # 4a. Ends with a 1-4 digit run appended to letters
    if re.fullmatch(r"[a-z]+\d{1,4}", lowered):
        findings.append({
            "type": "predictable_structure",
            "severity": "medium",
            "description": (
                "A word followed by a short number is a very common, "
                "highly predictable structure."
            ),
        })

    # 4b. Word + separator + number, e.g. 'admin@2026'
    if re.fullmatch(r"[a-z]+[!@#$%^&*_\-.]+\d{2,4}", lowered):
        findings.append({
            "type": "predictable_structure",
            "severity": "medium",
            "description": (
                "Word + symbol + number is a predictable template "
                "often used by password generators and attackers alike."
            ),
        })

    # 4c. Year fragment
    year_matches = _YEAR_RE.findall(lowered)
    if _YEAR_RE.search(lowered):
        fragment = _YEAR_RE.search(lowered).group(0)
        findings.append({
            "type": "year_pattern",
            "severity": "low",
            "description": (
                "A 4-digit year was detected. Birth years and current years "
                "are commonly tried by attackers."
            ),
            "fragment": fragment,
        })

    # 4d. Dictionary word embedded
    if common_words:
        for word in common_words:
            if len(word) >= 5 and word in lowered and word != lowered:
                findings.append({
                    "type": "dictionary_word",
                    "severity": "medium",
                    "description": (
                        "A well-known common word is embedded in the password."
                    ),
                })
                break

    return findings


# ---------------------------------------------------------------------------
# 5. Personal information overlap (optional, local, never stored)
# ---------------------------------------------------------------------------

def detect_personal_info(password: str, context: Optional[Dict[str, str]] = None) -> List[Dict]:
    """
    Compare the password (case-insensitively) against VOLUNTARY user-supplied
    context such as first name or birth year.

    Nothing here is stored. If the caller passes nothing, nothing happens.
    """
    findings: List[Dict] = []
    if not context:
        return findings

    lowered = password.lower()

    for key, value in context.items():
        if not value or not isinstance(value, str):
            continue
        value_clean = value.strip().lower()
        if len(value_clean) < 3:
            continue
        if value_clean in lowered:
            findings.append({
                "type": "personal_info",
                "severity": "high",
                "description": (
                    f"Password appears to contain personal information "
                    f"related to '{key}'. Attackers try this information first."
                ),
            })

    return findings


# ---------------------------------------------------------------------------
# Aggregate helper
# ---------------------------------------------------------------------------

def run_all_pattern_checks(
    password: str,
    common_words: Optional[set] = None,
    context: Optional[Dict[str, str]] = None,
) -> List[Dict]:
    """Run every pattern detector and return a single combined list."""
    findings: List[Dict] = []
    findings.extend(detect_sequences(password))
    findings.extend(detect_keyboard_patterns(password))
    findings.extend(detect_repetition(password))
    findings.extend(detect_predictable_structure(password, common_words=common_words))
    findings.extend(detect_personal_info(password, context=context))
    return findings