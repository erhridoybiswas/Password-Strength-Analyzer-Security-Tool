"""Unit tests for individual pattern detectors."""

from backend.services import pattern_detector as pd


def test_keyboard_rows_detected():
    for pw in ["qwerty", "asdfgh", "zxcvbn", "1qaz2wsx"]:
        findings = pd.detect_keyboard_patterns(pw)
        assert findings, f"Expected keyboard pattern for {pw}"


def test_no_false_keyboard_on_random():
    findings = pd.detect_keyboard_patterns("Xk9#mQ2$vL7!")
    assert findings == []


def test_ascending_sequence():
    findings = pd.detect_sequences("abczz1234")
    assert len(findings) >= 2


def test_descending_sequence():
    findings = pd.detect_sequences("zz9876zz")
    assert findings


def test_short_run_ignored():
    findings = pd.detect_sequences("ab1")
    assert findings == []


def test_repeated_char():
    findings = pd.detect_repetition("xxxx")
    assert any(f["type"] == "repetition_chars" for f in findings)


def test_repeated_substring():
    findings = pd.detect_repetition("abcabcabc")
    assert any(f["type"] == "repetition_substring" for f in findings)


def test_predictable_structure_word_number():
    findings = pd.detect_predictable_structure("hello1234")
    assert any(f["type"] == "predictable_structure" for f in findings)


def test_year_pattern():
    findings = pd.detect_predictable_structure("abc2024xyz")
    assert any(f["type"] == "year_pattern" for f in findings)


def test_personal_info_none_context():
    assert pd.detect_personal_info("anything", None) == []


def test_personal_info_match():
    findings = pd.detect_personal_info("Rahul@123", {"first_name": "Rahul"})
    assert findings