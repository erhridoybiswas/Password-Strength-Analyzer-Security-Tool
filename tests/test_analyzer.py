"""
Core analyzer tests.

NOTE: Every password used here is SYNTHETIC. Never commit real credentials.
"""

import pytest

from backend.services.password_analyzer import (
    analyze_password,
    analyze_characters,
    analyze_length,
    is_common_password,
)


def test_01_empty_password():
    result = analyze_password("")
    assert result["score"] == 0
    assert result["classification"] == "VERY WEAK"


def test_02_single_character():
    result = analyze_password("a")
    assert result["score"] < 20
    assert result["metrics"]["length"]["length"] == 1


def test_03_short_numeric():
    result = analyze_password("4821")
    assert result["classification"] in ("VERY WEAK", "WEAK")


def test_04_common_password():
    assert is_common_password("password") is True
    result = analyze_password("password")
    assert result["score"] <= 15
    assert any(f["type"] == "common_password" for f in result["findings"])


def test_05_long_repeated():
    result = analyze_password("aaaaaaaaaaaaaaaa")
    assert result["score"] <= 40
    types = {f["type"] for f in result["findings"]}
    assert "repetition_chars" in types


def test_06_lowercase_only():
    result = analyze_password("abcdefghijkl")
    assert result["metrics"]["characters"]["has_lowercase"] is True
    assert result["metrics"]["characters"]["has_uppercase"] is False


def test_07_uppercase_only():
    result = analyze_password("ABCDEFGHIJKL")
    assert result["metrics"]["characters"]["has_uppercase"] is True


def test_08_numbers_only():
    result = analyze_password("9384756210")
    assert result["metrics"]["characters"]["has_digit"] is True
    assert result["metrics"]["characters"]["has_lowercase"] is False


def test_09_symbols_only():
    result = analyze_password("!@#$%^&*()_+")
    assert result["metrics"]["characters"]["has_symbol"] is True


def test_10_mixed_characters():
    result = analyze_password("aB3$xY9!qW2#")
    assert result["metrics"]["characters"]["character_type_count"] >= 4


def test_11_sequential_numbers():
    result = analyze_password("mysecret12345")
    assert any(f["type"] == "sequence" for f in result["findings"])


def test_12_reverse_numeric_sequence():
    result = analyze_password("xk9876cd")
    assert any(f["type"] == "sequence" for f in result["findings"])


def test_13_sequential_letters():
    result = analyze_password("zzabcdefzz")
    assert any(f["type"] == "sequence" for f in result["findings"])


def test_14_keyboard_sequence():
    result = analyze_password("qwertyui")
    assert any(f["type"] == "keyboard_pattern" for f in result["findings"])


def test_15_repeated_characters():
    result = analyze_password("Pass1111word")
    assert any(f["type"] == "repetition_chars" for f in result["findings"])


def test_16_repeated_substring():
    result = analyze_password("abcabcabc")
    assert any(f["type"] == "repetition_substring" for f in result["findings"])


def test_17_common_word_plus_number():
    result = analyze_password("welcome123")
    types = {f["type"] for f in result["findings"]}
    assert "predictable_structure" in types or "common_password" in types


def test_18_word_plus_year():
    result = analyze_password("hello1998")
    types = {f["type"] for f in result["findings"]}
    assert "year_pattern" in types or "predictable_structure" in types


def test_19_personal_name_overlap():
    result = analyze_password("DemoUser@2026", context={"first_name": "DemoUser"})
    assert any(f["type"] == "personal_info" for f in result["findings"])


def test_20_birth_year_overlap():
    result = analyze_password("Xy7#1994ab", context={"birth_year": "1994"})
    assert any(f["type"] == "personal_info" for f in result["findings"])


def test_21_long_passphrase_like():
    result = analyze_password("copper-lantern-otter-breeze-marble")
    assert result["score"] >= 60


def test_22_unicode_handling():
    result = analyze_password("pässwörd-Ünïcode-2026")
    assert isinstance(result["score"], int)
    assert 0 <= result["score"] <= 100


def test_23_space_handling():
    result = analyze_password("correct horse battery staple")
    assert result["metrics"]["characters"]["has_space"] is True


def test_24_max_length_input():
    long_password = "Ab3!" * 64  # 256 characters
    result = analyze_password(long_password)
    assert 0 <= result["score"] <= 100


def test_25_score_boundaries():
    for pw in ["", "a", "password", "copper-lantern-otter-breeze-marble"]:
        result = analyze_password(pw)
        assert 0 <= result["score"] <= 100


def test_26_suggestion_generation():
    result = analyze_password("123456")
    assert len(result["suggestions"]) > 0
    assert all(isinstance(s, str) for s in result["suggestions"])


def test_27_response_contains_no_password():
    secret = "SuperSecret-Demo-Value-123!"
    result = analyze_password(secret)
    serialized = str(result)
    assert secret not in serialized


def test_28_metrics_present():
    result = analyze_password("Demo#2026xy")
    for key in ("length", "characters", "entropy", "score_breakdown"):
        assert key in result["metrics"]


def test_29_policy_result_present():
    result = analyze_password("Short1!")
    assert "policy" in result
    assert "policy_pass" in result["policy"]


def test_30_very_strong_random_like():
    # Synthetic, generated for this test only. Do NOT reuse.
    pw = "vT7#qLm2$Xz9!Rw4@Bk8"
    result = analyze_password(pw)
    assert result["score"] >= 61