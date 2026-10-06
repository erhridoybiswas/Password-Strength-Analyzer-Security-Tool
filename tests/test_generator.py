"""Tests for the secure password generator."""

from backend.services.password_generator import generate_password, generate_passphrase


def test_generated_password_length():
    result = generate_password(length=20)
    assert len(result["password"]) == 20


def test_generated_password_minimum_length():
    result = generate_password(length=2)
    assert len(result["password"]) >= 8


def test_generated_password_maximum_length():
    result = generate_password(length=500)
    assert len(result["password"]) <= 128


def test_generated_password_uniqueness():
    a = generate_password(length=24)["password"]
    b = generate_password(length=24)["password"]
    assert a != b


def test_generated_password_character_pools():
    result = generate_password(length=24)
    pw = result["password"]
    assert any(c.islower() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(not c.isalnum() for c in pw)


def test_passphrase_generation():
    result = generate_passphrase(word_count=5)
    assert result["passphrase"]
    assert result["word_count"] == 5