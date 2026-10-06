"""
Privacy / security tests.

These tests assert the core promises of the project:
  * Passwords are not stored.
  * Passwords are not returned by the API.
  * Passwords are not written to the database.
  * Passwords are not logged.
"""

import io
import logging
import os
import tempfile

import pytest

from backend.services.password_analyzer import analyze_password


SYNTHETIC_PASSWORD = "Zq7#Demo-Privacy-Test-2026!"


def test_password_not_in_analysis_result():
    result = analyze_password(SYNTHETIC_PASSWORD)
    assert SYNTHETIC_PASSWORD not in str(result)


def test_password_not_in_metrics():
    result = analyze_password(SYNTHETIC_PASSWORD)
    assert SYNTHETIC_PASSWORD not in str(result["metrics"])


def test_password_not_in_suggestions():
    result = analyze_password(SYNTHETIC_PASSWORD)
    joined = " ".join(result["suggestions"])
    assert SYNTHETIC_PASSWORD not in joined


def test_password_not_logged(caplog):
    with caplog.at_level(logging.DEBUG):
        analyze_password(SYNTHETIC_PASSWORD)
    assert SYNTHETIC_PASSWORD not in caplog.text


def test_database_has_no_password_column(tmp_path, monkeypatch):
    db_path = tmp_path / "test_analytics.db"
    monkeypatch.setenv("DATABASE_PATH", str(db_path))

    # Re-import config + database with patched env
    import importlib
    import backend.config as config_module
    import backend.models.database as db_module
    importlib.reload(config_module)
    importlib.reload(db_module)

    db_module.init_db()

    import sqlite3
    conn = sqlite3.connect(str(db_path))
    cursor = conn.execute("PRAGMA table_info(analyses)")
    columns = [row[1].lower() for row in cursor.fetchall()]
    conn.close()

    assert "password" not in columns
    assert "password_hash" not in columns


def test_database_stores_only_metadata(tmp_path, monkeypatch):
    db_path = tmp_path / "test_analytics2.db"
    monkeypatch.setenv("DATABASE_PATH", str(db_path))

    import importlib
    import backend.config as config_module
    import backend.models.database as db_module
    importlib.reload(config_module)
    importlib.reload(db_module)

    db_module.init_db()
    result = analyze_password(SYNTHETIC_PASSWORD)
    db_module.save_analysis_metadata(result)

    import sqlite3
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM analyses").fetchall()
    conn.close()

    assert len(rows) == 1
    row = dict(rows[0])
    assert SYNTHETIC_PASSWORD not in str(row)
    assert "password" not in row