"""
database.py
-----------
SQLite persistence for AGGREGATE ANALYTICS ONLY.

SECURITY DESIGN:
    There is NO password column. There is NO hash column.
    Even storing a hash of an arbitrary user-submitted password would create
    unnecessary privacy/security risk for a tool that only needs to display
    aggregate statistics.

    We store only:
        score, classification, password_length,
        unique_character_ratio, weakness_count, created_at
    plus per-finding type/severity/description rows.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, List

from backend.config import DATABASE_PATH
from backend.utils.logger import get_logger

log = get_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    score                  INTEGER NOT NULL,
    classification         TEXT    NOT NULL,
    password_length        INTEGER NOT NULL,
    unique_character_ratio REAL    NOT NULL,
    weakness_count         INTEGER NOT NULL,
    created_at             TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  INTEGER NOT NULL,
    finding_type TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    description  TEXT    NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses (created_at);
CREATE INDEX IF NOT EXISTS idx_findings_type       ON findings (finding_type);
"""


@contextmanager
def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if they do not exist."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
    log.info("Analytics database initialised (metadata only, no passwords).")


def save_analysis_metadata(result: Dict) -> None:
    """Persist safe aggregate metadata for one analysis."""
    metrics = result.get("metrics", {})
    findings = result.get("findings", [])

    length = metrics.get("length", {}).get("length", 0)
    unique_ratio = metrics.get("characters", {}).get("unique_character_ratio", 0.0)
    weakness_count = len(findings)
    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO analyses
                (score, classification, password_length,
                 unique_character_ratio, weakness_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                result.get("score", 0),
                result.get("classification", "UNKNOWN"),
                length,
                unique_ratio,
                weakness_count,
                created_at,
            ),
        )
        analysis_id = cursor.lastrowid

        if findings:
            conn.executemany(
                """
                INSERT INTO findings
                    (analysis_id, finding_type, severity, description)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        analysis_id,
                        f.get("type", "unknown"),
                        f.get("severity", "low"),
                        f.get("description", ""),
                    )
                    for f in findings
                ],
            )


def get_dashboard_stats() -> Dict:
    """Return aggregate statistics. Never reveals any password."""
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM analyses").fetchone()["c"]

        by_class = {
            row["classification"]: row["c"]
            for row in conn.execute(
                "SELECT classification, COUNT(*) AS c FROM analyses GROUP BY classification"
            )
        }

        avg_row = conn.execute("SELECT AVG(score) AS a FROM analyses").fetchone()
        average_score = round(avg_row["a"], 2) if avg_row["a"] is not None else 0.0

        length_buckets = {"<8": 0, "8-11": 0, "12-15": 0, "16+": 0}
        for row in conn.execute("SELECT password_length FROM analyses"):
            length = row["password_length"]
            if length < 8:
                length_buckets["<8"] += 1
            elif length < 12:
                length_buckets["8-11"] += 1
            elif length < 16:
                length_buckets["12-15"] += 1
            else:
                length_buckets["16+"] += 1

        score_buckets = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
        for row in conn.execute("SELECT score FROM analyses"):
            s = row["score"]
            if s <= 20:
                score_buckets["0-20"] += 1
            elif s <= 40:
                score_buckets["21-40"] += 1
            elif s <= 60:
                score_buckets["41-60"] += 1
            elif s <= 80:
                score_buckets["61-80"] += 1
            else:
                score_buckets["81-100"] += 1

    return {
        "total_analyses": total,
        "by_classification": by_class,
        "average_score": average_score,
        "length_distribution": length_buckets,
        "score_distribution": score_buckets,
        "privacy_note": "No passwords are stored. Only aggregate metadata.",
    }


def get_weakness_frequency() -> List[Dict]:
    """Return the frequency of each weakness type."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT finding_type, COUNT(*) AS c
            FROM findings
            GROUP BY finding_type
            ORDER BY c DESC
            """
        ).fetchall()
    return [{"type": row["finding_type"], "count": row["c"]} for row in rows]