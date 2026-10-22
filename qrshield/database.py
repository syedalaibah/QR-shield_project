"""Local SQLite storage for scan history."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "qrshield_history.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def _managed_connection() -> Iterator[sqlite3.Connection]:
    connection = _connect()
    try:
        yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    with _managed_connection() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analyzed_at TEXT NOT NULL,
                source TEXT NOT NULL,
                payload TEXT NOT NULL,
                kind TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                target TEXT NOT NULL,
                indicators_json TEXT NOT NULL,
                recommendations_json TEXT NOT NULL,
                engine TEXT NOT NULL
            )"""
        )
        connection.commit()


def save_scan(result: dict, source: str = "Manual input") -> int:
    """Save only the redacted payload supplied by the analyzer."""
    initialize_database()
    with _managed_connection() as connection:
        cursor = connection.execute(
            """INSERT INTO scans
                (analyzed_at, source, payload, kind, score, level, target,
                 indicators_json, recommendations_json, engine)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result.get("analyzed_at", ""),
                source,
                result.get("payload", "")[:2000],
                result.get("kind", "Unknown"),
                int(result.get("score", 0)),
                result.get("level", "Low"),
                result.get("target", "")[:2000],
                json.dumps(result.get("indicators", []), ensure_ascii=False),
                json.dumps(result.get("recommendations", []), ensure_ascii=False),
                result.get("engine", "QRShield Offline Rules v1.0"),
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def get_scans(limit: int = 500) -> list[dict]:
    initialize_database()
    with _managed_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 5000)),)
        ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["indicators"] = json.loads(item.pop("indicators_json"))
        item["recommendations"] = json.loads(item.pop("recommendations_json"))
        results.append(item)
    return results


def get_scan(scan_id: int) -> dict | None:
    initialize_database()
    with _managed_connection() as connection:
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["indicators"] = json.loads(item.pop("indicators_json"))
    item["recommendations"] = json.loads(item.pop("recommendations_json"))
    return item


def clear_scans() -> None:
    initialize_database()
    with _managed_connection() as connection:
        connection.execute("DELETE FROM scans")
        connection.commit()
