from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


class CacheManager:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS contract_analysis_cache (
                    cache_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS exploit_pattern_cache (
                    pattern_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS duplicate_report_cache (
                    fingerprint TEXT PRIMARY KEY,
                    platform TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )

    def get_contract_analysis(self, cache_key: str) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM contract_analysis_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def set_contract_analysis(self, cache_key: str, payload: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO contract_analysis_cache(cache_key, payload, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET payload=excluded.payload, created_at=excluded.created_at
                """,
                (cache_key, json.dumps(payload), int(time.time())),
            )

    def get_exploit_pattern(self, pattern_key: str) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM exploit_pattern_cache WHERE pattern_key = ?",
                (pattern_key,),
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def set_exploit_pattern(self, pattern_key: str, payload: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO exploit_pattern_cache(pattern_key, payload, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(pattern_key) DO UPDATE SET payload=excluded.payload, created_at=excluded.created_at
                """,
                (pattern_key, json.dumps(payload), int(time.time())),
            )

    def has_duplicate_fingerprint(self, fingerprint: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM duplicate_report_cache WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        return bool(row)

    def set_duplicate_fingerprint(self, fingerprint: str, platform: str, payload: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO duplicate_report_cache(fingerprint, platform, payload, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    platform=excluded.platform,
                    payload=excluded.payload,
                    created_at=excluded.created_at
                """,
                (fingerprint, platform, json.dumps(payload), int(time.time())),
            )