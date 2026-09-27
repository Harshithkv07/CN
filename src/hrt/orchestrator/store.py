"""SQLite incident store (stdlib only). One row per incident; the full object is kept as JSON."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from hrt.models import Incident


class IncidentStore:
    def __init__(self, path: Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                source_ip   TEXT,
                status      TEXT,
                detected_at REAL,
                data        TEXT
            )""")
        self._conn.commit()

    def upsert(self, inc: Incident) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO incidents VALUES (?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET "
                "status=excluded.status, data=excluded.data",
                (inc.incident_id, str(inc.alert.source_ip), inc.status, inc.alert.detected_at,
                 inc.model_dump_json()))
            self._conn.commit()

    def get(self, incident_id: str) -> Incident | None:
        row = self._conn.execute("SELECT data FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        return Incident.model_validate_json(row[0]) if row else None

    def recent(self, limit: int = 100) -> list[Incident]:
        rows = self._conn.execute("SELECT data FROM incidents ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()
        return [Incident.model_validate_json(r[0]) for r in rows]

    def deployed_rules(self) -> list[str]:
        """restore-syntax lines for every currently deployed rule (used by the conflict checker)."""
        rows = self._conn.execute("SELECT data FROM incidents WHERE status='DEPLOYED'").fetchall()
        out = []
        for (data,) in rows:
            inc = Incident.model_validate_json(data)
            if inc.verdict and inc.verdict.restore_line:
                out.append(inc.verdict.restore_line)
        return out

    def counts(self) -> dict[str, int]:
        rows = self._conn.execute("SELECT status, COUNT(*) FROM incidents GROUP BY status").fetchall()
        return {status: n for status, n in rows}

    def clear(self) -> int:
        with self._lock:
            n = self._conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            self._conn.execute("DELETE FROM incidents")
            self._conn.commit()
        return n
