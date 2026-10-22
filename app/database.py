"""Camada de persistência em SQLite."""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from app.parser import PacketRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS capture_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    interface     TEXT    NOT NULL,
    bpf_filter    TEXT,
    started_at    TEXT    NOT NULL,          -- ISO-8601 UTC
    ended_at      TEXT,                      -- NULL enquanto a captura roda
    packet_count  INTEGER NOT NULL DEFAULT 0,
    dropped_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS packets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    captured_at     REAL    NOT NULL,        -- epoch em segundos (precisão de µs)
    src_ip          TEXT,
    dst_ip          TEXT,
    protocol        TEXT    NOT NULL,
    protocol_number INTEGER,
    ip_version      INTEGER,
    size            INTEGER NOT NULL CHECK (size >= 0)
);

CREATE INDEX IF NOT EXISTS idx_packets_session  ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(session_id, protocol);
CREATE INDEX IF NOT EXISTS idx_packets_src      ON packets(session_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst      ON packets(session_id, dst_ip);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    """Wrapper fino sobre sqlite3, seguro para uso entre threads (com lock)."""

    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            # WAL permite ler (comando stats) enquanto outra captura escreve.
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.executescript(SCHEMA)

    def start_session(self, interface: str, bpf_filter: Optional[str]) -> int:
        with self._lock, self.conn:
            cur = self.conn.execute(
                "INSERT INTO capture_sessions (interface, bpf_filter, started_at) VALUES (?, ?, ?)",
                (interface, bpf_filter, _utc_now()),
            )
            return int(cur.lastrowid)

    def end_session(self, session_id: int, packet_count: int, dropped_count: int) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE capture_sessions SET ended_at = ?, packet_count = ?, dropped_count = ? WHERE id = ?",
                (_utc_now(), packet_count, dropped_count, session_id),
            )

    def insert_packets(self, session_id: int, records: Iterable[PacketRecord]) -> int:
        rows = [
            (session_id, r.timestamp, r.src_ip, r.dst_ip, r.protocol,
             r.protocol_number, r.ip_version, r.size)
            for r in records
        ]
        if not rows:
            return 0
        with self._lock, self.conn:  # uma transação por lote
            self.conn.executemany(
                "INSERT INTO packets (session_id, captured_at, src_ip, dst_ip, protocol,"
                " protocol_number, ip_version, size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def list_sessions(self) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT s.*, (SELECT COUNT(*) FROM packets p WHERE p.session_id = s.id) AS stored"
                " FROM capture_sessions s ORDER BY s.id DESC"
            ).fetchall()

    def latest_session_id(self) -> Optional[int]:
        with self._lock:
            row = self.conn.execute("SELECT MAX(id) FROM capture_sessions").fetchone()
        return row[0] if row else None

    def close(self) -> None:
        with self._lock:
            self.conn.close()
