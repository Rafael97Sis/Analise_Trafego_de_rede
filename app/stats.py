"""Cálculo de estatísticas de tráfego.

Duas fontes, mesmo formato de saída (TrafficStats):
  * compute_stats(): consulta SQL no banco -> relatório final/histórico.
  * LiveStats: contadores em memória -> painel ao vivo durante a captura,
    sem precisar consultar o banco a cada atualização.
"""
from __future__ import annotations

import sqlite3
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from app.parser import PacketRecord


@dataclass
class Row:
    key: str
    packets: int
    bytes: int


@dataclass
class TrafficStats:
    total_packets: int = 0
    total_bytes: int = 0
    by_protocol: list[Row] = field(default_factory=list)
    top_sources: list[Row] = field(default_factory=list)
    top_destinations: list[Row] = field(default_factory=list)


ORDER_COLUMNS = {"bytes": "bytes DESC, packets DESC", "packets": "packets DESC, bytes DESC"}


def compute_stats(conn: sqlite3.Connection, session_id: Optional[int] = None,
                  top: int = 5, order_by: str = "bytes") -> TrafficStats:
    """Calcula as estatísticas via SQL. session_id=None agrega todas as sessões."""
    order = ORDER_COLUMNS[order_by]
    params = {"sid": session_id, "top": top}
    where = "(:sid IS NULL OR session_id = :sid)"

    total = conn.execute(
        f"SELECT COUNT(*), COALESCE(SUM(size), 0) FROM packets WHERE {where}", params
    ).fetchone()

    def grouped(column: str, limit: bool) -> list[Row]:
        sql = (
            f"SELECT {column} AS k, COUNT(*) AS packets, SUM(size) AS bytes FROM packets "
            f"WHERE {where} AND {column} IS NOT NULL GROUP BY {column} ORDER BY "
            + ("packets DESC, bytes DESC" if not limit else order)
            + (" LIMIT :top" if limit else "")
        )
        return [Row(r[0], r[1], r[2]) for r in conn.execute(sql, params)]

    return TrafficStats(
        total_packets=total[0],
        total_bytes=total[1],
        by_protocol=grouped("protocol", limit=False),
        top_sources=grouped("src_ip", limit=True),
        top_destinations=grouped("dst_ip", limit=True),
    )


class LiveStats:
    """Contadores em memória, atualizados a cada pacote (thread-safe)."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self._proto = defaultdict(lambda: [0, 0])
        self._src = defaultdict(lambda: [0, 0])
        self._dst = defaultdict(lambda: [0, 0])

    def add(self, r: PacketRecord) -> None:
        with self._lock:
            self.total_packets += 1
            self.total_bytes += r.size
            for table, key in ((self._proto, r.protocol), (self._src, r.src_ip), (self._dst, r.dst_ip)):
                if key is not None:
                    table[key][0] += 1
                    table[key][1] += r.size

    def snapshot(self, top: int = 5, order_by: str = "bytes") -> TrafficStats:
        idx = 1 if order_by == "bytes" else 0

        def rows(table, limit=None):
            items = sorted(table.items(), key=lambda kv: (kv[1][idx], kv[1][1 - idx]), reverse=True)
            return [Row(k, v[0], v[1]) for k, v in items[:limit]]

        with self._lock:
            proto = sorted(self._proto.items(), key=lambda kv: (kv[1][0], kv[1][1]), reverse=True)
            return TrafficStats(
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                by_protocol=[Row(k, v[0], v[1]) for k, v in proto],
                top_sources=rows(self._src, top),
                top_destinations=rows(self._dst, top),
            )
