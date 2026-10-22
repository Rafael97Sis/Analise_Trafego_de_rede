"""Formatação das estatísticas em tabelas de texto para o terminal."""
from __future__ import annotations

from app.stats import Row, TrafficStats


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"


def _table(headers: list[str], rows: list[list[str]], align_right: set[int]) -> str:
    if not rows:
        return "  (sem dados)"
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]

    def fmt(cells):
        out = [c.rjust(w) if i in align_right else c.ljust(w) for i, (c, w) in enumerate(zip(cells, widths))]
        return "  " + "  ".join(out)

    sep = "  " + "  ".join("-" * w for w in widths)
    return "\n".join([fmt(headers), sep, *(fmt(r) for r in rows)])


def _pct(part: int, total: int) -> str:
    return f"{(100 * part / total):.1f}%" if total else "0.0%"


def _ip_table(rows: list[Row], total_bytes: int) -> str:
    body = [[str(i), r.key, str(r.packets), human_bytes(r.bytes), _pct(r.bytes, total_bytes)]
            for i, r in enumerate(rows, 1)]
    return _table(["#", "Endereço IP", "Pacotes", "Bytes", "% bytes"], body, {0, 2, 3, 4})


def render(stats: TrafficStats, title: str, top: int = 5, order_by: str = "bytes") -> str:
    criterion = "bytes" if order_by == "bytes" else "pacotes"
    proto_rows = [[r.key, str(r.packets), _pct(r.packets, stats.total_packets), human_bytes(r.bytes)]
                  for r in stats.by_protocol]
    line = "=" * 64
    return "\n".join([
        line,
        f" {title}",
        line,
        f"  Total de pacotes capturados: {stats.total_packets}",
        f"  Volume total:                {human_bytes(stats.total_bytes)}",
        "",
        "  Pacotes por protocolo",
        _table(["Protocolo", "Pacotes", "%", "Bytes"], proto_rows, {1, 2, 3}),
        "",
        f"  Top {top} IPs de ORIGEM (ordenado por {criterion})",
        _ip_table(stats.top_sources, stats.total_bytes),
        "",
        f"  Top {top} IPs de DESTINO (ordenado por {criterion})",
        _ip_table(stats.top_destinations, stats.total_bytes),
        line,
    ])
