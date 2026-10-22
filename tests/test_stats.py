"""Testes de persistência e estatísticas usando SQLite em memória."""
from app.database import Database
from app.parser import PacketRecord
from app.stats import LiveStats, compute_stats


def rec(src, dst, proto, size):
    return PacketRecord(0.0, src, dst, proto, None, 4, size)


RECORDS = (
    [rec("10.0.0.1", "8.8.8.8", "UDP", 100)] * 10      # muitos pacotes pequenos
    + [rec("10.0.0.2", "1.1.1.1", "TCP", 1500)] * 3     # poucos pacotes grandes
    + [rec("10.0.0.3", "1.1.1.1", "TCP", 60)]
    + [rec(None, None, "ETHERTYPE-0x88cc", 64)]
)


def make_db():
    db = Database(":memory:")
    sid = db.start_session("eth0", None)
    db.insert_packets(sid, RECORDS)
    return db, sid


def test_totals_and_protocols():
    db, sid = make_db()
    s = compute_stats(db.conn, sid)
    assert s.total_packets == 15
    assert s.total_bytes == 1000 + 4500 + 60 + 64
    assert {r.key: r.packets for r in s.by_protocol} == {"UDP": 10, "TCP": 4, "ETHERTYPE-0x88cc": 1}


def test_top_ips_by_bytes_vs_packets():
    db, sid = make_db()
    by_bytes = compute_stats(db.conn, sid, order_by="bytes")
    by_packets = compute_stats(db.conn, sid, order_by="packets")
    assert by_bytes.top_sources[0].key == "10.0.0.2"
    assert by_packets.top_sources[0].key == "10.0.0.1"
    assert by_bytes.top_destinations[0].key == "1.1.1.1"
    assert all(r.key is not None for r in by_bytes.top_sources)  # NULL não entra no ranking


def test_top_limit_and_session_isolation():
    db, sid = make_db()
    other = db.start_session("lo", None)
    db.insert_packets(other, [rec("172.16.0.9", "172.16.0.1", "TCP", 9999)])
    assert len(compute_stats(db.conn, sid, top=2).top_sources) == 2
    assert compute_stats(db.conn, sid).total_packets == 15
    assert compute_stats(db.conn, None).total_packets == 16  # todas as sessões


def test_live_stats_matches_sql():
    db, sid = make_db()
    live = LiveStats()
    for r in RECORDS:
        live.add(r)
    assert live.snapshot() == compute_stats(db.conn, sid)
