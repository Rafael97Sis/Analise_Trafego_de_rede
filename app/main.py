"""Ponto de entrada (CLI) do Traffic Analyzer.

Comandos:
  interfaces  lista as interfaces de rede disponíveis
  capture     captura pacotes, grava no banco e mostra estatísticas
  stats       recalcula estatísticas a partir do banco
  sessions    lista as sessões de captura gravadas
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time

# Silencia avisos de inicialização do Scapy (ex.: falta de rota IPv6).
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.config import conf  # noqa: E402
from scapy.sendrecv import AsyncSniffer  # noqa: E402

from app.database import Database  # noqa: E402
from app.parser import parse_packet  # noqa: E402
from app.report import render  # noqa: E402
from app.stats import LiveStats, compute_stats  # noqa: E402
from app.writer import PacketWriter  # noqa: E402

log = logging.getLogger("traffic_analyzer")
DEFAULT_DB = os.environ.get("DB_PATH", "data/traffic.db")


# --------------------------------------------------------------------------- #
# Comandos
# --------------------------------------------------------------------------- #
def find_interface(name: str):
    """Localiza uma interface pelo nome, descrição ou nome de rede.

    No Linux os três costumam ser iguais (ex.: eth0). No Windows (Npcap) o
    nome amigável é "Wi-Fi"/"Ethernet" e o nome de rede é "\\Device\\NPF_{GUID}";
    aceitar qualquer um deles deixa a CLI igual nos dois sistemas.
    """
    for iface in conf.ifaces.values():
        if name in (iface.name, iface.description, iface.network_name):
            return iface
    return None


def cmd_interfaces(_args) -> int:
    default = getattr(conf.iface, "name", str(conf.iface))
    rows = [(i.name, i.description or "", ", ".join(i.ips.get(4, [])) or "-")
            for i in conf.ifaces.values()]
    w_name = max([len("Nome")] + [len(r[0]) for r in rows])
    w_desc = max([len("Descrição")] + [len(r[1]) for r in rows])
    print(f"  {'Nome':<{w_name}}  {'Descrição':<{w_desc}}  IPv4")
    for name, desc, ips in rows:
        mark = "  (padrão)" if name == default else ""
        print(f"  {name:<{w_name}}  {desc:<{w_desc}}  {ips}{mark}")
    print('\nUse o valor da coluna "Nome" em: capture -i <Nome>')
    return 0


def cmd_capture(args) -> int:
    requested = args.interface or getattr(conf.iface, "name", str(conf.iface))
    nic = find_interface(requested)
    if nic is None:
        log.error("Interface '%s' não encontrada. Rode o comando 'interfaces' para ver as opções.", requested)
        return 2
    iface = nic.name

    db = Database(args.db)
    session_id = db.start_session(iface, args.filter)
    writer = PacketWriter(db, session_id, batch_size=args.batch_size)
    live = LiveStats()

    def on_packet(pkt) -> None:
        # Executa na thread do sniffer: precisa ser leve (parse + enfileirar).
        try:
            record = parse_packet(pkt)
        except Exception:  # pacote malformado não derruba a captura
            log.debug("Pacote ignorado (falha no parse)", exc_info=True)
            return
        live.add(record)
        writer.submit(record)

    sniffer = AsyncSniffer(
        iface=nic,
        filter=args.filter,
        prn=on_packet,
        store=False,              # não guarda pacotes em memória; o banco é o armazenamento
        count=args.count,         # 0 = ilimitado
        timeout=args.timeout,     # None = ilimitado
    )

    stop_event = threading.Event()

    def handle_signal(signum, _frame):
        log.info("Sinal %s recebido, finalizando captura...", signal.Signals(signum).name)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)    # Ctrl+C
    signal.signal(signal.SIGTERM, handle_signal)   # docker stop

    limits = []
    if args.count:
        limits.append(f"{args.count} pacotes")
    if args.timeout:
        limits.append(f"{args.timeout}s")
    log.info("Sessão #%d | interface=%s | filtro=%s | limite=%s | banco=%s",
             session_id, iface, args.filter or "(nenhum)", " ou ".join(limits) or "Ctrl+C", args.db)

    writer.start()
    sniffer.start()
    last_report = time.monotonic()
    error = None
    try:
        # Laço principal: espera o fim da captura imprimindo o painel ao vivo.
        while sniffer.thread.is_alive() and not stop_event.wait(0.5):
            if args.live_interval and time.monotonic() - last_report >= args.live_interval:
                print(render(live.snapshot(args.top, args.order_by),
                             f"AO VIVO - sessão #{session_id}", args.top, args.order_by), flush=True)
                last_report = time.monotonic()
    finally:
        try:
            if sniffer.thread.is_alive():
                sniffer.stop()
            else:
                sniffer.join()      # relança exceções da thread (ex.: permissão negada)
        except Exception as exc:    # noqa: BLE001
            error = exc
        writer.stop()               # grava o que restou na fila
        db.end_session(session_id, writer.written, writer.dropped)

    if error:
        log.error("Erro na captura: %s", error)
        if isinstance(error, PermissionError):
            log.error("Execute como root ou com as capabilities NET_RAW/NET_ADMIN.")

    log.info("Captura finalizada: %d pacotes gravados, %d descartados.", writer.written, writer.dropped)
    stats = compute_stats(db.conn, session_id, args.top, args.order_by)
    print(render(stats, f"RESULTADO - sessão #{session_id} ({iface})", args.top, args.order_by))
    db.close()
    return 1 if error else 0


def cmd_stats(args) -> int:
    db = Database(args.db)
    session_id = None if args.all else (args.session or db.latest_session_id())
    if session_id is None and not args.all:
        print("Nenhuma sessão encontrada no banco. Execute 'capture' primeiro.")
        return 1
    stats = compute_stats(db.conn, session_id, args.top, args.order_by)
    title = "ESTATÍSTICAS - todas as sessões" if session_id is None else f"ESTATÍSTICAS - sessão #{session_id}"
    print(render(stats, title, args.top, args.order_by))
    db.close()
    return 0


def cmd_sessions(args) -> int:
    db = Database(args.db)
    rows = db.list_sessions()
    if not rows:
        print("Nenhuma sessão gravada.")
        return 0
    print(f"{'ID':>4}  {'Interface':<12} {'Início (UTC)':<26} {'Fim (UTC)':<26} {'Pacotes':>8}  Filtro")
    for r in rows:
        print(f"{r['id']:>4}  {r['interface']:<12} {r['started_at']:<26} {r['ended_at'] or '(em andamento)':<26}"
              f" {r['stored']:>8}  {r['bpf_filter'] or '-'}")
    db.close()
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def positive_int(value: str) -> int:
    n = int(value)
    if n < 0:
        raise argparse.ArgumentTypeError("deve ser >= 0")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="traffic-analyzer", description="Captura e análise básica de tráfego de rede.")
    p.add_argument("--db", default=DEFAULT_DB, help=f"caminho do banco SQLite (padrão: {DEFAULT_DB})")
    p.add_argument("-v", "--verbose", action="store_true", help="logs detalhados")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("interfaces", help="lista interfaces de rede").set_defaults(func=cmd_interfaces)

    def add_report_opts(sp):
        sp.add_argument("--top", type=positive_int, default=5, help="quantidade de IPs no ranking (padrão: 5)")
        sp.add_argument("--order-by", choices=["bytes", "packets"], default="bytes",
                        help="critério do ranking de IPs (padrão: bytes)")

    c = sub.add_parser("capture", help="captura pacotes de uma interface")
    c.add_argument("-i", "--interface", default=os.environ.get("INTERFACE"),
                   help="interface de rede (padrão: $INTERFACE ou a interface padrão do sistema)")
    c.add_argument("-c", "--count", type=positive_int, default=0, help="parar após N pacotes (0 = sem limite)")
    c.add_argument("-t", "--timeout", type=positive_int, default=None, help="parar após N segundos")
    c.add_argument("-f", "--filter", default=None, help='filtro BPF, ex.: "tcp or udp", "port 443"')
    c.add_argument("--live-interval", type=positive_int, default=5,
                   help="segundos entre atualizações do painel ao vivo (0 desativa; padrão: 5)")
    c.add_argument("--batch-size", type=positive_int, default=500, help="pacotes por transação no banco")
    add_report_opts(c)
    c.set_defaults(func=cmd_capture)

    s = sub.add_parser("stats", help="estatísticas a partir do banco")
    g = s.add_mutually_exclusive_group()
    g.add_argument("-s", "--session", type=int, help="ID da sessão (padrão: a mais recente)")
    g.add_argument("--all", action="store_true", help="agrega todas as sessões")
    add_report_opts(s)
    s.set_defaults(func=cmd_stats)

    sub.add_parser("sessions", help="lista sessões de captura").set_defaults(func=cmd_sessions)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
