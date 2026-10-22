"""Thread que grava os pacotes no banco em lotes.

O callback do Scapy roda na thread de captura e precisa ser rápido: se
ele fizesse um INSERT por pacote, o kernel poderia descartar pacotes
em rajadas. Por isso o callback só coloca o registro numa fila e esta
thread grava em lotes (por tamanho ou por tempo, o que vier primeiro).
"""
from __future__ import annotations

import logging
import queue
import threading
import time

from app.database import Database
from app.parser import PacketRecord

log = logging.getLogger(__name__)
_STOP = object()


class PacketWriter(threading.Thread):
    def __init__(self, db: Database, session_id: int, batch_size: int = 500,
                 flush_interval: float = 1.0, max_queue: int = 100_000):
        super().__init__(name="PacketWriter", daemon=True)
        self.db = db
        self.session_id = session_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self.written = 0
        self.dropped = 0  # pacotes descartados porque a fila encheu

    def submit(self, record: PacketRecord) -> None:
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            self.dropped += 1

    def stop(self) -> None:
        self.queue.put(_STOP)  # bloqueante: garante que o sinal de parada entre
        self.join()

    def run(self) -> None:
        batch: list[PacketRecord] = []
        last_flush = time.monotonic()
        while True:
            try:
                item = self.queue.get(timeout=self.flush_interval)
            except queue.Empty:
                item = None
            if item is _STOP:
                self._flush(batch)
                return
            if item is not None:
                batch.append(item)
            if len(batch) >= self.batch_size or time.monotonic() - last_flush >= self.flush_interval:
                self._flush(batch)
                batch = []
                last_flush = time.monotonic()

    def _flush(self, batch: list[PacketRecord]) -> None:
        if not batch:
            return
        try:
            self.written += self.db.insert_packets(self.session_id, batch)
        except Exception:  # não derruba a captura por erro de escrita
            log.exception("Falha ao gravar lote de %d pacotes", len(batch))
            self.dropped += len(batch)
