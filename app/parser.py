"""Conversão de pacotes Scapy em registros simples (PacketRecord).

Este módulo é a única parte que "conhece" o Scapy na hora de extrair
os campos. Mantê-lo isolado facilita testar a lógica sem capturar
tráfego real (basta montar pacotes sintéticos com Scapy).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

# Números de protocolo IANA mais comuns -> nome legível.
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-in-IPv4",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}

# Cabeçalhos de extensão IPv6 que precisamos "atravessar" para achar
# o protocolo de camada superior (Hop-by-Hop, Routing, Fragment, Dest. Options).
IPV6_EXTENSION_HEADERS = {0, 43, 44, 60}


@dataclass(frozen=True)
class PacketRecord:
    """Campos extraídos de um pacote capturado."""

    timestamp: float                # epoch (segundos) em que o pacote foi capturado
    src_ip: Optional[str]           # IP de origem (None para pacotes sem endereço IP)
    dst_ip: Optional[str]           # IP de destino
    protocol: str                   # nome do protocolo (TCP, UDP, ICMP, ARP, ...)
    protocol_number: Optional[int]  # número IANA do protocolo (None se não for IP)
    ip_version: Optional[int]       # 4, 6 ou None
    size: int                       # tamanho total do quadro em bytes


def protocol_name(number: int) -> str:
    return IP_PROTOCOLS.get(number, f"IP-{number}")


def _ipv6_upper_protocol(ip6) -> int:
    """Retorna o protocolo de camada 4 de um pacote IPv6, pulando extensões."""
    next_header = ip6.nh
    layer = ip6.payload
    while next_header in IPV6_EXTENSION_HEADERS and hasattr(layer, "nh"):
        next_header = layer.nh
        layer = layer.payload
    return next_header


def parse_packet(pkt) -> PacketRecord:
    """Extrai origem, destino, protocolo e tamanho de um pacote Scapy."""
    size = len(pkt)
    timestamp = float(pkt.time)

    if IP in pkt:
        ip = pkt[IP]
        number = int(ip.proto)
        return PacketRecord(timestamp, ip.src, ip.dst, protocol_name(number), number, 4, size)

    if IPv6 in pkt:
        ip6 = pkt[IPv6]
        number = int(_ipv6_upper_protocol(ip6))
        return PacketRecord(timestamp, ip6.src, ip6.dst, protocol_name(number), number, 6, size)

    if ARP in pkt:
        # ARP não é IP, mas carrega endereços IP (psrc/pdst); útil para análise de LAN.
        arp = pkt[ARP]
        return PacketRecord(timestamp, arp.psrc, arp.pdst, "ARP", None, None, size)

    # Qualquer outro quadro (LLDP, STP, ...): registra só protocolo e tamanho.
    if Ether in pkt:
        name = f"ETHERTYPE-0x{pkt[Ether].type:04x}"
    else:
        name = "OTHER"
    return PacketRecord(timestamp, None, None, name, None, None, size)
