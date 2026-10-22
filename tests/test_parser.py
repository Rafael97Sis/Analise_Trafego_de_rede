"""Testes do parser usando pacotes sintéticos (não precisam de rede nem root)."""
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6, IPv6ExtHdrHopByHop
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.parser import parse_packet


def test_ipv4_tcp():
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443) / Raw(b"a" * 100)
    r = parse_packet(pkt)
    assert (r.src_ip, r.dst_ip, r.protocol, r.protocol_number, r.ip_version) == ("10.0.0.1", "10.0.0.2", "TCP", 6, 4)
    assert r.size == len(pkt) == 14 + 20 + 20 + 100


def test_ipv4_udp_and_icmp():
    assert parse_packet(Ether() / IP() / UDP(dport=53)).protocol == "UDP"
    assert parse_packet(Ether() / IP() / ICMP()).protocol == "ICMP"


def test_ipv6_with_extension_header():
    pkt = Ether() / IPv6(src="fe80::1", dst="ff02::1") / IPv6ExtHdrHopByHop() / ICMPv6EchoRequest()
    r = parse_packet(pkt)
    assert r.protocol == "ICMPv6" and r.protocol_number == 58 and r.ip_version == 6
    assert r.src_ip == "fe80::1"


def test_unknown_ip_protocol_gets_numeric_name():
    assert parse_packet(Ether() / IP(proto=253)).protocol == "IP-253"


def test_arp_and_non_ip():
    r = parse_packet(Ether() / ARP(psrc="192.168.0.1", pdst="192.168.0.20"))
    assert (r.protocol, r.src_ip, r.dst_ip, r.ip_version) == ("ARP", "192.168.0.1", "192.168.0.20", None)
    other = parse_packet(Ether(type=0x88CC) / Raw(b"lldp"))
    assert other.protocol == "ETHERTYPE-0x88cc" and other.src_ip is None
