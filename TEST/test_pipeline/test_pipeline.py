from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

import modules.core.pipeline as pipeline
from modules.core import parse_packet

packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20",
    )
    / TCP(
        sport=50000,
        dport=80,
        flags="PA",
    )
    / Raw(
        load=(
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"\r\n"
        )
    )
)

event = parse_packet(
    packet,
    packet_id=1,
)

print(event.to_dict())

dns_packet = (
    IP(
        src="192.168.1.30",
        dst="192.168.1.40",
    )
    / UDP(
        sport=53000,
        dport=53,
    )
    / DNS(
        qr=0,
    )
    / DNSQR(
        qname="example.com",
    )
)

arp_packet = Ether() / ARP()

icmp_packet = (
    IP(
        src="192.168.1.50",
        dst="192.168.1.60",
    )
    / ICMP()
)

def test_parse_packet_pipeline():
    assert event.packet_id == 1
    assert event.network_protocol == "IPv4"
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "192.168.1.20"
    assert event.transport_protocol == "TCP"
    assert event.src_port == 50000
    assert event.dst_port == 80
    assert event.tcp_flags == "PA"
    assert event.application_protocol == "HTTP"
    assert event.application_data["type"] == "request"
    assert event.application_data["method"] == "GET"
    assert event.application_data["uri"] == "/index.html"
    assert event.application_data["headers"]["Host"] == "example.com"

def test_parse_packet_records_error(monkeypatch):

    def fail_parser(packet, event):
        raise ValueError("broken parser")

    monkeypatch.setattr(
        pipeline,
        "parse_dns_query",
        fail_parser,
    )

    dns_event = parse_packet(
        dns_packet,
        packet_id=2,
    )

    assert dns_event.status == "ERROR"
    assert dns_event.error == "ValueError: broken parser"
    assert dns_event.network_protocol == "IPv4"
    assert dns_event.transport_protocol == "UDP"
    assert dns_event.application_protocol == "DNS"

def test_parse_packet_marks_unknown():

    arp_event = parse_packet(arp_packet, packet_id=3)
    icmp_event = parse_packet(icmp_packet, packet_id=4)

    assert event.status == "OK"
    assert event.error is None

    assert arp_event.status == "UNKNOWN"
    assert arp_event.error is None

    assert icmp_event.status == "UNKNOWN"
    assert icmp_event.network_protocol == "IPv4"

def test_parse_packet_error_beats_unknown(monkeypatch):

    def fail_parser(packet, event):
        raise TypeError("broken network parser")

    monkeypatch.setattr(
        pipeline,
        "parse_ipv4",
        fail_parser,
    )

    arp_event = parse_packet(arp_packet, packet_id=5)

    assert arp_event.status == "ERROR"
    assert arp_event.error == "TypeError: broken network parser"
