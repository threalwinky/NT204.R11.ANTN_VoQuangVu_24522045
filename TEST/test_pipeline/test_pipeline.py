from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

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
