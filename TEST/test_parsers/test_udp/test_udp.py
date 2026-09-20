from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from main.models import NormalizedIDSEvent
from main.parsers import parse_ipv4, parse_udp

packet = (
    IP(
        src="192.168.1.10",
        dst="8.8.8.8",
    )
    / UDP(
        sport=53000,
        dport=53,
    )
    / Raw(load=b"hello")
)

event = NormalizedIDSEvent(
    packet_id=1,
    timestamp=1234567890.0,
)

parse_ipv4(packet, event)
parse_udp(packet, event)

print(event.to_dict())

def test_udp_parser():
    assert event.network_protocol == "IPv4"
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "8.8.8.8"
    assert event.transport_protocol == "UDP"
    assert event.src_port == 53000
    assert event.dst_port == 53
    assert event.payload_length == len(b"hello")
