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