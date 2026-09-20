from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from main.detector import detect_application_protocol
from main.models import NormalizedIDSEvent
from main.parsers import parse_tcp

packet = (
    IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=50000, dport=25)
    / Raw(load=b"EHLO example.com\r\n")
)

event = NormalizedIDSEvent(
    packet_id=3,
    timestamp=1234567890.0,
)

parse_tcp(packet, event)
detect_application_protocol(packet, event)

print(event.to_dict())