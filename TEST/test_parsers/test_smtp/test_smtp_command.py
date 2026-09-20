from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from main.detector import detect_application_protocol
from main.models import NormalizedIDSEvent
from main.parsers import (
    parse_ipv4,
    parse_smtp_command,
    parse_tcp,
)

packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20",
    )
    / TCP(
        sport=50000,
        dport=25,
        flags="PA",
    )
    / Raw(
        load=b"EHLO example.com\r\n"
    )
)

event = NormalizedIDSEvent(
    packet_id=1,
    timestamp=1234567890.0,
)

parse_ipv4(packet, event)
parse_tcp(packet, event)
detect_application_protocol(packet, event)
parse_smtp_command(packet, event)

print(event.to_dict())