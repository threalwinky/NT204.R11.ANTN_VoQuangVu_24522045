from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from main.detector import detect_application_protocol
from main.models import NormalizedIDSEvent
from main.parsers import (
    parse_http_response,
    parse_ipv4,
    parse_tcp,
)

packet = (
    IP(
        src="192.168.1.20",
        dst="192.168.1.10",
    )
    / TCP(
        sport=80,
        dport=50000,
    )
    / Raw(
        load=(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"Hello"
        )
    )
)

event = NormalizedIDSEvent(
    packet_id=1,
    timestamp=1234567890.0,
)

parse_ipv4(packet, event)
parse_tcp(packet, event)
detect_application_protocol(packet, event)
parse_http_response(packet, event)

print(event.to_dict())