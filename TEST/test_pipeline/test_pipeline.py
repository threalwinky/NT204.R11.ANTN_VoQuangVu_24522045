from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from main.core import parse_packet

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