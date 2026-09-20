from scapy.layers.inet import IP
from main.models import NormalizedIDSEvent
from main.parsers import parse_ipv4

packet = IP(
    src="192.168.1.10",
    dst="8.8.8.8",
)

event = NormalizedIDSEvent(
    packet_id=1,
    timestamp=1234567890.0,
)

parse_ipv4(packet, event)

print(event.to_dict())