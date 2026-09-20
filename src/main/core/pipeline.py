import time

from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet

from main.detector import detect_application_protocol
from main.models import NormalizedIDSEvent
from main.parsers import (
    parse_dns_query,
    parse_dns_response,
    parse_http_request,
    parse_http_response,
    parse_ipv4,
    parse_smtp_command,
    parse_smtp_response,
    parse_tcp,
    parse_udp,
)

def parse_packet(
    packet: Packet,
    packet_id: int,
) -> NormalizedIDSEvent:

    packet_time = getattr(packet, "time", None)

    if packet_time is not None:
        timestamp = float(packet_time)
    else:
        timestamp = time.time()

    event = NormalizedIDSEvent(
        packet_id=packet_id,
        timestamp=timestamp,
    )

    # Network layer
    parse_ipv4(packet, event)

    # Transport layer
    if packet.haslayer(TCP):
        parse_tcp(packet, event)

    elif packet.haslayer(UDP):
        parse_udp(packet, event)

    # Application protocol detection
    detect_application_protocol(packet, event)

    # Application layer parsing
    if event.application_protocol == "HTTP":
        parse_http_request(packet, event)
        parse_http_response(packet, event)

    elif event.application_protocol == "DNS":
        parse_dns_query(packet, event)
        parse_dns_response(packet, event)

    elif event.application_protocol == "SMTP":
        parse_smtp_command(packet, event)
        parse_smtp_response(packet, event)

    return event