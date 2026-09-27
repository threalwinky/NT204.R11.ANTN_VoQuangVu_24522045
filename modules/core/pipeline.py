import time

from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet

from ..detector import detect_application_protocol
from ..models import NormalizedIDSEvent
from ..parsers import (
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

def _record_parse_error(
    event: NormalizedIDSEvent,
    error: Exception,
) -> None:

    event.status = "ERROR"
    event.error = f"{type(error).__name__}: {error}"


def _mark_unknown(
    event: NormalizedIDSEvent,
) -> None:

    if event.status != "OK":
        return

    if event.transport_protocol is None and event.application_protocol is None:
        event.status = "UNKNOWN"


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

    try:
        # Network layer
        parse_ipv4(packet, event)

        # Transport layer
        if packet.haslayer(TCP):
            parse_tcp(packet, event)

        elif packet.haslayer(UDP):
            parse_udp(packet, event)

        # Application protocol detection
        detect_application_protocol(packet, event)

    except Exception as error:
        _record_parse_error(event, error)

    try:
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

    except Exception as error:
        _record_parse_error(event, error)

    _mark_unknown(event)

    return event