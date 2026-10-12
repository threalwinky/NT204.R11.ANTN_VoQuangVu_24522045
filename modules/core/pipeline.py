import time

from scapy.layers.inet import TCP, UDP
from scapy.packet import Packet

from ..decoder import (
    decode_html_entities,
    decode_http_form,
    decode_http_uri,
    decode_smtp_mime,
)
from ..detector import detect_application_protocol
from ..models import NormalizedIDSEvent
from ..preprocessor import (
    apply_processing_policy,
    handle_missing_fields,
    normalize_event,
    validate_event,
)
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

    # Decode
    try:
        decode_http_uri(event)
        decode_http_form(event)
        decode_html_entities(event)
        decode_smtp_mime(packet, event)
    except Exception as error:
        _record_parse_error(event, error)

    _mark_unknown(event)

    try:
        normalize_event(event)
        validate_event(event)
        handle_missing_fields(event)
        apply_processing_policy(event)
    except Exception as error:
        _record_parse_error(event, error)
        event.preprocess_status = "invalid"
        event.processing_action = "emit"
        event.reason = "validation_exception"

    return event