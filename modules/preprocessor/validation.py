from ipaddress import IPv4Address
from math import isfinite

from ..models import NormalizedIDSEvent


def validate_event(
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:

    invalid = []
    partial = []

    if type(event.packet_id) is not int or event.packet_id < 1:
        invalid.append("invalid_packet_id")

    if (
        type(event.timestamp) not in (int, float)
        or not isfinite(event.timestamp)
        or event.timestamp < 0
    ):
        invalid.append("invalid_timestamp")

    if event.network_protocol is None:
        partial.append("missing_network_protocol")

    elif not isinstance(event.network_protocol, str):
        invalid.append("invalid_network_protocol")

    elif event.network_protocol == "IPv4":
        for field in ("src_ip", "dst_ip"):
            value = getattr(event, field)

            if value is None:
                partial.append(f"missing_{field}")
                continue

            try:
                if not isinstance(value, str):
                    raise ValueError("IP must be a string")
                IPv4Address(value)
            except ValueError:
                invalid.append(f"invalid_{field}")

    else:
        partial.append("unsupported_network_protocol")

    if event.transport_protocol is None:
        partial.append("missing_transport_protocol")

    elif not isinstance(event.transport_protocol, str):
        invalid.append("invalid_transport_protocol")

    elif event.transport_protocol not in ("TCP", "UDP"):
        partial.append("unsupported_transport_protocol")

    for field in ("src_port", "dst_port"):
        port = getattr(event, field)

        if port is None:
            if event.transport_protocol in ("TCP", "UDP"):
                partial.append(f"missing_{field}")
            continue

        if type(port) is not int or not 0 <= port <= 65535:
            invalid.append(f"invalid_{field}")

    if event.application_protocol is None:
        partial.append("missing_application_protocol")

    elif not isinstance(event.application_protocol, str):
        invalid.append("invalid_application_protocol")

    elif event.application_protocol not in ("HTTP", "DNS", "SMTP"):
        partial.append("unsupported_application_protocol")

    if (
        type(event.payload_length) is not int
        or event.payload_length < 0
    ):
        invalid.append("invalid_payload_length")

    if not isinstance(event.application_data, dict):
        invalid.append("invalid_application_data")

    if event.status == "ERROR":
        invalid.append("parser_error")

    elif event.status not in ("OK", "UNKNOWN"):
        invalid.append("invalid_event_status")

    if invalid:
        event.preprocess_status = "invalid"
    elif partial:
        event.preprocess_status = "partial"
    else:
        event.preprocess_status = "valid"

    event.processing_action = "emit"
    event.reason = "; ".join(invalid + partial) or None

    return event
