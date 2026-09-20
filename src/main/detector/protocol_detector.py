from scapy.layers.dns import DNS
from scapy.packet import Packet, Raw

from main.models import NormalizedIDSEvent

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
)

HTTP_PORTS = {80, 8000, 8080, 8888}
DNS_PORTS = {53}
SMTP_PORTS = {25, 587}

SMTP_COMMANDS = (
    b"HELO ",
    b"EHLO ",
    b"MAIL FROM:",
    b"RCPT TO:",
    b"DATA",
    b"QUIT",
    b"RSET",
    b"NOOP",
    b"VRFY ",
    b"EXPN ",
    b"STARTTLS",
    b"AUTH ",
)

def _get_payload(packet: Packet) -> bytes:

    if packet.haslayer(Raw):
        return bytes(packet[Raw].load)

    return b""


def _looks_like_http(payload: bytes) -> bool:

    upper_payload = payload.upper()

    if upper_payload.startswith(HTTP_METHODS):
        return True

    return payload.startswith((b"HTTP/1.0 ", b"HTTP/1.1 "))


def _looks_like_smtp(payload: bytes) -> bool:

    upper_payload = payload.upper()
    return upper_payload.startswith(SMTP_COMMANDS)


def detect_application_protocol(
    packet: Packet,
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:

    payload = _get_payload(packet)

    if _looks_like_http(payload):
        event.application_protocol = "HTTP"
        return event

    if _looks_like_smtp(payload):
        event.application_protocol = "SMTP"
        return event

    if packet.haslayer(DNS):
        event.application_protocol = "DNS"
        return event

    ports = {
        port
        for port in (event.src_port, event.dst_port)
        if port is not None
    }

    if ports & DNS_PORTS:
        event.application_protocol = "DNS"
    elif ports & HTTP_PORTS:
        event.application_protocol = "HTTP"
    elif ports & SMTP_PORTS:
        event.application_protocol = "SMTP"

    return event