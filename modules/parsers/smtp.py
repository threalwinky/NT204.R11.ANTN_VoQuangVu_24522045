from scapy.packet import Packet, Raw

from ..models import NormalizedIDSEvent

SMTP_COMMANDS = {
    "HELO",
    "EHLO",
    "MAIL FROM",
    "RCPT TO",
    "DATA",
    "QUIT",
    "RSET",
    "NOOP",
    "VRFY",
    "EXPN",
    "STARTTLS",
    "AUTH",
}


def parse_smtp_command(
    packet: Packet,
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:
    
    if not packet.haslayer(Raw):
        return event

    payload = bytes(packet[Raw].load)

    text = payload.decode("utf-8", errors="replace").strip()

    if not text:
        return event

    upper_text = text.upper()

    command = None
    argument = ""

    if upper_text.startswith("MAIL FROM:"):
        command = "MAIL FROM"
        argument = text[len("MAIL FROM:"):].strip()

    elif upper_text.startswith("RCPT TO:"):
        command = "RCPT TO"
        argument = text[len("RCPT TO:"):].strip()

    else:
        parts = text.split(" ", 1)

        candidate = parts[0].upper()

        if candidate not in SMTP_COMMANDS:
            return event

        command = candidate

        if len(parts) == 2:
            argument = parts[1].strip()

    event.application_protocol = "SMTP"
    event.application_data = {
        "type": "command",
        "command": command,
        "argument": argument,
    }

    return event

def parse_smtp_response(
    packet: Packet,
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:

    if not packet.haslayer(Raw):
        return event

    payload = bytes(packet[Raw].load)

    text = payload.decode(
        "utf-8",
        errors="replace",
    ).strip()

    if not text:
        return event

    first_line = text.split("\r\n", 1)[0]

    if len(first_line) < 3:
        return event

    status_code_text = first_line[:3]

    if not status_code_text.isdigit():
        return event

    status_code = int(status_code_text)

    message = first_line[3:].lstrip(" -")

    event.application_protocol = "SMTP"
    event.application_data = {
        "type": "response",
        "status_code": status_code,
        "message": message,
    }

    return event