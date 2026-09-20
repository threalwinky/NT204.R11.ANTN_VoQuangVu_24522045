from scapy.packet import Packet, Raw

from main.models import NormalizedIDSEvent

HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
}

def parse_http_request(
    packet: Packet,
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:

    if not packet.haslayer(Raw):
        return event

    payload = bytes(packet[Raw].load)

    header_bytes, separator, body_bytes = payload.partition(b"\r\n\r\n")

    try:
        header_text = header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError:
        return event

    lines = header_text.split("\r\n")

    if not lines:
        return event

    request_line = lines[0].split(" ", 2)

    if len(request_line) != 3:
        return event

    method, uri, version = request_line

    if method not in HTTP_METHODS:
        return event

    if not version.startswith("HTTP/1."):
        return event

    headers: dict[str, str] = {}

    for line in lines[1:]:
        if ":" not in line:
            continue

        name, value = line.split(":", 1)

        headers[name.strip()] = value.strip()

    body = ""

    if separator:
        body = body_bytes.decode("utf-8", errors="replace")

    event.application_protocol = "HTTP"
    event.application_data = {
        "type": "request",
        "method": method,
        "uri": uri, 
        "version": version,
        "headers": headers,
        "body": body,
    }

    return event