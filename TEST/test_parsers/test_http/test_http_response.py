from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from modules.detector import detect_application_protocol
from modules.models import NormalizedIDSEvent
from modules.parsers import (
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

def test_http_response_parser():
    assert event.application_protocol == "HTTP"
    assert event.application_data["type"] == "response"
    assert event.application_data["version"] == "HTTP/1.1"
    assert event.application_data["status_code"] == 200
    assert event.application_data["reason"] == "OK"
    assert event.application_data["headers"]["Content-Type"] == "text/plain"
    assert event.application_data["headers"]["Content-Length"] == "5"
    assert event.application_data["body"] == "Hello"
