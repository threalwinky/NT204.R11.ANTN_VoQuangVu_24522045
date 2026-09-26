from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from modules.detector import detect_application_protocol
from modules.models import NormalizedIDSEvent
from modules.parsers import (
    parse_http_request,
    parse_ipv4,
    parse_tcp,
)

packet = (
    IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=50000, dport=8080)
    / Raw(
        load=(
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0\r\n"
            b"\r\n"
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
parse_http_request(packet, event)

print(event.to_dict())

def test_get_http_request_parser():
    assert event.application_protocol == "HTTP"
    assert event.application_data["type"] == "request"
    assert event.application_data["method"] == "GET"
    assert event.application_data["uri"] == "/index.html"
    assert event.application_data["version"] == "HTTP/1.1"
    assert event.application_data["headers"]["Host"] == "example.com"
    assert event.application_data["body"] == ""
