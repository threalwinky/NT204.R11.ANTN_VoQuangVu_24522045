from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from main.detector import detect_application_protocol
from main.models import NormalizedIDSEvent
from main.parsers import (
    parse_ipv4,
    parse_smtp_response,
    parse_tcp,
)

packet = (
    IP(
        src="192.168.1.20",
        dst="192.168.1.10",
    )
    / TCP(
        sport=25,
        dport=50000,
        flags="PA",
    )
    / Raw(
        load=b"250 OK\r\n"
    )
)

event = NormalizedIDSEvent(
    packet_id=1,
    timestamp=1234567890.0,
)

parse_ipv4(packet, event)
parse_tcp(packet, event)
detect_application_protocol(packet, event)
parse_smtp_response(packet, event)

print(event.to_dict())

def test_smtp_response_parser():
    assert event.application_protocol == "SMTP"
    assert event.application_data["type"] == "response"
    assert event.application_data["status_code"] == 250
    assert event.application_data["message"] == "OK"
