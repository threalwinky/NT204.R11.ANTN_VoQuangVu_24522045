from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from main.detector import detect_application_protocol
from main.models import NormalizedIDSEvent
from main.parsers import (
    parse_dns_query,
    parse_ipv4,
    parse_udp,
)

packet = (
    IP(
        src="192.168.1.10",
        dst="8.8.8.8",
    )
    / UDP(
        sport=53000,
        dport=53,
    )
    / DNS(
        rd=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A",
        ),
    )
)

event = NormalizedIDSEvent(
    packet_id=1,
    timestamp=1234567890.0,
)

parse_ipv4(packet, event)
parse_udp(packet, event)
detect_application_protocol(packet, event)
parse_dns_query(packet, event)

print(event.to_dict())

def test_dns_query_parser():
    assert event.application_protocol == "DNS"
    assert event.application_data["type"] == "query"
    assert event.application_data["domain"] == "example.com"
    assert event.application_data["query_type"] == "A"
    assert event.application_data["query_type_code"] == 1
