from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from main.detector import detect_application_protocol
from main.models import NormalizedIDSEvent
from main.parsers import (
    parse_dns_response,
    parse_ipv4,
    parse_udp,
)

packet = (
    IP(
        src="8.8.8.8",
        dst="192.168.1.10",
    )
    / UDP(
        sport=53,
        dport=53000,
    )
    / DNS(
        id=1234,
        qr=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A",
        ),
        an=DNSRR(
            rrname="example.com",
            type="A",
            ttl=300,
            rdata="93.184.216.34",
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
parse_dns_response(packet, event)

answer = event.application_data["answer"]

print(event.to_dict())
print(answer)