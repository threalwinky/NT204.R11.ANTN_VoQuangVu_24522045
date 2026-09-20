from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Packet

from main.models import NormalizedIDSEvent

DNS_QUERY_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
}


def parse_dns_query(
    packet: Packet,
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:
    
    if not packet.haslayer(DNS):
        return event

    dns = packet[DNS]

    # qr = 0 means DNS query.
    if dns.qr != 0:
        return event

    if not packet.haslayer(DNSQR):
        return event

    query = packet[DNSQR]

    qname = query.qname

    if isinstance(qname, bytes):
        domain = qname.decode("utf-8", errors="replace")
    else:
        domain = str(qname)

    domain = domain.rstrip(".")

    query_type_code = int(query.qtype)

    query_type = DNS_QUERY_TYPES.get(
        query_type_code,
        f"TYPE{query_type_code}",
    )

    event.application_protocol = "DNS"
    event.application_data = {
        "type": "query",
        "domain": domain,
        "query_type": query_type,
        "query_type_code": query_type_code,
    }

    return event

def _decode_dns_value(value) -> str:
    """Convert DNS byte values into a JSON-friendly string."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".")

    return str(value)

def parse_dns_response(
    packet: Packet,
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:
    
    if not packet.haslayer(DNS):
        return event

    dns = packet[DNS]

    # qr = 1 means DNS response.
    if dns.qr != 1:
        return event

    if dns.ancount == 0 or dns.an is None:
        return event

    try:
        answer = dns.an[0]
    except (TypeError, IndexError):
        answer = dns.an

    if not isinstance(answer, DNSRR):
        return event

    answer_type_code = int(answer.type)

    answer_type = DNS_QUERY_TYPES.get(
        answer_type_code,
        f"TYPE{answer_type_code}",
    )

    event.application_protocol = "DNS"
    event.application_data = {
        "type": "response",
        "answer": {
            "name": _decode_dns_value(answer.rrname),
            "record_type": answer_type,
            "record_type_code": answer_type_code,
            "ttl": int(answer.ttl),
            "data": _decode_dns_value(answer.rdata),
        },
    }

    return event