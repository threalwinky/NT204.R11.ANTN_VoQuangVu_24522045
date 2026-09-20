from scapy.layers.dns import DNS, DNSQR
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