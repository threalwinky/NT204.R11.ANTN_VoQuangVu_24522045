from scapy.layers.inet import IP
from scapy.packet import Packet

from ..models import NormalizedIDSEvent

def parse_ipv4(
    packet: Packet,
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:
    
    if not packet.haslayer(IP):
        return event

    ip = packet[IP]

    event.network_protocol = "IPv4"
    event.src_ip = ip.src
    event.dst_ip = ip.dst

    return event