from scapy.layers.inet import TCP
from scapy.packet import Packet

from ..models import NormalizedIDSEvent

def parse_tcp(
    packet: Packet,
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:
    
    if not packet.haslayer(TCP):
        return event

    tcp = packet[TCP]

    event.transport_protocol = "TCP"
    event.src_port = tcp.sport
    event.dst_port = tcp.dport
    event.tcp_flags = str(tcp.flags)
    event.payload_length = len(bytes(tcp.payload))

    return event