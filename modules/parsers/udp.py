from scapy.layers.inet import UDP
from scapy.packet import Packet

from ..models import NormalizedIDSEvent


def parse_udp(
    packet: Packet,
    event: NormalizedIDSEvent,
) -> NormalizedIDSEvent:

    if not packet.haslayer(UDP):
        return event

    udp = packet[UDP]
    payload = bytes(udp.payload)

    event.transport_protocol = "UDP"
    event.src_port = udp.sport
    event.dst_port = udp.dport
    event.payload_length = len(payload)
    event.payload = payload

    return event
