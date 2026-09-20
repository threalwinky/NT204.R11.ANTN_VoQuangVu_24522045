from collections.abc import Callable
from itertools import count

from scapy.all import sniff

from main.core import parse_packet
from main.models import NormalizedIDSEvent


def capture_live(
    interface: str,
    on_event: Callable[[NormalizedIDSEvent], None],
) -> None:
    
    packet_ids = count(start=1)

    def handle_packet(packet) -> None:
        packet_id = next(packet_ids)

        event = parse_packet(
            packet,
            packet_id=packet_id,
        )

        on_event(event)

    sniff(
        iface=interface,
        prn=handle_packet,
        store=False,
    )