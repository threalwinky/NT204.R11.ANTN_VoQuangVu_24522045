from collections.abc import Callable
from itertools import count

from scapy.all import sniff
from scapy.error import Scapy_Exception
from scapy.interfaces import resolve_iface

from ..core import parse_packet
from ..models import NormalizedIDSEvent
from .errors import CaptureError


def capture_live(
    interface: str,
    on_event: Callable[[NormalizedIDSEvent], None],
) -> None:
    
    try:
        iface = resolve_iface(interface)
    except ValueError as error:
        raise CaptureError(f"interface {interface!r} not found") from error

    packet_ids = count(start=1)

    def handle_packet(packet) -> None:
        packet_id = next(packet_ids)

        event = parse_packet(
            packet,
            packet_id=packet_id,
        )

        on_event(event)

    try:
        sniff(
            iface=iface,
            prn=handle_packet,
            store=False,
        )
    except (OSError, Scapy_Exception) as error:
        raise CaptureError(f"cannot capture on {interface!r}: {error}") from error
