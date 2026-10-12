from collections.abc import Callable, Iterator
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from ..core import parse_packet
from ..models import NormalizedIDSEvent
from ..tracker import FlowTracker
from .errors import CaptureError


def read_pcap(
    path: str | Path,
    on_flow_expired: Callable[[dict[str, object]], None] | None = None,
) -> Iterator[NormalizedIDSEvent]:
    
    source = Path(path)
    tracker = FlowTracker(on_flow_expired=on_flow_expired)

    try:
        with PcapReader(str(source)) as reader:
            for packet_id, packet in enumerate(reader, start=1):
                yield parse_packet(
                    packet,
                    packet_id=packet_id,
                    tracker=tracker,
                )
    except (OSError, Scapy_Exception) as error:
        raise CaptureError(f"cannot read pcap file {source}: {error}") from error
