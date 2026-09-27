from collections.abc import Iterator
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.utils import PcapReader

from ..core import parse_packet
from ..models import NormalizedIDSEvent
from .errors import CaptureError


def read_pcap(
    path: str | Path,
) -> Iterator[NormalizedIDSEvent]:
    
    source = Path(path)

    try:
        with PcapReader(str(source)) as reader:
            for packet_id, packet in enumerate(reader, start=1):
                yield parse_packet(
                    packet,
                    packet_id=packet_id,
                )
    except (OSError, Scapy_Exception) as error:
        raise CaptureError(f"cannot read pcap file {source}: {error}") from error
