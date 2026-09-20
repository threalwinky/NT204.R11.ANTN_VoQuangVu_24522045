from collections.abc import Iterator
from pathlib import Path

from scapy.utils import PcapReader

from main.core import parse_packet
from main.models import NormalizedIDSEvent

def read_pcap(
    path: str | Path,
) -> Iterator[NormalizedIDSEvent]:
    
    with PcapReader(str(path)) as reader:
        for packet_id, packet in enumerate(reader, start=1):
            yield parse_packet(
                packet,
                packet_id=packet_id,
            )