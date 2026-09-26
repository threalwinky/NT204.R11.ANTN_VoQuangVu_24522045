from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

from modules.capture import read_pcap

pcap_path = Path(__file__).parent / "test.pcap"

packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20",
    )
    / TCP(
        sport=50000,
        dport=80,
        flags="PA",
    )
    / Raw(
        load=(
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"\r\n"
        )
    )
)

wrpcap(
    str(pcap_path),
    [packet],
)

events = list(read_pcap(pcap_path))

event = events[0]

def test_pcap_reader():
    assert len(events) == 1
    assert event.packet_id == 1
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "192.168.1.20"
    assert event.transport_protocol == "TCP"
    assert event.application_protocol == "HTTP"
    assert event.application_data["method"] == "GET"
    assert event.application_data["uri"] == "/index.html"