from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap

from modules.capture import read_pcap
from modules.core import parse_packet
from modules.models import NormalizedIDSEvent
from modules.tracker import FlowTracker


CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"


def make_packet(
    src=CLIENT,
    dst=SERVER,
    sport=50000,
    dport=443,
    protocol="TCP",
):
    if protocol == "TCP":
        layer = TCP(sport=sport, dport=dport, flags="A")
    else:
        layer = UDP(sport=sport, dport=dport)

    return IP(src=src, dst=dst) / layer


def observe(tracker, packets):
    return [
        parse_packet(packet, index, tracker=tracker)
        for index, packet in enumerate(packets, start=1)
    ]


def test_t08_bidirectional_tcp():
    tracker = FlowTracker()

    events = observe(tracker, [
        make_packet(),
        make_packet(src=SERVER, dst=CLIENT, sport=443, dport=50000),
        make_packet(),
    ])

    assert [event.flow_direction for event in events] == [
        "forward",
        "backward",
        "forward",
    ]

    assert len({event.flow_id for event in events}) == 1
    assert events[0].flow_id == "flow-000001"
    assert len(tracker.flows) == 1

    flow = next(iter(tracker.flows.values()))

    assert flow.protocol == "TCP"
    assert flow.initiator == (CLIENT, 50000)
    assert flow.responder == (SERVER, 443)


def test_t08_first_packet_defines_direction():
    tracker = FlowTracker()

    events = observe(tracker, [
        make_packet(src=SERVER, dst=CLIENT, sport=443, dport=50000),
        make_packet(),
    ])

    assert events[0].flow_direction == "forward"
    assert events[1].flow_direction == "backward"
    assert events[0].flow_id == events[1].flow_id

    flow = next(iter(tracker.flows.values()))

    assert flow.initiator == (SERVER, 443)
    assert flow.responder == (CLIENT, 50000)


def test_t08_different_source_ports():
    tracker = FlowTracker()

    events = observe(tracker, [
        make_packet(sport=50000),
        make_packet(sport=50001),
        make_packet(
            src=SERVER, dst=CLIENT,
            sport=443, dport=50000,
        ),
        make_packet(
            src=SERVER, dst=CLIENT,
            sport=443, dport=50001,
        ),
    ])

    assert events[0].flow_id == events[2].flow_id
    assert events[1].flow_id == events[3].flow_id
    assert events[0].flow_id != events[1].flow_id
    assert len(tracker.flows) == 2


def test_t08_tcp_udp_separate_flows():
    tracker = FlowTracker()

    events = observe(tracker, [
        make_packet(protocol="TCP"),
        make_packet(protocol="UDP"),
        make_packet(
            src=SERVER, dst=CLIENT,
            sport=443, dport=50000,
            protocol="UDP",
        ),
    ])

    assert events[0].flow_id != events[1].flow_id
    assert events[1].flow_id == events[2].flow_id
    assert events[1].flow_direction == "forward"
    assert events[2].flow_direction == "backward"
    assert events[1].tcp_state is None
    assert events[2].tcp_state is None
    assert len(tracker.flows) == 2


def test_t08_different_ip_addresses():
    tracker = FlowTracker()
    other_client = "192.168.1.11"

    events = observe(tracker, [
        make_packet(src=CLIENT),
        make_packet(src=other_client),
        make_packet(
            src=SERVER, dst=other_client,
            sport=443, dport=50000,
        ),
    ])

    assert events[0].flow_id != events[1].flow_id
    assert events[1].flow_id == events[2].flow_id
    assert len(tracker.flows) == 2


def test_t08_first_seen_last_seen():
    tracker = FlowTracker()

    packets = [
        make_packet(),
        make_packet(
            src=SERVER, dst=CLIENT,
            sport=443, dport=50000,
        ),
        make_packet(),
    ]

    for packet, timestamp in zip(
        packets, (1000.0, 1012.0, 1008.0)
    ):
        packet.time = timestamp

    events = observe(tracker, packets)
    flow = next(iter(tracker.flows.values()))

    assert len({event.flow_id for event in events}) == 1
    assert flow.first_seen == 1000.0
    assert flow.last_seen == 1012.0


def test_t08_bidirectional_pcap():
    packets = [
        make_packet(sport=50000),
        make_packet(
            src=SERVER, dst=CLIENT,
            sport=443, dport=50000,
        ),
        make_packet(sport=50001),
        make_packet(
            src=SERVER, dst=CLIENT,
            sport=443, dport=50001,
        ),
    ]

    with TemporaryDirectory() as directory:
        path = Path(directory) / "t08_bidirectional.pcap"
        wrpcap(str(path), packets)
        events = list(read_pcap(path))

    assert len(events) == 4
    assert events[0].flow_id == events[1].flow_id
    assert events[2].flow_id == events[3].flow_id
    assert events[0].flow_id != events[2].flow_id

    assert [event.flow_direction for event in events] == [
        "forward",
        "backward",
        "forward",
        "backward",
    ]

    assert all(event.flow_id is not None for event in events)
    assert events[1].to_dict()["flow_direction"] == "backward"


def test_t08_invalid_event_not_tracked():
    tracker = FlowTracker()

    event = NormalizedIDSEvent(
        packet_id=1,
        timestamp=1000.0,
        src_ip=CLIENT,
        dst_ip=SERVER,
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=50000,
        dst_port=443,
        preprocess_status="invalid",
    )

    tracker.track(event)

    assert event.flow_id is None
    assert event.flow_direction is None
    assert len(tracker.flows) == 0
