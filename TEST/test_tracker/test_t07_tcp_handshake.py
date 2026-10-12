from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from modules.capture import read_pcap
from modules.core import parse_packet
from modules.tracker import FlowTracker


CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"


def make_packet(flags, forward=True, client_port=50000):
    if forward:
        src, dst = CLIENT, SERVER
        sport, dport = client_port, 443
    else:
        src, dst = SERVER, CLIENT
        sport, dport = 443, client_port

    return (
        IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags)
    )


def test_t07_three_way_handshake():
    tracker = FlowTracker()

    packets = [
        make_packet("S"),
        make_packet("SA", forward=False),
        make_packet("A"),
    ]

    events = [
        parse_packet(packet, index, tracker=tracker)
        for index, packet in enumerate(packets, start=1)
    ]

    assert [event.tcp_state for event in events] == [
        "NEW",
        "HANDSHAKE",
        "ESTABLISHED",
    ]

    assert [event.flow_direction for event in events] == [
        "forward",
        "backward",
        "forward",
    ]

    assert len({event.flow_id for event in events}) == 1
    assert events[0].flow_id == "flow-000001"
    assert all(event.status == "OK" for event in events)

    flow = next(iter(tracker.flows.values()))

    assert flow.syn_from_initiator is True
    assert flow.syn_ack_from_responder is True
    assert flow.tcp_state == "ESTABLISHED"


def test_t07_ack_before_syn_ack():
    tracker = FlowTracker()

    packets = [
        make_packet("S"),
        make_packet("A"),
        make_packet("A"),
    ]

    events = [
        parse_packet(packet, index, tracker=tracker)
        for index, packet in enumerate(packets, start=1)
    ]

    assert [event.tcp_state for event in events] == [
        "NEW",
        "NEW",
        "NEW",
    ]


def test_t07_syn_retransmission():
    tracker = FlowTracker()

    packets = [
        make_packet("S"),
        make_packet("S"),
        make_packet("SA", forward=False),
        make_packet("SA", forward=False),
        make_packet("A"),
    ]

    events = [
        parse_packet(packet, index, tracker=tracker)
        for index, packet in enumerate(packets, start=1)
    ]

    assert [event.tcp_state for event in events] == [
        "NEW",
        "NEW",
        "HANDSHAKE",
        "HANDSHAKE",
        "ESTABLISHED",
    ]

    assert len(tracker.flows) == 1
    assert len({event.flow_id for event in events}) == 1


def test_t07_syn_ack_wrong_direction():
    tracker = FlowTracker()

    events = [
        parse_packet(make_packet("S"), 1, tracker=tracker),
        parse_packet(make_packet("SA"), 2, tracker=tracker),
        parse_packet(
            make_packet("SA", forward=False),
            3,
            tracker=tracker,
        ),
        parse_packet(make_packet("A"), 4, tracker=tracker),
    ]

    assert [event.tcp_state for event in events] == [
        "NEW",
        "NEW",
        "HANDSHAKE",
        "ESTABLISHED",
    ]


def test_t07_reset_during_handshake():
    tracker = FlowTracker()

    events = [
        parse_packet(make_packet("S"), 1, tracker=tracker),
        parse_packet(
            make_packet("SA", forward=False),
            2,
            tracker=tracker,
        ),
        parse_packet(make_packet("R"), 3, tracker=tracker),
        parse_packet(make_packet("A"), 4, tracker=tracker),
    ]

    assert [event.tcp_state for event in events] == [
        "NEW",
        "HANDSHAKE",
        "RESET",
        "RESET",
    ]


def test_t07_handshake_from_pcap():
    packets = [
        make_packet("S"),
        make_packet("SA", forward=False),
        make_packet("A"),
    ]

    with TemporaryDirectory() as directory:
        path = Path(directory) / "t07_handshake.pcap"
        wrpcap(str(path), packets)
        events = list(read_pcap(path))

    assert len(events) == 3
    assert [event.packet_id for event in events] == [1, 2, 3]
    assert [event.tcp_state for event in events] == [
        "NEW",
        "HANDSHAKE",
        "ESTABLISHED",
    ]
    assert len({event.flow_id for event in events}) == 1
    assert events[1].flow_direction == "backward"
    assert events[2].to_dict()["tcp_state"] == "ESTABLISHED"


def test_t07_optional_tracker():
    event = parse_packet(make_packet("S"), packet_id=1)

    assert event.status == "OK"
    assert event.flow_id is None
    assert event.flow_direction is None
    assert event.tcp_state is None
