from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from modules.capture import read_pcap
from modules.core import parse_packet
from modules.tracker import FlowTracker


CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"


def make_packet(flags, reverse=False, client_port=50000):
    if reverse:
        src, dst = SERVER, CLIENT
        sport, dport = 443, client_port
    else:
        src, dst = CLIENT, SERVER
        sport, dport = client_port, 443

    return IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags=flags,
    )


def handshake_packets(client_port=50000):
    return [
        make_packet("S", client_port=client_port),
        make_packet("SA", reverse=True, client_port=client_port),
        make_packet("A", client_port=client_port),
    ]


def observe(tracker, packets):
    return [
        parse_packet(packet, index, tracker=tracker)
        for index, packet in enumerate(packets, start=1)
    ]


def test_t09_graceful_tcp_close():
    tracker = FlowTracker()

    packets = handshake_packets() + [
        make_packet("FA"),
        make_packet("A", reverse=True),
        make_packet("FA", reverse=True),
        make_packet("A"),
    ]

    events = observe(tracker, packets)

    assert [event.tcp_state for event in events] == [
        "NEW",
        "HANDSHAKE",
        "ESTABLISHED",
        "CLOSING",
        "CLOSING",
        "CLOSING",
        "CLOSED",
    ]

    assert len({event.flow_id for event in events}) == 1

    assert [event.flow_direction for event in events[3:]] == [
        "forward",
        "backward",
        "backward",
        "forward",
    ]

    flow = next(iter(tracker.flows.values()))

    assert flow.fin_from_initiator is True
    assert flow.fin_from_responder is True
    assert flow.tcp_state == "CLOSED"
    assert events[-1].to_dict()["tcp_state"] == "CLOSED"


def test_t09_server_initiated_close():
    tracker = FlowTracker()

    packets = handshake_packets() + [
        make_packet("FA", reverse=True),
        make_packet("A"),
        make_packet("FA"),
        make_packet("A", reverse=True),
    ]

    events = observe(tracker, packets)

    assert [event.tcp_state for event in events[3:]] == [
        "CLOSING",
        "CLOSING",
        "CLOSING",
        "CLOSED",
    ]

    assert events[3].flow_direction == "backward"
    assert events[5].flow_direction == "forward"
    assert len({event.flow_id for event in events}) == 1

    flow = next(iter(tracker.flows.values()))

    assert flow.fin_from_initiator is True
    assert flow.fin_from_responder is True
    assert flow.tcp_state == "CLOSED"


def test_t09_one_sided_fin_remains_closing():
    tracker = FlowTracker()

    packets = handshake_packets() + [
        make_packet("FA"),
        make_packet("A", reverse=True),
        make_packet("A"),
        make_packet("A", reverse=True),
    ]

    events = observe(tracker, packets)

    assert [event.tcp_state for event in events[3:]] == [
        "CLOSING",
        "CLOSING",
        "CLOSING",
        "CLOSING",
    ]

    flow = next(iter(tracker.flows.values()))

    assert flow.fin_from_initiator is True
    assert flow.fin_from_responder is False
    assert flow.tcp_state == "CLOSING"


def test_t09_fin_retransmission():
    tracker = FlowTracker()

    packets = handshake_packets() + [
        make_packet("FA"),
        make_packet("FA"),
        make_packet("A", reverse=True),
        make_packet("FA", reverse=True),
        make_packet("A"),
    ]

    events = observe(tracker, packets)

    assert [event.tcp_state for event in events[3:]] == [
        "CLOSING",
        "CLOSING",
        "CLOSING",
        "CLOSING",
        "CLOSED",
    ]

    assert len(tracker.flows) == 1
    assert len({event.flow_id for event in events}) == 1


def test_t09_reset_established_connection():
    tracker = FlowTracker()

    packets = handshake_packets() + [
        make_packet("RA", reverse=True),
        make_packet("A"),
        make_packet("FA"),
    ]

    events = observe(tracker, packets)

    assert [event.tcp_state for event in events] == [
        "NEW",
        "HANDSHAKE",
        "ESTABLISHED",
        "RESET",
        "RESET",
        "RESET",
    ]

    assert events[3].flow_direction == "backward"
    assert len({event.flow_id for event in events}) == 1

    flow = next(iter(tracker.flows.values()))

    assert flow.tcp_state == "RESET"


def test_t09_reset_during_closing():
    tracker = FlowTracker()

    packets = handshake_packets() + [
        make_packet("FA"),
        make_packet("RA", reverse=True),
        make_packet("A"),
    ]

    events = observe(tracker, packets)

    assert [event.tcp_state for event in events[3:]] == [
        "CLOSING",
        "RESET",
        "RESET",
    ]

    flow = next(iter(tracker.flows.values()))

    assert flow.fin_from_initiator is True
    assert flow.tcp_state == "RESET"


def test_t09_close_one_flow_does_not_close_another():
    tracker = FlowTracker()

    packets = (
        handshake_packets(client_port=50000)
        + handshake_packets(client_port=50001)
        + [
            make_packet("FA", client_port=50000),
            make_packet("A", reverse=True, client_port=50000),
            make_packet("FA", reverse=True, client_port=50000),
            make_packet("A", client_port=50000),
            make_packet("A", client_port=50001),
        ]
    )

    events = observe(tracker, packets)

    first_flow_id = events[0].flow_id
    second_flow_id = events[3].flow_id

    assert first_flow_id != second_flow_id
    assert events[9].flow_id == first_flow_id
    assert events[9].tcp_state == "CLOSED"
    assert events[10].flow_id == second_flow_id
    assert events[10].tcp_state == "ESTABLISHED"

    assert len(tracker.flows) == 2
    assert sorted(
        flow.tcp_state for flow in tracker.flows.values()
    ) == ["CLOSED", "ESTABLISHED"]


def test_t09_close_from_pcap():
    packets = handshake_packets() + [
        make_packet("FA"),
        make_packet("A", reverse=True),
        make_packet("FA", reverse=True),
        make_packet("A"),
    ]

    with TemporaryDirectory() as directory:
        path = Path(directory) / "t09_tcp_close.pcap"
        wrpcap(str(path), packets)
        events = list(read_pcap(path))

    assert len(events) == 7
    assert [event.packet_id for event in events] == list(range(1, 8))

    assert [event.tcp_state for event in events] == [
        "NEW",
        "HANDSHAKE",
        "ESTABLISHED",
        "CLOSING",
        "CLOSING",
        "CLOSING",
        "CLOSED",
    ]

    assert len({event.flow_id for event in events}) == 1
    assert events[-1].flow_direction == "forward"
    assert events[-1].processing_action == "emit"
