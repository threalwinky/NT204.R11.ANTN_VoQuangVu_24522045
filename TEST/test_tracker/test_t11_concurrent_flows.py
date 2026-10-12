from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap

from modules.capture import read_pcap
from modules.core import parse_packet
from modules.tracker import FlowTracker


CLIENT_A = "192.168.1.10"
CLIENT_B = "192.168.1.11"
SERVER = "192.168.1.20"
UDP_SERVER = "8.8.8.8"


def make_tcp(client, flags, reverse=False, port=50000):
    if reverse:
        src, dst = SERVER, client
        sport, dport = 443, port
    else:
        src, dst = client, SERVER
        sport, dport = port, 443

    return IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=dport,
        flags=flags,
    )


def make_udp(reverse=False, port=53000):
    if reverse:
        return (
            IP(src=UDP_SERVER, dst=CLIENT_A)
            / UDP(sport=9999, dport=port)
        )

    return (
        IP(src=CLIENT_A, dst=UDP_SERVER)
        / UDP(sport=port, dport=9999)
    )


def observe(packets):
    tracker = FlowTracker()
    events = [
        parse_packet(packet, index, tracker=tracker)
        for index, packet in enumerate(packets, start=1)
    ]
    return tracker, events


def get_flow(tracker, flow_id):
    return next(
        flow for flow in tracker.flows.values()
        if flow.flow_id == flow_id
    )


def test_t11_interleaved_tcp_handshakes():
    tracker, events = observe([
        make_tcp(CLIENT_A, "S"),
        make_tcp(CLIENT_B, "S", port=51000),
        make_tcp(CLIENT_B, "SA", reverse=True, port=51000),
        make_tcp(CLIENT_A, "SA", reverse=True),
        make_tcp(CLIENT_A, "A"),
        make_tcp(CLIENT_B, "A", port=51000),
    ])

    assert [event.tcp_state for event in events] == [
        "NEW",
        "NEW",
        "HANDSHAKE",
        "HANDSHAKE",
        "ESTABLISHED",
        "ESTABLISHED",
    ]

    assert events[0].flow_id == events[3].flow_id
    assert events[0].flow_id == events[4].flow_id
    assert events[1].flow_id == events[2].flow_id
    assert events[1].flow_id == events[5].flow_id
    assert events[0].flow_id != events[1].flow_id

    assert [event.flow_direction for event in events] == [
        "forward",
        "forward",
        "backward",
        "backward",
        "forward",
        "forward",
    ]

    assert len(tracker.flows) == 2
    assert all(
        flow.tcp_state == "ESTABLISHED"
        for flow in tracker.flows.values()
    )


def test_t11_interleaved_tcp_and_udp():
    tracker, events = observe([
        make_tcp(CLIENT_A, "S"),
        make_udp(),
        make_tcp(CLIENT_A, "SA", reverse=True),
        make_udp(reverse=True),
        make_tcp(CLIENT_A, "A"),
    ])

    assert events[0].flow_id == events[2].flow_id
    assert events[0].flow_id == events[4].flow_id
    assert events[1].flow_id == events[3].flow_id
    assert events[0].flow_id != events[1].flow_id

    assert [events[i].tcp_state for i in (0, 2, 4)] == [
        "NEW",
        "HANDSHAKE",
        "ESTABLISHED",
    ]

    assert events[1].tcp_state is None
    assert events[3].tcp_state is None
    assert events[3].flow_direction == "backward"

    assert len(tracker.flows) == 2
    assert {
        flow.protocol for flow in tracker.flows.values()
    } == {"TCP", "UDP"}


def test_t11_close_one_flow_keeps_other_established():
    tracker, events = observe([
        make_tcp(CLIENT_A, "S"),
        make_tcp(CLIENT_B, "S", port=51000),
        make_tcp(CLIENT_A, "SA", reverse=True),
        make_tcp(CLIENT_B, "SA", reverse=True, port=51000),
        make_tcp(CLIENT_A, "A"),
        make_tcp(CLIENT_B, "A", port=51000),
        make_tcp(CLIENT_A, "FA"),
        make_tcp(CLIENT_B, "PA", port=51000),
        make_tcp(CLIENT_A, "A", reverse=True),
        make_tcp(CLIENT_A, "FA", reverse=True),
        make_tcp(CLIENT_A, "A"),
        make_tcp(CLIENT_B, "A", reverse=True, port=51000),
    ])

    first_id = events[0].flow_id
    second_id = events[1].flow_id

    assert events[10].flow_id == first_id
    assert events[10].tcp_state == "CLOSED"
    assert events[11].flow_id == second_id
    assert events[11].tcp_state == "ESTABLISHED"

    assert get_flow(tracker, first_id).tcp_state == "CLOSED"
    assert get_flow(tracker, second_id).tcp_state == "ESTABLISHED"
    assert len(tracker.flows) == 2


def test_t11_reset_one_flow_does_not_reset_other():
    tracker, events = observe([
        make_tcp(CLIENT_A, "S"),
        make_tcp(CLIENT_B, "S", port=51000),
        make_tcp(CLIENT_A, "SA", reverse=True),
        make_tcp(CLIENT_B, "SA", reverse=True, port=51000),
        make_tcp(CLIENT_A, "A"),
        make_tcp(CLIENT_B, "A", port=51000),
        make_tcp(CLIENT_A, "RA", reverse=True),
        make_tcp(CLIENT_B, "PA", port=51000),
        make_tcp(CLIENT_A, "A"),
    ])

    first_id = events[0].flow_id
    second_id = events[1].flow_id

    assert events[6].tcp_state == "RESET"
    assert events[7].tcp_state == "ESTABLISHED"
    assert events[8].tcp_state == "RESET"

    assert get_flow(tracker, first_id).tcp_state == "RESET"
    assert get_flow(tracker, second_id).tcp_state == "ESTABLISHED"


def test_t11_thirty_interleaved_connections():
    ports = list(range(50000, 50030))

    packets = (
        [make_tcp(CLIENT_A, "S", port=port) for port in ports]
        + [
            make_tcp(CLIENT_A, "SA", reverse=True, port=port)
            for port in ports
        ]
        + [make_tcp(CLIENT_A, "A", port=port) for port in ports]
    )

    tracker, events = observe(packets)

    assert len(events) == 90
    assert len(tracker.flows) == 30
    assert len({event.flow_id for event in events}) == 30

    for index in range(30):
        syn = events[index]
        syn_ack = events[index + 30]
        ack = events[index + 60]

        assert syn.flow_id == syn_ack.flow_id == ack.flow_id
        assert syn.tcp_state == "NEW"
        assert syn_ack.tcp_state == "HANDSHAKE"
        assert ack.tcp_state == "ESTABLISHED"

    assert all(
        flow.tcp_state == "ESTABLISHED"
        for flow in tracker.flows.values()
    )


def test_t11_reverse_first_packet_isolated():
    tracker, events = observe([
        make_tcp(CLIENT_A, "A", reverse=True),
        make_tcp(CLIENT_B, "S", port=51000),
        make_tcp(CLIENT_A, "A"),
        make_tcp(CLIENT_B, "SA", reverse=True, port=51000),
        make_tcp(CLIENT_B, "A", port=51000),
    ])

    assert events[0].flow_id == events[2].flow_id
    assert events[1].flow_id == events[3].flow_id
    assert events[1].flow_id == events[4].flow_id
    assert events[0].flow_id != events[1].flow_id

    assert events[0].flow_direction == "forward"
    assert events[2].flow_direction == "backward"

    assert events[2].tcp_state == "NEW"
    assert events[4].tcp_state == "ESTABLISHED"
    assert len(tracker.flows) == 2


def test_t11_concurrent_flows_from_pcap():
    packets = [
        make_tcp(CLIENT_A, "S"),
        make_tcp(CLIENT_B, "S", port=51000),
        make_udp(),
        make_tcp(CLIENT_B, "SA", reverse=True, port=51000),
        make_udp(reverse=True),
        make_tcp(CLIENT_A, "SA", reverse=True),
        make_tcp(CLIENT_A, "A"),
        make_tcp(CLIENT_B, "A", port=51000),
    ]

    with TemporaryDirectory() as directory:
        path = Path(directory) / "t11_concurrent.pcap"
        wrpcap(str(path), packets)
        events = list(read_pcap(path))

    assert len(events) == 8
    assert [event.packet_id for event in events] == list(range(1, 9))

    assert events[0].flow_id == events[5].flow_id
    assert events[0].flow_id == events[6].flow_id

    assert events[1].flow_id == events[3].flow_id
    assert events[1].flow_id == events[7].flow_id

    assert events[2].flow_id == events[4].flow_id
    assert len({event.flow_id for event in events}) == 3

    assert events[6].tcp_state == "ESTABLISHED"
    assert events[7].tcp_state == "ESTABLISHED"
    assert events[4].tcp_state is None

    assert events[3].flow_direction == "backward"
    assert events[4].flow_direction == "backward"
    assert events[5].flow_direction == "backward"


def test_t11_separate_capture_sessions():
    packets = [
        make_tcp(CLIENT_A, "S"),
        make_tcp(CLIENT_B, "S", port=51000),
        make_tcp(CLIENT_A, "SA", reverse=True),
        make_tcp(CLIENT_B, "SA", reverse=True, port=51000),
    ]

    with TemporaryDirectory() as directory:
        path = Path(directory) / "t11_sessions.pcap"
        wrpcap(str(path), packets)

        first = list(read_pcap(path))
        second = list(read_pcap(path))

    for events in (first, second):
        assert events[0].flow_id == "flow-000001"
        assert events[1].flow_id == "flow-000002"
        assert events[0].flow_id == events[2].flow_id
        assert events[1].flow_id == events[3].flow_id

    assert [event.tcp_state for event in first] == [
        "NEW",
        "NEW",
        "HANDSHAKE",
        "HANDSHAKE",
    ]

    assert [event.tcp_state for event in second] == [
        "NEW",
        "NEW",
        "HANDSHAKE",
        "HANDSHAKE",
    ]
