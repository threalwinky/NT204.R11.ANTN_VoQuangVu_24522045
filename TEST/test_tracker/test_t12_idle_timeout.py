from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap

from modules.capture import read_pcap
from modules.core import parse_packet
from modules.models import NormalizedIDSEvent
from modules.tracker import FlowTracker


CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"


def make_packet(
    protocol="TCP",
    timestamp=1000.0,
    port=50000,
    reverse=False,
    flags="S",
):
    if reverse:
        src, dst = SERVER, CLIENT
    else:
        src, dst = CLIENT, SERVER

    if protocol == "TCP":
        if reverse:
            transport = TCP(sport=443, dport=port, flags=flags)
        else:
            transport = TCP(sport=port, dport=443, flags=flags)
    else:
        if reverse:
            transport = UDP(sport=9999, dport=port)
        else:
            transport = UDP(sport=port, dport=9999)

    packet = IP(src=src, dst=dst) / transport
    packet.time = float(timestamp)

    return packet


def send(tracker, packet_id, **kwargs):
    packet = make_packet(**kwargs)
    return parse_packet(packet, packet_id, tracker=tracker)


def test_t12_default_and_custom_timeouts():
    default = FlowTracker()

    assert default.tcp_timeout == 300.0
    assert default.udp_timeout == 60.0

    custom = FlowTracker(tcp_timeout=10, udp_timeout=5)

    assert custom.tcp_timeout == 10.0
    assert custom.udp_timeout == 5.0


def test_t12_tcp_exact_timeout_boundary():
    tracker = FlowTracker(tcp_timeout=10)

    first = send(tracker, 1, timestamp=1000)
    before = send(tracker, 2, timestamp=1009)
    expired = send(tracker, 3, timestamp=1019)

    assert first.flow_id == before.flow_id
    assert expired.flow_id != first.flow_id
    assert expired.flow_id == "flow-000002"
    assert expired.tcp_state == "NEW"
    assert len(tracker.flows) == 1

    flow = next(iter(tracker.flows.values()))

    assert flow.first_seen == 1019.0
    assert flow.last_seen == 1019.0


def test_t12_udp_reverse_packet_refreshes_timeout():
    tracker = FlowTracker(udp_timeout=5)

    first = send(
        tracker, 1,
        protocol="UDP", timestamp=1000,
    )

    response = send(
        tracker, 2,
        protocol="UDP", timestamp=1004,
        reverse=True,
    )

    refreshed = send(
        tracker, 3,
        protocol="UDP", timestamp=1008,
    )

    expired = send(
        tracker, 4,
        protocol="UDP", timestamp=1013,
    )

    assert first.flow_id == response.flow_id
    assert first.flow_id == refreshed.flow_id
    assert expired.flow_id != first.flow_id

    assert response.flow_direction == "backward"
    assert expired.flow_direction == "forward"
    assert expired.tcp_state is None
    assert len(tracker.flows) == 1


def test_t12_tcp_udp_independent_timeouts():
    tracker = FlowTracker(
        tcp_timeout=10,
        udp_timeout=5,
    )

    tcp_first = send(
        tracker, 1,
        protocol="TCP", timestamp=1000,
    )

    udp_first = send(
        tracker, 2,
        protocol="UDP", timestamp=1000,
    )

    tcp_refresh = send(
        tracker, 3,
        protocol="TCP", timestamp=1006,
    )

    assert tcp_refresh.flow_id == tcp_first.flow_id
    assert len(tracker.flows) == 1

    udp_new = send(
        tracker, 4,
        protocol="UDP", timestamp=1006,
    )

    assert udp_new.flow_id != udp_first.flow_id
    assert len(tracker.flows) == 2

    tcp_new = send(
        tracker, 5,
        protocol="TCP", timestamp=1016,
    )

    assert tcp_new.flow_id != tcp_first.flow_id
    assert len(tracker.flows) == 1


def test_t12_automatic_cleanup_of_other_flows():
    tracker = FlowTracker(tcp_timeout=10)

    first = send(tracker, 1, timestamp=1000, port=50000)
    second = send(tracker, 2, timestamp=1001, port=50001)
    third = send(tracker, 3, timestamp=1010, port=50002)

    active_ids = {
        flow.flow_id for flow in tracker.flows.values()
    }

    assert first.flow_id not in active_ids
    assert second.flow_id in active_ids
    assert third.flow_id in active_ids
    assert len(tracker.flows) == 2


def test_t12_manual_expiration():
    tracker = FlowTracker(
        tcp_timeout=10,
        udp_timeout=5,
    )

    tcp = send(tracker, 1, timestamp=1000)
    udp = send(
        tracker, 2,
        protocol="UDP", timestamp=1007,
    )

    assert tracker.expire_flows(1009) == []

    first_expired = tracker.expire_flows(1010)

    assert len(first_expired) == 1
    assert first_expired[0].flow_id == tcp.flow_id
    assert len(tracker.flows) == 1

    second_expired = tracker.expire_flows(1012)

    assert len(second_expired) == 1
    assert second_expired[0].flow_id == udp.flow_id
    assert tracker.flows == {}
    assert tracker.expire_flows(1012) == []


def test_t12_out_of_order_timestamps():
    tracker = FlowTracker(tcp_timeout=10)

    first = send(tracker, 1, timestamp=1000)
    second = send(tracker, 2, timestamp=1008)
    delayed = send(tracker, 3, timestamp=1003)

    flow = next(iter(tracker.flows.values()))

    assert first.flow_id == second.flow_id
    assert delayed.flow_id == first.flow_id
    assert flow.last_seen == 1008.0

    before = send(tracker, 4, timestamp=1017)

    assert before.flow_id == first.flow_id

    expired = send(tracker, 5, timestamp=1027)

    assert expired.flow_id != first.flow_id


def test_t12_tcp_handshake_restarts_after_timeout():
    tracker = FlowTracker(tcp_timeout=10)

    syn = send(
        tracker, 1,
        timestamp=1000, flags="S",
    )

    syn_ack = send(
        tracker, 2,
        timestamp=1001, flags="SA",
        reverse=True,
    )

    ack = send(
        tracker, 3,
        timestamp=1002, flags="A",
    )

    new_syn = send(
        tracker, 4,
        timestamp=1012, flags="S",
    )

    assert [event.tcp_state for event in (syn, syn_ack, ack)] == [
        "NEW",
        "HANDSHAKE",
        "ESTABLISHED",
    ]

    assert new_syn.flow_id != syn.flow_id
    assert new_syn.tcp_state == "NEW"

    flow = next(iter(tracker.flows.values()))

    assert flow.syn_from_initiator is True
    assert flow.syn_ack_from_responder is False
    assert len(tracker.flows) == 1


def test_t12_invalid_event_does_not_trigger_cleanup():
    tracker = FlowTracker(tcp_timeout=10)

    first = send(tracker, 1, timestamp=1000)

    invalid = NormalizedIDSEvent(
        packet_id=2,
        timestamp=1200.0,
        src_ip=CLIENT,
        dst_ip=SERVER,
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=50000,
        dst_port=443,
        preprocess_status="invalid",
    )

    tracker.track(invalid)

    assert invalid.flow_id is None
    assert len(tracker.flows) == 1

    flow = next(iter(tracker.flows.values()))

    assert flow.flow_id == first.flow_id


def test_t12_reject_invalid_timeout_configuration():
    invalid_values = (
        0,
        -1,
        float("nan"),
        float("inf"),
        "10",
        True,
        None,
    )

    for name in ("tcp_timeout", "udp_timeout"):
        for value in invalid_values:
            with pytest.raises(ValueError):
                FlowTracker(**{name: value})


def test_t12_reject_invalid_expiration_timestamp():
    tracker = FlowTracker()

    invalid_values = (
        -1,
        float("nan"),
        float("inf"),
        "1200",
        True,
        None,
    )

    for value in invalid_values:
        with pytest.raises(ValueError):
            tracker.expire_flows(value)


def test_t12_pcap_timeout():
    packets = [
        make_packet("TCP", timestamp=1000),
        make_packet("UDP", timestamp=1000),
        make_packet("UDP", timestamp=1059, reverse=True),
        make_packet("UDP", timestamp=1119),
        make_packet("TCP", timestamp=1299),
        make_packet("TCP", timestamp=1599),
    ]

    with TemporaryDirectory() as directory:
        path = Path(directory) / "t12_idle_timeout.pcap"
        wrpcap(str(path), packets)
        events = list(read_pcap(path))

    assert len(events) == 6

    assert events[1].flow_id == events[2].flow_id
    assert events[3].flow_id != events[1].flow_id

    assert events[0].flow_id == events[4].flow_id
    assert events[5].flow_id != events[0].flow_id

    assert events[5].tcp_state == "NEW"
    assert events[2].flow_direction == "backward"

    assert len({event.flow_id for event in events}) == 4
