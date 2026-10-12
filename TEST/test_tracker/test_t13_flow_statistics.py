import json
from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

from modules.capture import read_pcap
from modules.core import parse_packet
from modules.models import NormalizedIDSEvent
from modules.tracker import FlowTracker


CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"


def make_event(
    packet_id=1,
    timestamp=1000.0,
    protocol="TCP",
    port=50000,
    reverse=False,
    payload_size=0,
    flags="A",
):
    service_port = 443 if protocol == "TCP" else 9999

    if reverse:
        src, dst = SERVER, CLIENT
        sport, dport = service_port, port
    else:
        src, dst = CLIENT, SERVER
        sport, dport = port, service_port

    return NormalizedIDSEvent(
        packet_id=packet_id,
        timestamp=float(timestamp),
        src_ip=src,
        dst_ip=dst,
        network_protocol="IPv4",
        transport_protocol=protocol,
        src_port=sport,
        dst_port=dport,
        tcp_flags=flags if protocol == "TCP" else None,
        payload_length=payload_size,
        preprocess_status="valid",
    )


def send(tracker, packet_id, **kwargs):
    event = make_event(packet_id=packet_id, **kwargs)
    return tracker.track(event)


def make_packet(
    protocol="TCP",
    reverse=False,
    port=50000,
    payload=b"",
):
    service_port = 443 if protocol == "TCP" else 9999

    if reverse:
        src, dst = SERVER, CLIENT
        sport, dport = service_port, port
    else:
        src, dst = CLIENT, SERVER
        sport, dport = port, service_port

    if protocol == "TCP":
        transport = TCP(sport=sport, dport=dport, flags="PA")
    else:
        transport = UDP(sport=sport, dport=dport)

    packet = IP(src=src, dst=dst) / transport

    if payload:
        packet = packet / Raw(load=payload)

    return packet


def test_t13_empty_tracker_statistics():
    tracker = FlowTracker()
    stats = tracker.get_stats()

    assert stats["active_flows"] == 0
    assert stats["total_flows_created"] == 0
    assert stats["tcp_flows"] == 0
    assert stats["udp_flows"] == 0
    assert stats["total_packets"] == 0
    assert stats["total_bytes"] == 0
    assert stats["forward_packets"] == 0
    assert stats["backward_packets"] == 0
    assert stats["tcp_states"] == {}
    assert tracker.get_flow_stats("not-found") is None


def test_t13_directional_packet_byte_counters():
    tracker = FlowTracker()

    first = send(
        tracker, 1,
        timestamp=1000, payload_size=5,
    )

    second = send(
        tracker, 2,
        timestamp=1002, payload_size=7,
        reverse=True,
    )

    third = send(
        tracker, 3,
        timestamp=1004, payload_size=3,
    )

    assert first.flow_id == second.flow_id == third.flow_id

    flow = tracker.get_flow_stats(first.flow_id)

    assert flow["packet_count"] == 3
    assert flow["byte_count"] == 15
    assert flow["forward_packets"] == 2
    assert flow["backward_packets"] == 1
    assert flow["forward_bytes"] == 8
    assert flow["backward_bytes"] == 7
    assert flow["duration"] == 4.0

    stats = tracker.get_stats()

    assert stats["total_packets"] == 3
    assert stats["total_bytes"] == 15
    assert stats["forward_packets"] == 2
    assert stats["backward_packets"] == 1
    assert stats["forward_bytes"] == 8
    assert stats["backward_bytes"] == 7


def test_t13_event_statistics_snapshots():
    tracker = FlowTracker()

    first = send(tracker, 1, payload_size=4)
    second = send(
        tracker, 2,
        timestamp=1001,
        payload_size=6,
        reverse=True,
    )
    third = send(
        tracker, 3,
        timestamp=1002,
        payload_size=8,
    )

    assert first.flow_statistics["packet_count"] == 1
    assert second.flow_statistics["packet_count"] == 2
    assert third.flow_statistics["packet_count"] == 3

    assert first.flow_statistics["byte_count"] == 4
    assert second.flow_statistics["byte_count"] == 10
    assert third.flow_statistics["byte_count"] == 18

    assert first.flow_statistics["backward_packets"] == 0
    assert second.flow_statistics["backward_packets"] == 1
    assert third.flow_statistics["backward_packets"] == 1


def test_t13_duration_with_out_of_order_packets():
    tracker = FlowTracker()

    first = send(tracker, 1, timestamp=1000)
    send(tracker, 2, timestamp=1008)
    send(tracker, 3, timestamp=1003)

    flow = tracker.get_flow_stats(first.flow_id)

    assert flow["first_seen"] == 1000.0
    assert flow["last_seen"] == 1008.0
    assert flow["duration"] == 8.0
    assert flow["packet_count"] == 3


def test_t13_multiple_flows_aggregate():
    tracker = FlowTracker()

    events = [
        send(tracker, 1, timestamp=1000, flags="S", payload_size=1),
        send(tracker, 2, timestamp=1001, flags="SA",
             reverse=True, payload_size=2),
        send(tracker, 3, timestamp=1002, flags="A", payload_size=3),
        send(tracker, 4, timestamp=1003, port=50001,
             flags="S", payload_size=4),
        send(tracker, 5, timestamp=1004, port=50001,
             flags="RA", reverse=True, payload_size=5),
        send(tracker, 6, timestamp=1005, protocol="UDP",
             port=53000, payload_size=6),
        send(tracker, 7, timestamp=1006, protocol="UDP",
             port=53000, reverse=True, payload_size=7),
    ]

    stats = tracker.get_stats()

    assert len({event.flow_id for event in events}) == 3
    assert stats["active_flows"] == 3
    assert stats["total_flows_created"] == 3
    assert stats["tcp_flows"] == 2
    assert stats["udp_flows"] == 1
    assert stats["total_packets"] == 7
    assert stats["total_bytes"] == 28
    assert stats["forward_packets"] == 4
    assert stats["backward_packets"] == 3
    assert stats["forward_bytes"] == 14
    assert stats["backward_bytes"] == 14
    assert stats["tcp_states"] == {
        "ESTABLISHED": 1,
        "RESET": 1,
    }

    assert events[2].tcp_state == "ESTABLISHED"
    assert events[4].tcp_state == "RESET"
    assert events[6].tcp_state is None


def test_t13_tcp_state_statistics_update():
    tracker = FlowTracker()

    syn = send(tracker, 1, timestamp=1000, flags="S")

    assert tracker.get_stats()["tcp_states"] == {"NEW": 1}

    syn_ack = send(
        tracker, 2,
        timestamp=1001, flags="SA", reverse=True,
    )

    assert tracker.get_stats()["tcp_states"] == {
        "HANDSHAKE": 1,
    }

    ack = send(tracker, 3, timestamp=1002, flags="A")

    assert tracker.get_stats()["tcp_states"] == {
        "ESTABLISHED": 1,
    }

    assert syn.flow_id == syn_ack.flow_id == ack.flow_id
    assert tracker.get_flow_stats(syn.flow_id)["packet_count"] == 3


def test_t13_timeout_updates_aggregate_statistics():
    tracker = FlowTracker(
        tcp_timeout=10,
        udp_timeout=5,
    )

    tcp_first = send(
        tracker, 1,
        timestamp=1000, payload_size=10,
    )

    udp_first = send(
        tracker, 2,
        timestamp=1001, protocol="UDP",
        payload_size=20,
    )

    tcp_second = send(
        tracker, 3,
        timestamp=1006, port=50001,
        payload_size=30,
    )

    stats = tracker.get_stats()

    assert stats["active_flows"] == 2
    assert stats["total_flows_created"] == 3
    assert stats["tcp_flows"] == 2
    assert stats["udp_flows"] == 0
    assert stats["total_packets"] == 2
    assert stats["total_bytes"] == 40
    assert tracker.get_flow_stats(udp_first.flow_id) is None

    expired = tracker.expire_flows(1010)

    assert len(expired) == 1
    assert expired[0].flow_id == tcp_first.flow_id
    assert expired[0].packet_count == 1

    stats = tracker.get_stats()

    assert stats["active_flows"] == 1
    assert stats["total_flows_created"] == 3
    assert stats["total_packets"] == 1
    assert stats["total_bytes"] == 30

    assert tracker.get_flow_stats(tcp_first.flow_id) is None
    assert tracker.get_flow_stats(tcp_second.flow_id) is not None

    tracker.expire_flows(1016)

    assert tracker.get_stats()["active_flows"] == 0
    assert tracker.get_stats()["total_packets"] == 0
    assert tracker.get_stats()["total_flows_created"] == 3


def test_t13_recreated_flow_resets_counters():
    tracker = FlowTracker(tcp_timeout=5)

    first = send(
        tracker, 1,
        timestamp=1000, payload_size=5,
    )

    second = send(
        tracker, 2,
        timestamp=1004, payload_size=6,
    )

    third = send(
        tracker, 3,
        timestamp=1009, payload_size=7,
    )

    assert first.flow_id == second.flow_id
    assert third.flow_id != first.flow_id

    flow = tracker.get_flow_stats(third.flow_id)

    assert flow["packet_count"] == 1
    assert flow["byte_count"] == 7
    assert flow["duration"] == 0.0

    assert tracker.get_flow_stats(first.flow_id) is None

    stats = tracker.get_stats()

    assert stats["active_flows"] == 1
    assert stats["total_flows_created"] == 2
    assert stats["total_packets"] == 1
    assert stats["total_bytes"] == 7


def test_t13_invalid_event_not_counted():
    tracker = FlowTracker()

    valid = send(tracker, 1, payload_size=10)

    invalid = make_event(
        packet_id=2,
        timestamp=1001,
        payload_size=100,
    )

    invalid.preprocess_status = "invalid"

    tracker.track(invalid)

    assert invalid.flow_id is None
    assert invalid.flow_statistics is None

    stats = tracker.get_stats()

    assert stats["active_flows"] == 1
    assert stats["total_packets"] == 1
    assert stats["total_bytes"] == 10
    assert tracker.get_flow_stats(valid.flow_id)["packet_count"] == 1


def test_t13_flow_stats_returns_independent_snapshot():
    tracker = FlowTracker()

    event = send(tracker, 1, payload_size=5)

    snapshot = tracker.get_flow_stats(event.flow_id)
    snapshot["packet_count"] = 999
    snapshot["initiator"]["ip"] = "0.0.0.0"

    current = tracker.get_flow_stats(event.flow_id)

    assert current["packet_count"] == 1
    assert current["initiator"]["ip"] == CLIENT
    assert event.flow_statistics["packet_count"] == 1


def test_t13_pcap_statistics_and_json():
    packets = [
        make_packet(payload=b"abc"),
        make_packet(reverse=True, payload=b"xy"),
        make_packet(protocol="UDP", port=53000, payload=b"hello"),
        make_packet(protocol="UDP", port=53000,
                    reverse=True, payload=b"!"),
    ]

    for index, packet in enumerate(packets):
        packet.time = float(1000 + index)

    with TemporaryDirectory() as directory:
        path = Path(directory) / "t13_flow_statistics.pcap"
        wrpcap(str(path), packets)
        events = list(read_pcap(path))

    assert len(events) == 4

    assert events[0].flow_id == events[1].flow_id
    assert events[2].flow_id == events[3].flow_id
    assert events[0].flow_id != events[2].flow_id

    tcp_stats = events[1].flow_statistics
    udp_stats = events[3].flow_statistics

    assert tcp_stats["packet_count"] == 2
    assert tcp_stats["byte_count"] == 5
    assert tcp_stats["forward_bytes"] == 3
    assert tcp_stats["backward_bytes"] == 2

    assert udp_stats["packet_count"] == 2
    assert udp_stats["byte_count"] == 6
    assert udp_stats["forward_bytes"] == 5
    assert udp_stats["backward_bytes"] == 1
    assert udp_stats["tcp_state"] is None

    output = json.dumps(
        [event.to_dict() for event in events],
        ensure_ascii=False,
    )

    decoded = json.loads(output)

    assert len(decoded) == 4
    assert decoded[0]["flow_statistics"]["packet_count"] == 1
    assert decoded[1]["flow_statistics"]["packet_count"] == 2
    assert decoded[2]["flow_statistics"]["packet_count"] == 1
    assert decoded[3]["flow_statistics"]["packet_count"] == 2

    assert decoded[1]["flow_statistics"]["byte_count"] == 5
    assert decoded[3]["flow_statistics"]["byte_count"] == 6
