import json
import threading
from importlib import import_module
from pathlib import Path
from threading import Event
from time import sleep

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from modules.capture import CaptureError
from modules.logger import JSONLLogger


LIVE = import_module("modules.capture.live")
WORKER_NAME = "ids-live-flow-expiration"


def udp_packet(timestamp=1000.0, port=53000, payload=b"hello"):
    packet = (
        IP(src="192.0.2.10", dst="192.0.2.20")
        / UDP(sport=port, dport=9999)
        / Raw(load=payload)
    )
    packet.time = float(timestamp)
    return packet


def tcp_packet(flags, timestamp, reverse=False):
    if reverse:
        src, dst = "192.0.2.20", "192.0.2.10"
        sport, dport = 443, 50000
    else:
        src, dst = "192.0.2.10", "192.0.2.20"
        sport, dport = 50000, 443

    packet = (
        IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags=flags)
    )
    packet.time = float(timestamp)
    return packet


def prepare_live(monkeypatch, fake_sniff):
    monkeypatch.setattr(
        LIVE,
        "resolve_iface",
        lambda interface: interface,
    )
    monkeypatch.setattr(LIVE, "sniff", fake_sniff)


def assert_worker_stopped():
    assert not any(
        thread.name == WORKER_NAME
        for thread in threading.enumerate()
    )


def test_live_udp_expires_without_new_packets(monkeypatch):
    signal = Event()
    events = []
    expired = []

    def on_expired(record):
        expired.append(record)
        signal.set()

    def fake_sniff(*, iface, prn, store):
        assert iface == "test-interface"
        assert store is False

        prn(udp_packet())

        assert signal.wait(timeout=3.0)

    prepare_live(monkeypatch, fake_sniff)

    LIVE.capture_live(
        interface="test-interface",
        on_event=events.append,
        on_flow_expired=on_expired,
        tcp_timeout=1.0,
        udp_timeout=0.2,
    )

    assert len(events) == 1
    assert len(expired) == 1

    record = expired[0]

    assert record["record_type"] == "flow_expired"
    assert record["end_reason"] == "idle_timeout"
    assert record["transport_protocol"] == "UDP"
    assert record["flow_id"] == events[0].flow_id
    assert record["packet_count"] == 1
    assert record["byte_count"] == 5
    assert record["expired_at"] >= 1000.2

    assert_worker_stopped()


def test_live_tcp_expires_with_state_and_flags(monkeypatch):
    signal = Event()
    events = []
    expired = []

    packets = [
        tcp_packet("S", 1000.0),
        tcp_packet("SA", 1000.01, reverse=True),
        tcp_packet("A", 1000.02),
    ]

    def on_expired(record):
        expired.append(record)
        signal.set()

    def fake_sniff(*, iface, prn, store):
        for packet in packets:
            prn(packet)

        assert signal.wait(timeout=3.0)

    prepare_live(monkeypatch, fake_sniff)

    LIVE.capture_live(
        interface="test-interface",
        on_event=events.append,
        on_flow_expired=on_expired,
        tcp_timeout=0.2,
        udp_timeout=1.0,
    )

    assert len(events) == 3
    assert len(expired) == 1
    assert len({event.flow_id for event in events}) == 1

    record = expired[0]

    assert record["flow_id"] == events[0].flow_id
    assert record["transport_protocol"] == "TCP"
    assert record["tcp_state"] == "ESTABLISHED"
    assert record["packet_count"] == 3
    assert record["SYN_count"] == 2
    assert record["ACK_count"] == 2
    assert record["FIN_count"] == 0
    assert record["RST_count"] == 0

    assert_worker_stopped()


def test_live_does_not_expire_before_timeout(monkeypatch):
    signal = Event()
    expired = []

    def on_expired(record):
        expired.append(record)
        signal.set()

    def fake_sniff(*, iface, prn, store):
        prn(udp_packet())

        assert not signal.wait(timeout=0.05)
        assert signal.wait(timeout=3.0)

    prepare_live(monkeypatch, fake_sniff)

    LIVE.capture_live(
        interface="test-interface",
        on_event=lambda event: None,
        on_flow_expired=on_expired,
        tcp_timeout=1.0,
        udp_timeout=0.3,
    )

    assert len(expired) == 1
    assert expired[0]["expired_at"] >= 1000.3

    assert_worker_stopped()


def test_live_expires_multiple_udp_flows(monkeypatch):
    signal = Event()
    events = []
    expired = []

    def on_expired(record):
        expired.append(record)

        if len(expired) == 2:
            signal.set()

    def fake_sniff(*, iface, prn, store):
        prn(udp_packet(1000.0, port=53000))
        prn(udp_packet(1000.01, port=53001))

        assert signal.wait(timeout=3.0)

    prepare_live(monkeypatch, fake_sniff)

    LIVE.capture_live(
        interface="test-interface",
        on_event=events.append,
        on_flow_expired=on_expired,
        tcp_timeout=1.0,
        udp_timeout=0.2,
    )

    assert len(events) == 2
    assert len(expired) == 2
    assert events[0].flow_id != events[1].flow_id

    assert {
        record["flow_id"]
        for record in expired
    } == {
        event.flow_id
        for event in events
    }

    assert all(
        record["packet_count"] == 1
        for record in expired
    )

    assert_worker_stopped()


def test_live_tcp_udp_timeouts_are_independent(monkeypatch):
    signal = Event()
    events = []
    expired = []

    def on_expired(record):
        expired.append(record)
        signal.set()

    def fake_sniff(*, iface, prn, store):
        prn(tcp_packet("S", 1000.0))
        prn(udp_packet(1000.01))

        assert signal.wait(timeout=3.0)

    prepare_live(monkeypatch, fake_sniff)

    LIVE.capture_live(
        interface="test-interface",
        on_event=events.append,
        on_flow_expired=on_expired,
        tcp_timeout=2.0,
        udp_timeout=0.2,
    )

    assert len(events) == 2
    assert len(expired) == 1
    assert expired[0]["transport_protocol"] == "UDP"
    assert expired[0]["flow_id"] == events[1].flow_id
    assert expired[0]["flow_id"] != events[0].flow_id

    assert_worker_stopped()


def test_live_no_packets_no_expiration(monkeypatch):
    events = []
    expired = []

    def fake_sniff(*, iface, prn, store):
        sleep(0.15)

    prepare_live(monkeypatch, fake_sniff)

    LIVE.capture_live(
        interface="test-interface",
        on_event=events.append,
        on_flow_expired=expired.append,
        tcp_timeout=0.2,
        udp_timeout=0.1,
    )

    assert events == []
    assert expired == []

    assert_worker_stopped()


def test_live_worker_stops_after_capture_returns(monkeypatch):
    expired = []

    def fake_sniff(*, iface, prn, store):
        prn(udp_packet())

    prepare_live(monkeypatch, fake_sniff)

    LIVE.capture_live(
        interface="test-interface",
        on_event=lambda event: None,
        on_flow_expired=expired.append,
        tcp_timeout=1.0,
        udp_timeout=0.2,
    )

    assert_worker_stopped()

    sleep(0.3)

    assert expired == []
    assert_worker_stopped()


def test_live_worker_stops_on_sniff_error(monkeypatch):
    def fake_sniff(*, iface, prn, store):
        raise OSError("simulated capture error")

    prepare_live(monkeypatch, fake_sniff)

    with pytest.raises(
        CaptureError,
        match="simulated capture error",
    ):
        LIVE.capture_live(
            interface="test-interface",
            on_event=lambda event: None,
            tcp_timeout=0.2,
            udp_timeout=0.1,
        )

    assert_worker_stopped()


def test_live_new_packet_refreshes_idle_timeout(monkeypatch):
    signal = Event()
    events = []
    expired = []

    def on_expired(record):
        expired.append(record)
        signal.set()

    def fake_sniff(*, iface, prn, store):
        prn(udp_packet(timestamp=1000.0))

        assert not signal.wait(timeout=0.10)

        prn(udp_packet(timestamp=1000.10))

        assert not signal.wait(timeout=0.10)
        assert signal.wait(timeout=3.0)

    prepare_live(monkeypatch, fake_sniff)

    LIVE.capture_live(
        interface="test-interface",
        on_event=events.append,
        on_flow_expired=on_expired,
        tcp_timeout=1.0,
        udp_timeout=0.35,
    )

    assert len(events) == 2
    assert len(expired) == 1

    assert events[0].flow_id == events[1].flow_id
    assert expired[0]["flow_id"] == events[0].flow_id
    assert expired[0]["packet_count"] == 2
    assert expired[0]["byte_count"] == 10
    assert expired[0]["expired_at"] >= 1000.45

    assert_worker_stopped()


def test_live_idle_expiration_jsonl_output(monkeypatch, tmp_path):
    signal = Event()
    path = tmp_path / "live_idle.jsonl"

    def fake_sniff(*, iface, prn, store):
        prn(udp_packet())
        assert signal.wait(timeout=3.0)

    prepare_live(monkeypatch, fake_sniff)

    with JSONLLogger(path) as logger:
        def on_expired(record):
            logger.write(record)
            signal.set()

        LIVE.capture_live(
            interface="test-interface",
            on_event=logger.write,
            on_flow_expired=on_expired,
            tcp_timeout=1.0,
            udp_timeout=0.2,
        )

    records = [
        json.loads(line)
        for line in path.read_text().splitlines()
    ]

    assert len(records) == 2

    event, expired = records

    assert event["flow_id"] == expired["flow_id"]
    assert expired["record_type"] == "flow_expired"
    assert expired["end_reason"] == "idle_timeout"
    assert expired["packet_count"] == 1
    assert expired["byte_count"] == 5

    assert_worker_stopped()
