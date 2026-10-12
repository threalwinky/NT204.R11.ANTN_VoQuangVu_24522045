import json
import subprocess
import sys
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

import main
from modules.capture import read_pcap


MAIN_PATH = Path(__file__).resolve().parents[2] / "main.py"


def make_packet(protocol, timestamp, port=53000):
    if protocol == "TCP":
        packet = (
            IP(src="192.0.2.10", dst="192.0.2.20")
            / TCP(sport=port, dport=443, flags="S")
        )
    else:
        packet = (
            IP(src="192.0.2.10", dst="192.0.2.20")
            / UDP(sport=port, dport=9999)
            / Raw(load=b"abc")
        )

    packet.time = float(timestamp)
    return packet


def make_pcap(tmp_path, protocol="UDP", times=(1000, 1006)):
    path = tmp_path / f"{protocol.lower()}_timeout.pcap"
    packets = [
        make_packet(protocol, timestamp)
        for timestamp in times
    ]
    wrpcap(str(path), packets)
    return path


def run_cli(tmp_path, pcap, *options):
    return subprocess.run(
        [
            sys.executable,
            str(MAIN_PATH),
            "--pcap",
            str(pcap),
            *options,
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )


def parse_output(output):
    return [
        json.loads(line)
        for line in output.splitlines()
        if line.startswith("{")
    ]


def test_udp_reader_custom_timeout_expires(tmp_path):
    path = make_pcap(tmp_path)
    expired = []

    events = list(
        read_pcap(
            path,
            udp_timeout=5,
            on_flow_expired=expired.append,
        )
    )

    assert len(events) == 2
    assert len(expired) == 1
    assert events[0].flow_id != events[1].flow_id
    assert expired[0]["flow_id"] == events[0].flow_id
    assert expired[0]["expired_at"] == 1006.0
    assert expired[0]["packet_count"] == 1
    assert expired[0]["byte_count"] == 3


def test_tcp_reader_custom_timeout_expires(tmp_path):
    path = make_pcap(tmp_path, protocol="TCP")
    expired = []

    events = list(
        read_pcap(
            path,
            tcp_timeout=5,
            on_flow_expired=expired.append,
        )
    )

    assert len(events) == 2
    assert len(expired) == 1
    assert events[0].flow_id != events[1].flow_id
    assert expired[0]["transport_protocol"] == "TCP"
    assert expired[0]["flow_id"] == events[0].flow_id
    assert expired[0]["SYN_count"] == 1
    assert expired[0]["packet_count"] == 1


def test_longer_timeout_preserves_flow(tmp_path):
    path = make_pcap(tmp_path)
    expired = []

    events = list(
        read_pcap(
            path,
            udp_timeout=10,
            on_flow_expired=expired.append,
        )
    )

    assert len(events) == 2
    assert expired == []
    assert events[0].flow_id == events[1].flow_id
    assert events[1].flow_statistics["packet_count"] == 2
    assert events[1].flow_statistics["byte_count"] == 6


def test_timeout_exact_boundary(tmp_path):
    path = make_pcap(tmp_path, times=(1000, 1005))
    expired = []

    events = list(
        read_pcap(
            path,
            udp_timeout=5,
            on_flow_expired=expired.append,
        )
    )

    assert len(expired) == 1
    assert expired[0]["expired_at"] == 1005.0
    assert events[0].flow_id != events[1].flow_id


def test_tcp_udp_timeout_independent(tmp_path):
    packets = [
        make_packet("TCP", 1000, port=50000),
        make_packet("UDP", 1000, port=53000),
        make_packet("UDP", 1006, port=53000),
    ]

    path = tmp_path / "mixed_timeout.pcap"
    wrpcap(str(path), packets)

    expired = []
    finalized = []

    events = list(
        read_pcap(
            path,
            tcp_timeout=10,
            udp_timeout=5,
            on_flow_expired=expired.append,
            on_flow_finalized=finalized.append,
        )
    )

    assert len(events) == 3
    assert len(expired) == 1
    assert len(finalized) == 2

    assert expired[0]["transport_protocol"] == "UDP"
    assert expired[0]["flow_id"] == events[1].flow_id
    assert events[1].flow_id != events[2].flow_id

    summary_ids = {record["flow_id"] for record in finalized}

    assert events[0].flow_id in summary_ids
    assert events[2].flow_id in summary_ids
    assert expired[0]["flow_id"] not in summary_ids


def test_timeout_and_capture_end_no_duplicates(tmp_path):
    path = make_pcap(tmp_path)
    expired = []
    finalized = []

    events = list(
        read_pcap(
            path,
            udp_timeout=5,
            on_flow_expired=expired.append,
            on_flow_finalized=finalized.append,
        )
    )

    assert len(events) == 2
    assert len(expired) == 1
    assert len(finalized) == 1

    assert expired[0]["record_type"] == "flow_expired"
    assert finalized[0]["record_type"] == "flow_summary"

    assert expired[0]["end_reason"] == "idle_timeout"
    assert finalized[0]["end_reason"] == "capture_end"

    assert expired[0]["flow_id"] == events[0].flow_id
    assert finalized[0]["flow_id"] == events[1].flow_id
    assert expired[0]["flow_id"] != finalized[0]["flow_id"]


def test_cli_stdout_custom_timeout(tmp_path):
    path = make_pcap(tmp_path)

    result = run_cli(
        tmp_path,
        path,
        "--udp-timeout",
        "5",
        "--emit-flow-summaries",
    )

    records = parse_output(result.stdout)

    assert len(records) == 4
    assert records[1]["record_type"] == "flow_expired"
    assert records[3]["record_type"] == "flow_summary"

    assert records[0]["flow_id"] == records[1]["flow_id"]
    assert records[2]["flow_id"] == records[3]["flow_id"]
    assert records[0]["flow_id"] != records[2]["flow_id"]

    assert records[1]["packet_count"] == 1
    assert records[3]["packet_count"] == 1


def test_cli_jsonl_custom_timeout(tmp_path):
    path = make_pcap(tmp_path, protocol="TCP")

    run_cli(
        tmp_path,
        path,
        "--tcp-timeout",
        "5",
        "--output",
        "file",
        "--emit-flow-summaries",
    )

    outputs = list(
        (tmp_path / "files" / "output").glob("*.jsonl")
    )

    assert len(outputs) == 1

    records = [
        json.loads(line)
        for line in outputs[0].read_text().splitlines()
    ]

    assert len(records) == 4
    assert records[1]["record_type"] == "flow_expired"
    assert records[3]["record_type"] == "flow_summary"

    assert records[1]["transport_protocol"] == "TCP"
    assert records[1]["SYN_count"] == 1
    assert records[3]["SYN_count"] == 1


def test_cli_rejects_invalid_timeout_values(tmp_path):
    path = make_pcap(tmp_path)

    invalid_cases = [
        ("--tcp-timeout", "0"),
        ("--tcp-timeout", "nan"),
        ("--tcp-timeout", "inf"),
        ("--udp-timeout", "-1"),
        ("--udp-timeout", "-inf"),
    ]

    for option, value in invalid_cases:
        result = subprocess.run(
            [
                sys.executable,
                str(MAIN_PATH),
                "--pcap",
                str(path),
                f"{option}={value}",
            ],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 2
        assert "positive finite number" in result.stderr


def test_live_capture_custom_timeout_mock(monkeypatch):
    live = import_module("modules.capture.live")

    packets = [
        make_packet("UDP", 1000),
        make_packet("UDP", 1006),
    ]

    events = []
    expired = []

    def fake_sniff(*, iface, prn, store):
        assert iface == "test-interface"
        assert store is False

        for packet in packets:
            prn(packet)

    monkeypatch.setattr(
        live,
        "resolve_iface",
        lambda interface: interface,
    )

    monkeypatch.setattr(live, "sniff", fake_sniff)

    live.capture_live(
        interface="test-interface",
        on_event=events.append,
        on_flow_expired=expired.append,
        tcp_timeout=10,
        udp_timeout=5,
    )

    assert len(events) == 2
    assert len(expired) == 1

    assert events[0].flow_id != events[1].flow_id
    assert expired[0]["flow_id"] == events[0].flow_id
    assert expired[0]["expired_at"] == 1006.0
    assert expired[0]["byte_count"] == 3


def test_main_forwards_live_timeouts(monkeypatch):
    captured = {}

    def fake_capture_live(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(
        main,
        "capture_live",
        fake_capture_live,
    )

    args = SimpleNamespace(
        interface="mock0",
        pcap=None,
        tcp_timeout=13.0,
        udp_timeout=7.0,
        skip_partial=False,
        skip_invalid=False,
        skip_unknown=False,
    )

    main.run_capture(args, lambda record: None)

    assert captured["interface"] == "mock0"
    assert captured["tcp_timeout"] == 13.0
    assert captured["udp_timeout"] == 7.0
    assert callable(captured["on_event"])
    assert callable(captured["on_flow_expired"])
