import json
import subprocess
import sys
from contextlib import redirect_stdout
from importlib import import_module
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

from main import print_event, run_capture
from modules.capture import read_pcap
from modules.logger import JSONLLogger


CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"


def make_packets():
    packets = [
        IP(src=CLIENT, dst=SERVER)
        / UDP(sport=53000, dport=9999)
        / Raw(load=b"abc"),

        IP(src=SERVER, dst=CLIENT)
        / UDP(sport=9999, dport=53000)
        / Raw(load=b"de"),

        IP(src="192.168.1.11", dst=SERVER)
        / UDP(sport=53001, dport=9999)
        / Raw(load=b"xyz"),
    ]

    for packet, timestamp in zip(packets, (1000, 1002, 1062)):
        packet.time = float(timestamp)

    return packets


def make_pcap(tmp_path):
    path = tmp_path / "expired_flow.pcap"
    wrpcap(str(path), make_packets())
    return path


def make_args(path, skip_partial=False):
    return SimpleNamespace(
        interface=None,
        pcap=str(path),
        skip_partial=skip_partial,
        skip_invalid=False,
        skip_unknown=False,
    )


def parse_json_lines(output):
    return [
        json.loads(line)
        for line in output.splitlines()
        if line.startswith("{")
    ]


def check_records(records):
    assert len(records) == 4

    assert records[2]["record_type"] == "flow_expired"

    expired = records[2]

    assert expired["end_reason"] == "idle_timeout"
    assert expired["expired_at"] == 1062.0
    assert expired["transport_protocol"] == "UDP"
    assert expired["packet_count"] == 2
    assert expired["byte_count"] == 5
    assert expired["forward_packets"] == 1
    assert expired["backward_packets"] == 1
    assert expired["forward_bytes"] == 3
    assert expired["backward_bytes"] == 2
    assert expired["start_time"] == 1000.0
    assert expired["last_seen"] == 1002.0
    assert expired["duration"] == 2.0

    assert records[0]["flow_id"] == expired["flow_id"]
    assert records[1]["flow_id"] == expired["flow_id"]
    assert records[3]["flow_id"] != expired["flow_id"]


def test_expired_flow_pcap_callback(tmp_path):
    path = make_pcap(tmp_path)
    expired = []

    events = list(read_pcap(
        path,
        on_flow_expired=expired.append,
    ))

    assert len(events) == 3
    assert len(expired) == 1

    record = expired[0]

    assert record["record_type"] == "flow_expired"
    assert record["end_reason"] == "idle_timeout"
    assert record["packet_count"] == 2
    assert record["byte_count"] == 5

    assert events[0].flow_id == events[1].flow_id
    assert record["flow_id"] == events[0].flow_id
    assert events[2].flow_id != record["flow_id"]


def test_expired_flow_below_timeout(tmp_path):
    packets = make_packets()[:2]
    packets[1].time = 1059.0

    path = tmp_path / "active_flow.pcap"
    wrpcap(str(path), packets)

    expired = []

    events = list(read_pcap(
        path,
        on_flow_expired=expired.append,
    ))

    assert len(events) == 2
    assert events[0].flow_id == events[1].flow_id
    assert expired == []


def test_expired_flow_tcp_state_flags(tmp_path):
    packets = [
        IP(src=CLIENT, dst=SERVER)
        / TCP(sport=50000, dport=443, flags="S"),

        IP(src=SERVER, dst=CLIENT)
        / TCP(sport=443, dport=50000, flags="SA"),

        IP(src=CLIENT, dst=SERVER)
        / TCP(sport=50000, dport=443, flags="A"),

        IP(src="192.168.1.11", dst=SERVER)
        / UDP(sport=53001, dport=9999),
    ]

    for packet, timestamp in zip(
        packets, (1000, 1001, 1002, 1302)
    ):
        packet.time = float(timestamp)

    path = tmp_path / "tcp_expired.pcap"
    wrpcap(str(path), packets)

    expired = []

    events = list(read_pcap(
        path,
        on_flow_expired=expired.append,
    ))

    assert len(events) == 4
    assert len(expired) == 1

    record = expired[0]

    assert record["flow_id"] == events[0].flow_id
    assert record["transport_protocol"] == "TCP"
    assert record["tcp_state"] == "ESTABLISHED"
    assert record["packet_count"] == 3
    assert record["SYN_count"] == 2
    assert record["ACK_count"] == 2
    assert record["FIN_count"] == 0
    assert record["RST_count"] == 0
    assert record["expired_at"] == 1302.0


def test_expired_flow_console_output(tmp_path):
    path = make_pcap(tmp_path)
    buffer = StringIO()

    with redirect_stdout(buffer):
        run_capture(make_args(path), print_event)

    records = parse_json_lines(buffer.getvalue())

    check_records(records)


def test_expired_flow_jsonl_logger(tmp_path):
    path = make_pcap(tmp_path)
    output = tmp_path / "events.jsonl"

    with JSONLLogger(output) as logger:
        with redirect_stdout(StringIO()):
            run_capture(make_args(path), logger.write)

    records = [
        json.loads(line)
        for line in output.read_text().splitlines()
    ]

    check_records(records)


def test_expired_flow_skip_partial(tmp_path):
    path = make_pcap(tmp_path)
    records = []

    with redirect_stdout(StringIO()):
        run_capture(
            make_args(path, skip_partial=True),
            records.append,
        )

    assert len(records) == 1

    record = records[0]

    assert isinstance(record, dict)
    assert record["record_type"] == "flow_expired"
    assert record["packet_count"] == 2
    assert record["byte_count"] == 5


def test_expired_flow_cli_stdout(tmp_path):
    path = make_pcap(tmp_path)
    main_path = Path(__file__).resolve().parents[2] / "main.py"

    result = subprocess.run(
        [
            sys.executable,
            str(main_path),
            "--pcap",
            str(path),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )

    records = parse_json_lines(result.stdout)

    check_records(records)


def test_expired_flow_cli_file(tmp_path):
    path = make_pcap(tmp_path)
    main_path = Path(__file__).resolve().parents[2] / "main.py"

    subprocess.run(
        [
            sys.executable,
            str(main_path),
            "--pcap",
            str(path),
            "--output",
            "file",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )

    files = list(
        (tmp_path / "files" / "output").glob("*.jsonl")
    )

    assert len(files) == 1

    records = [
        json.loads(line)
        for line in files[0].read_text().splitlines()
    ]

    check_records(records)


def test_expired_flow_live_mock(monkeypatch):
    live_module = import_module("modules.capture.live")

    packets = make_packets()
    events = []
    expired = []

    def fake_sniff(*, iface, prn, store):
        assert iface == "test-interface"
        assert store is False

        for packet in packets:
            prn(packet)

    monkeypatch.setattr(
        live_module,
        "resolve_iface",
        lambda interface: interface,
    )

    monkeypatch.setattr(
        live_module,
        "sniff",
        fake_sniff,
    )

    live_module.capture_live(
        interface="test-interface",
        on_event=events.append,
        on_flow_expired=expired.append,
    )

    assert len(events) == 3
    assert len(expired) == 1

    assert events[0].flow_id == events[1].flow_id
    assert expired[0]["flow_id"] == events[0].flow_id
    assert expired[0]["packet_count"] == 2
    assert events[2].flow_id != expired[0]["flow_id"]


def test_expired_flow_backward_compatible_reader(tmp_path):
    path = make_pcap(tmp_path)

    events = list(read_pcap(path))

    assert len(events) == 3
    assert events[0].flow_id == events[1].flow_id
    assert events[2].flow_id != events[0].flow_id
