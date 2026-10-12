import json
import subprocess
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

from main import run_capture
from modules.capture import read_pcap
from modules.models import NormalizedIDSEvent
from modules.tracker import FlowTracker


CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"
MAIN_PATH = Path(__file__).resolve().parents[2] / "main.py"


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

    for packet, timestamp in zip(
        packets, (1000.0, 1002.0, 1062.0)
    ):
        packet.time = timestamp

    return packets


def make_pcap(tmp_path, packets=None):
    path = tmp_path / "finalization.pcap"
    wrpcap(str(path), make_packets() if packets is None else packets)
    return path


def parse_records(output):
    return [
        json.loads(line)
        for line in output.splitlines()
        if line.startswith("{")
    ]


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


def verify_full_output(records):
    assert len(records) == 5

    assert records[2]["record_type"] == "flow_expired"
    assert records[4]["record_type"] == "flow_summary"

    expired = records[2]
    summary = records[4]

    assert expired["end_reason"] == "idle_timeout"
    assert expired["expired_at"] == 1062.0
    assert expired["packet_count"] == 2
    assert expired["byte_count"] == 5
    assert expired["forward_bytes"] == 3
    assert expired["backward_bytes"] == 2

    assert summary["end_reason"] == "capture_end"
    assert summary["transport_protocol"] == "UDP"
    assert summary["packet_count"] == 1
    assert summary["byte_count"] == 3
    assert summary["forward_packets"] == 1
    assert summary["backward_packets"] == 0
    assert summary["start_time"] == 1062.0
    assert summary["last_seen"] == 1062.0
    assert summary["duration"] == 0.0

    assert records[0]["flow_id"] == expired["flow_id"]
    assert records[1]["flow_id"] == expired["flow_id"]
    assert records[3]["flow_id"] == summary["flow_id"]

    assert expired["flow_id"] != summary["flow_id"]


def test_finalization_empty_tracker():
    tracker = FlowTracker()

    assert tracker.finalize_flows() == []
    assert tracker.finalize_flows() == []
    assert tracker.get_stats()["active_flows"] == 0


def test_finalization_preserves_statistics():
    tracker = FlowTracker()

    events = []

    for index, (timestamp, reverse, size) in enumerate(
        [
            (1000.0, False, 5),
            (1002.0, True, 7),
        ],
        start=1,
    ):
        event = NormalizedIDSEvent(
            packet_id=index,
            timestamp=timestamp,
            src_ip=SERVER if reverse else CLIENT,
            dst_ip=CLIENT if reverse else SERVER,
            network_protocol="IPv4",
            transport_protocol="UDP",
            application_protocol="DNS",
            src_port=9999 if reverse else 53000,
            dst_port=53000 if reverse else 9999,
            payload_length=size,
            preprocess_status="valid",
        )

        events.append(tracker.track(event))

    summaries = tracker.finalize_flows()

    assert len(summaries) == 1

    summary = summaries[0]

    assert summary["record_type"] == "flow_summary"
    assert summary["end_reason"] == "capture_end"
    assert summary["application_protocol"] == "DNS"
    assert summary["packet_count"] == 2
    assert summary["byte_count"] == 12
    assert summary["forward_bytes"] == 5
    assert summary["backward_bytes"] == 7
    assert summary["duration"] == 2.0

    assert summary["flow_id"] == events[0].flow_id
    assert events[0].flow_id == events[1].flow_id
    assert tracker.get_flow_stats(summary["flow_id"]) is None
    assert tracker.get_stats()["active_flows"] == 0
    assert tracker.get_stats()["total_flows_created"] == 1
    assert tracker.finalize_flows() == []

    json.dumps(summary)


def test_reader_finalizes_remaining_flow(tmp_path):
    path = make_pcap(tmp_path)

    expired = []
    finalized = []

    events = list(
        read_pcap(
            path,
            on_flow_expired=expired.append,
            on_flow_finalized=finalized.append,
        )
    )

    assert len(events) == 3
    assert len(expired) == 1
    assert len(finalized) == 1

    assert expired[0]["flow_id"] == events[0].flow_id
    assert finalized[0]["flow_id"] == events[2].flow_id

    assert expired[0]["packet_count"] == 2
    assert finalized[0]["packet_count"] == 1

    assert expired[0]["end_reason"] == "idle_timeout"
    assert finalized[0]["end_reason"] == "capture_end"

    assert expired[0]["flow_id"] != finalized[0]["flow_id"]


def test_reader_callback_order(tmp_path):
    path = make_pcap(tmp_path)
    records = []

    for event in read_pcap(
        path,
        on_flow_expired=records.append,
        on_flow_finalized=records.append,
    ):
        records.append(event.to_dict())

    verify_full_output(records)


def test_reader_without_finalization_callback(tmp_path):
    path = make_pcap(tmp_path)
    expired = []

    events = list(
        read_pcap(
            path,
            on_flow_expired=expired.append,
        )
    )

    assert len(events) == 3
    assert len(expired) == 1

    assert expired[0]["record_type"] == "flow_expired"
    assert events[2].flow_id != expired[0]["flow_id"]


def test_single_flow_summary(tmp_path):
    packet = (
        IP(src=CLIENT, dst=SERVER)
        / UDP(sport=53000, dport=9999)
        / Raw(load=b"abc")
    )
    packet.time = 1000.0

    path = make_pcap(tmp_path, [packet])

    finalized = []

    events = list(
        read_pcap(
            path,
            on_flow_finalized=finalized.append,
        )
    )

    assert len(events) == 1
    assert len(finalized) == 1

    summary = finalized[0]

    assert summary["flow_id"] == events[0].flow_id
    assert summary["packet_count"] == 1
    assert summary["byte_count"] == 3
    assert summary["duration"] == 0.0
    assert summary["end_reason"] == "capture_end"


def test_cli_stdout_with_summaries(tmp_path):
    path = make_pcap(tmp_path)

    result = run_cli(
        tmp_path,
        path,
        "--emit-flow-summaries",
    )

    records = parse_records(result.stdout)

    verify_full_output(records)


def test_cli_jsonl_with_summaries(tmp_path):
    path = make_pcap(tmp_path)

    run_cli(
        tmp_path,
        path,
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

    verify_full_output(records)


def test_cli_default_backward_compatibility(tmp_path):
    path = make_pcap(tmp_path)

    result = run_cli(tmp_path, path)

    records = parse_records(result.stdout)

    assert len(records) == 4
    assert records[2]["record_type"] == "flow_expired"

    assert not any(
        record.get("record_type") == "flow_summary"
        for record in records
    )


def test_cli_rejects_live_summary_option(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(MAIN_PATH),
            "--interface",
            "invalid-interface",
            "--emit-flow-summaries",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "--emit-flow-summaries requires --pcap" in result.stderr


def test_skip_partial_still_exports_summaries(tmp_path):
    path = make_pcap(tmp_path)

    args = SimpleNamespace(
        interface=None,
        pcap=str(path),
        skip_partial=True,
        skip_invalid=False,
        skip_unknown=False,
        emit_flow_summaries=True,
    )

    records = []

    with redirect_stdout(StringIO()):
        run_capture(args, records.append)

    assert len(records) == 2

    assert records[0]["record_type"] == "flow_expired"
    assert records[1]["record_type"] == "flow_summary"

    assert records[0]["packet_count"] == 2
    assert records[1]["packet_count"] == 1
