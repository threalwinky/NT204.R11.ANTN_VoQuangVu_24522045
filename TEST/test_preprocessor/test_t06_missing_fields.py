from types import SimpleNamespace

import main as cli
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from modules.core import parse_packet
from modules.models import NormalizedIDSEvent
from modules.preprocessor import (
    apply_processing_policy,
    handle_missing_fields,
    normalize_event,
    validate_event,
)


def make_event(**overrides):
    fields = {
        "packet_id": 1,
        "timestamp": 1000.0,
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "src_port": 50000,
        "dst_port": 80,
        "application_protocol": "HTTP",
        "application_data": {
            "type": "request",
            "method": "GET",
            "uri": "/",
            "version": "HTTP/1.1",
        },
    }
    fields.update(overrides)
    return NormalizedIDSEvent(**fields)


def process(event):
    normalize_event(event)
    validate_event(event)
    handle_missing_fields(event)
    apply_processing_policy(event)
    return event


def test_t06_http_request_missing_fields():
    event = process(make_event(application_data={
        "type": "request",
        "method": "GET",
        "headers": {"Host": "example.com"},
    }))

    data = event.application_data

    assert event.preprocess_status == "partial"
    assert event.processing_action == "emit"
    assert "missing_uri" in event.reason
    assert "missing_version" in event.reason
    assert data["uri"] is None
    assert data["version"] is None
    assert data["normalized_uri"] is None
    assert data["normalized_path"] is None
    assert data["normalized_headers"]["host"] == "example.com"


def test_t06_http_response_missing_status_code():
    event = process(make_event(application_data={
        "type": "response",
        "version": "HTTP/1.1",
        "headers": {},
    }))

    assert event.preprocess_status == "partial"
    assert "missing_status_code" in event.reason
    assert event.application_data["status_code"] is None
    assert event.application_data["reason"] is None


def test_t06_dns_missing_domain():
    event = process(make_event(
        transport_protocol="UDP",
        dst_port=53,
        application_protocol="DNS",
        application_data={"type": "query"},
    ))

    data = event.application_data

    assert event.preprocess_status == "partial"
    assert "missing_domain" in event.reason
    assert data["domain"] is None
    assert data["query_type"] is None
    assert data["query_type_code"] is None
    assert data["normalized_domain"] is None


def test_t06_smtp_optional_fields():
    event = process(make_event(
        dst_port=25,
        application_protocol="SMTP",
        application_data={
            "type": "command",
            "command": "EHLO",
        },
    ))

    assert event.preprocess_status == "valid"
    assert event.application_data["argument"] is None
    assert event.application_data["mime_parts"] == []


def test_t06_mutable_defaults_are_independent():
    first = process(make_event(
        application_protocol="SMTP",
        application_data={"type": "command", "command": "EHLO"},
    ))

    second = process(make_event(
        application_protocol="SMTP",
        application_data={"type": "command", "command": "HELO"},
    ))

    first.application_data["mime_parts"].append("test")

    assert second.application_data["mime_parts"] == []


def test_t06_missing_application_type():
    event = process(make_event(application_data={}))

    assert event.preprocess_status == "partial"
    assert "missing_application_type" in event.reason
    assert event.processing_action == "emit"


def test_t06_invalid_status_is_preserved():
    event = process(make_event(
        timestamp=-10.0,
        application_data={
            "type": "request",
            "method": "POST",
        },
    ))

    assert event.preprocess_status == "invalid"
    assert "invalid_timestamp" in event.reason
    assert "missing_uri" in event.reason
    assert "missing_version" in event.reason

    apply_processing_policy(event, skip_invalid=True)

    assert event.processing_action == "skip"


def test_t06_partial_and_unknown_skip_policy():
    partial = process(make_event(application_data={
        "type": "request",
        "method": "GET",
    }))

    assert partial.processing_action == "emit"

    apply_processing_policy(partial, skip_partial=True)

    assert partial.processing_action == "skip"

    apply_processing_policy(partial)

    assert partial.processing_action == "emit"

    unknown = process(make_event(status="UNKNOWN"))

    apply_processing_policy(unknown, skip_unknown=True)

    assert unknown.processing_action == "skip"


def test_t06_unparsed_http_packet():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, flags="PA")
        / Raw(load=b"UNRECOGNIZED DATA")
    )

    event = parse_packet(packet, packet_id=9)

    assert event.application_protocol == "HTTP"
    assert event.status == "OK"
    assert event.preprocess_status == "partial"
    assert "missing_application_type" in event.reason
    assert event.processing_action == "emit"


def test_t06_cli_skip_policy(monkeypatch):
    valid = process(make_event())

    partial = process(make_event(application_data={
        "type": "request",
        "method": "GET",
    }))

    invalid = process(make_event(timestamp=-1.0))

    args = SimpleNamespace(
        interface=None,
        pcap="test.pcap",
        skip_unknown=False,
        skip_partial=True,
        skip_invalid=True,
    )

    monkeypatch.setattr(
        cli,
        "read_pcap",
        lambda path: iter((partial, invalid, valid)),
    )

    emitted = []

    cli.run_capture(args, emitted.append)

    assert emitted == [valid]
    assert partial.processing_action == "skip"
    assert invalid.processing_action == "skip"
    assert valid.processing_action == "emit"
