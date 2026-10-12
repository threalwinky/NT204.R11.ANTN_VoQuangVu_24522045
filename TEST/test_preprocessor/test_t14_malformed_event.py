import pytest
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


@pytest.mark.parametrize(
    "timestamp",
    [-1.0, float("nan"), float("inf"), "invalid", True],
)
def test_t14_invalid_timestamp(timestamp):
    event = process(make_event(timestamp=timestamp))

    assert event.preprocess_status == "invalid"
    assert "invalid_timestamp" in event.reason
    assert event.processing_action == "emit"


@pytest.mark.parametrize(
    "field,value",
    [
        ("src_port", -1),
        ("src_port", 65536),
        ("dst_port", "80"),
        ("dst_port", True),
    ],
)
def test_t14_invalid_ports(field, value):
    event = make_event()
    setattr(event, field, value)

    process(event)

    assert event.preprocess_status == "invalid"
    assert f"invalid_{field}" in event.reason


@pytest.mark.parametrize(
    "address",
    ["999.999.999.999", "not-an-ip", "", 123],
)
def test_t14_invalid_ip(address):
    event = process(make_event(src_ip=address))

    assert event.preprocess_status == "invalid"
    assert "invalid_src_ip" in event.reason


@pytest.mark.parametrize(
    "data",
    [None, [], "corrupted"],
)
def test_t14_invalid_application_data(data):
    event = process(make_event(application_data=data))

    assert event.preprocess_status == "invalid"
    assert "invalid_application_data" in event.reason
    assert event.processing_action == "emit"


def test_t14_invalid_packet_id():
    event = process(make_event(packet_id=-1))

    assert event.preprocess_status == "invalid"
    assert "invalid_packet_id" in event.reason


def test_t14_invalid_payload_length():
    event = process(make_event(payload_length=-100))

    assert event.preprocess_status == "invalid"
    assert "invalid_payload_length" in event.reason


def test_t14_parser_error():
    event = process(make_event(
        status="ERROR",
        error="ValueError: malformed packet",
    ))

    assert event.status == "ERROR"
    assert event.preprocess_status == "invalid"
    assert "parser_error" in event.reason
    assert event.error == "ValueError: malformed packet"

    apply_processing_policy(event, skip_invalid=True)

    assert event.processing_action == "skip"


def test_t14_unsupported_protocol():
    event = process(make_event(
        transport_protocol="SCTP",
        application_protocol="FTP",
    ))

    assert event.preprocess_status == "partial"
    assert "unsupported_transport_protocol" in event.reason
    assert "unsupported_application_protocol" in event.reason
    assert event.processing_action == "emit"


def test_t14_malformed_packet_then_valid_packet():
    malformed = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, flags="PA")
        / Raw(load=b"\xff\xfe\x00INVALID")
    )

    valid = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, flags="PA")
        / Raw(load=(
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"\r\n"
        ))
    )

    first = parse_packet(malformed, packet_id=1)
    second = parse_packet(valid, packet_id=2)

    assert first.status == "OK"
    assert first.preprocess_status == "partial"
    assert "missing_application_type" in first.reason

    assert second.status == "OK"
    assert second.preprocess_status == "valid"
    assert second.application_data["method"] == "GET"


def test_t14_invalid_event_skip_policy():
    event = process(make_event(
        src_port=70000,
        timestamp=-1,
    ))

    assert event.preprocess_status == "invalid"
    assert event.processing_action == "emit"

    apply_processing_policy(event, skip_invalid=True)

    assert event.processing_action == "skip"

    apply_processing_policy(event)

    assert event.processing_action == "emit"
