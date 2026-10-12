from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from modules.core import parse_packet
from modules.models import NormalizedIDSEvent
from modules.preprocessor import normalize_event, validate_event


def test_t05_protocol_ip_domain_timestamp():
    event = NormalizedIDSEvent(
        packet_id=1,
        timestamp=1234,
        src_ip=" 192.168.1.10 ",
        dst_ip=" 8.8.8.8 ",
        network_protocol=" ipv4 ",
        transport_protocol=" udp ",
        application_protocol=" dNs ",
        src_port=53000,
        dst_port=53,
        application_data={
            "type": "query",
            "domain": " ExAmPlE.COM. ",
        },
    )

    normalize_event(event)
    validate_event(event)

    assert event.network_protocol == "IPv4"
    assert event.transport_protocol == "UDP"
    assert event.application_protocol == "DNS"
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "8.8.8.8"
    assert event.timestamp == 1234.0
    assert type(event.timestamp) is float
    assert event.application_data["normalized_domain"] == "example.com"
    assert event.application_data["domain"] == " ExAmPlE.COM. "
    assert event.preprocess_status == "valid"


def test_t05_http_headers_and_uri():
    payload = (
        b"GET /files/%2f?q=%ff HTTP/1.1\r\n"
        b"hOsT: ExAmPlE.COM\r\n"
        b"CoNtEnT-TyPe: text/plain\r\n"
        b"\r\n"
    )

    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, flags="PA")
        / Raw(load=payload)
    )

    event = parse_packet(packet, packet_id=2)
    data = event.application_data

    assert event.status == "OK"
    assert event.preprocess_status == "valid"
    assert data["uri"] == "/files/%2f?q=%ff"
    assert data["normalized_uri"] == "/files/%2F?q=%FF"
    assert data["normalized_path"] == "/files/%2F"
    assert data["normalized_headers"]["host"] == "ExAmPlE.COM"
    assert data["normalized_headers"]["content-type"] == "text/plain"
    assert "hOsT" in data["headers"]


def test_t05_dns_response_normalization():
    event = NormalizedIDSEvent(
        packet_id=3,
        timestamp=1000.0,
        src_ip="8.8.8.8",
        dst_ip="192.168.1.10",
        network_protocol="IPv4",
        transport_protocol="UDP",
        application_protocol="DNS",
        src_port=53,
        dst_port=53000,
        application_data={
            "type": "response",
            "answer": {
                "name": " ExAmPlE.COM. ",
                "record_type": "A",
                "data": "93.184.216.34",
            },
        },
    )

    normalize_event(event)
    validate_event(event)

    answer = event.application_data["answer"]

    assert answer["name"] == " ExAmPlE.COM. "
    assert answer["normalized_name"] == "example.com"
    assert event.preprocess_status == "valid"


def test_t05_invalid_ip_is_preserved():
    event = NormalizedIDSEvent(
        packet_id=4,
        timestamp=1000.0,
        src_ip="999.999.999.999",
        dst_ip="192.168.1.20",
        network_protocol=" ipv4 ",
        transport_protocol="tcp",
        application_protocol="http",
        src_port=50000,
        dst_port=80,
    )

    normalize_event(event)
    validate_event(event)

    assert event.network_protocol == "IPv4"
    assert event.transport_protocol == "TCP"
    assert event.application_protocol == "HTTP"
    assert event.src_ip == "999.999.999.999"
    assert event.preprocess_status == "invalid"
    assert "invalid_src_ip" in event.reason


def test_t05_malformed_uri():
    event = NormalizedIDSEvent(
        packet_id=5,
        timestamp=1000.0,
        application_protocol="HTTP",
        application_data={
            "type": "request",
            "uri": "http://[::1",
            "headers": {" X-TEST ": "value"},
        },
    )

    normalize_event(event)

    assert event.application_data["normalized_uri"] == "http://[::1"
    assert event.application_data["normalized_path"] is None
    assert event.application_data["normalized_headers"]["x-test"] == "value"


def test_t05_normalization_idempotent():
    event = NormalizedIDSEvent(
        packet_id=6,
        timestamp=1234,
        src_ip=" 192.168.1.10 ",
        dst_ip="192.168.1.20",
        network_protocol="ipv4",
        transport_protocol="tcp",
        application_protocol="http",
        src_port=50000,
        dst_port=80,
        application_data={
            "type": "request",
            "uri": "/test/%2f",
            "headers": {"CONTENT-TYPE": "text/plain"},
        },
    )

    normalize_event(event)
    first_result = event.to_dict()

    normalize_event(event)
    second_result = event.to_dict()

    assert first_result == second_result
    assert event.application_data["normalized_uri"] == "/test/%2F"
