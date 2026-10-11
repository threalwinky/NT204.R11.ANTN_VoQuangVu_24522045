import pytest

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from modules.core import parse_packet
from modules.decoder import decode_html_entities
from modules.models import NormalizedIDSEvent


@pytest.mark.parametrize(
    "start_line, src_port, dst_port, expected_type",
    [
        ("POST /preview HTTP/1.1", 50000, 80, "request"),
        ("HTTP/1.1 200 OK", 80, 50000, "response"),
    ],
)
def test_t02_html_entity_decoding(
    start_line, src_port, dst_port, expected_type
):
    body = '&lt;script&gt;alert(&quot;Hello&quot;)&lt;/script&gt;'

    payload = (
        f"{start_line}\r\n"
        "Host: example.com\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body.encode())}\r\n"
        "\r\n"
        f"{body}"
    ).encode()

    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=src_port, dport=dst_port, flags="PA")
        / Raw(load=payload)
    )

    event = parse_packet(packet, packet_id=1)
    data = event.application_data

    assert event.status == "OK"
    assert event.application_protocol == "HTTP"
    assert data["type"] == expected_type
    assert data["body"] == body
    assert data["decoded_body"] == '<script>alert("Hello")</script>'
    assert data["html_decode_status"] == "OK"


def test_t02_unsupported_content_type():
    event = NormalizedIDSEvent(
        packet_id=2,
        timestamp=1000.0,
        application_protocol="HTTP",
        application_data={
            "type": "response",
            "headers": {"Content-Type": "application/json"},
            "body": "&lt;test&gt;",
        },
    )

    decode_html_entities(event)

    assert event.application_data["body"] == "&lt;test&gt;"
    assert "decoded_body" not in event.application_data


def test_t02_body_size_limit():
    event = NormalizedIDSEvent(
        packet_id=3,
        timestamp=1000.0,
        application_protocol="HTTP",
        application_data={
            "type": "response",
            "headers": {"Content-Type": "text/html"},
            "body": "&lt;script&gt;",
        },
    )

    decode_html_entities(event, max_chars=5)

    assert event.application_data["html_decode_status"] == "SKIPPED"
    assert "decoded_body" not in event.application_data


def test_t02_missing_body():
    event = NormalizedIDSEvent(
        packet_id=4,
        timestamp=1000.0,
        application_protocol="HTTP",
        application_data={
            "type": "response",
            "headers": None,
            "body": None,
        },
    )

    decode_html_entities(event)

    assert event.status == "OK"
    assert "decoded_body" not in event.application_data
