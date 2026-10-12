from base64 import b64encode

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from modules.core import parse_packet


def make_packet(payload, sport=50000, dport=80):
    return (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=sport, dport=dport, flags="PA")
        / Raw(load=payload)
    )


@pytest.mark.parametrize(
    "start_line, sport, dport, expected_type",
    [
        (b"POST /submit HTTP/1.1", 50000, 80, "request"),
        (b"HTTP/1.1 200 OK", 80, 50000, "response"),
    ],
)
def test_t04_invalid_http_body(
    start_line, sport, dport, expected_type
):
    payload = (
        start_line
        + b"\r\nContent-Type: text/plain\r\n\r\n"
        + b"Hello \xff\xfe World"
    )

    event = parse_packet(
        make_packet(payload, sport, dport),
        packet_id=1,
    )

    data = event.application_data

    assert event.status == "OK"
    assert data["type"] == expected_type
    assert data["body_decode_status"] == "PARTIAL"
    assert "\ufffd" in data["body"]


def test_t04_invalid_percent_encoded_uri():
    payload = (
        b"GET /search?q=%FF%FE HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"\r\n"
    )

    event = parse_packet(make_packet(payload), packet_id=2)
    data = event.application_data

    assert event.status == "OK"
    assert data["uri"] == "/search?q=%FF%FE"
    assert data["decoded_uri"] == "/search?q=\ufffd\ufffd"
    assert data["decode_status"] == "PARTIAL"


def test_t04_invalid_form_encoding():
    payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"name=%FF"
    )

    event = parse_packet(make_packet(payload), packet_id=3)
    data = event.application_data

    assert event.status == "OK"
    assert data["form_decode_status"] == "PARTIAL"
    assert data["decoded_form"] == [
        {"name": "name", "value": "\ufffd"}
    ]


def test_t04_invalid_smtp_utf8():
    payload = (
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        + b64encode(b"Hello \xff World")
    )

    event = parse_packet(
        make_packet(payload, 50000, 25),
        packet_id=4,
    )

    data = event.application_data

    assert event.status == "OK"
    assert data["mime_decode_status"] == "PARTIAL"
    assert data["mime_parts"][0]["decode_status"] == "PARTIAL"
    assert "\ufffd" in data["mime_decoded_body"]


def test_t04_continues_after_invalid_packet():
    bodies = [
        b"Invalid \xff body",
        b"Valid UTF-8 body",
    ]

    events = []

    for packet_id, body in enumerate(bodies, start=1):
        payload = (
            b"POST /test HTTP/1.1\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            + body
        )

        events.append(
            parse_packet(
                make_packet(payload),
                packet_id=packet_id,
            )
        )

    assert len(events) == 2
    assert events[0].status == "OK"
    assert events[1].status == "OK"
    assert events[0].application_data["body_decode_status"] == "PARTIAL"
    assert events[1].application_data["body_decode_status"] == "OK"
    assert events[1].application_data["body"] == "Valid UTF-8 body"
