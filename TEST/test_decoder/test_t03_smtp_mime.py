from base64 import b64encode
from quopri import encodestring

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from modules.core import parse_packet
from modules.decoder import decode_smtp_mime
from modules.models import NormalizedIDSEvent


def make_packet(message):
    return (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=25, flags="PA")
        / Raw(load=message)
    )


@pytest.mark.parametrize(
    "encoding, encoder",
    [
        ("base64", b64encode),
        ("quoted-printable", encodestring),
    ],
)
def test_t03_encoded_body(encoding, encoder):
    text = "Xin chào SMTP"

    message = (
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Transfer-Encoding: {encoding}\r\n".encode()
        + b"\r\n"
        + encoder(text.encode("utf-8"))
    )

    event = parse_packet(make_packet(message), packet_id=1)
    data = event.application_data

    assert event.status == "OK"
    assert event.application_protocol == "SMTP"
    assert data["mime_decode_status"] == "OK"
    assert data["mime_decoded_body"] == text
    assert data["mime_parts"][0]["encoding"] == encoding
    assert data["mime_parts"][0]["decode_status"] == "OK"


def test_t03_multipart():
    plain_text = "Plain tiếng Việt"
    html_text = "<b>Chào SMTP</b>"

    message = (
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/alternative; boundary="ids-boundary"\r\n'
        b"\r\n"
        b"--ids-boundary\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        + b64encode(plain_text.encode("utf-8"))
        + b"\r\n"
        b"--ids-boundary\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n"
        b"\r\n"
        + encodestring(html_text.encode("utf-8"))
        + b"\r\n"
        b"--ids-boundary--\r\n"
    )

    event = parse_packet(make_packet(message), packet_id=2)
    data = event.application_data

    assert event.status == "OK"
    assert data["mime_decode_status"] == "OK"
    assert len(data["mime_parts"]) == 2
    assert data["mime_parts"][0]["decoded_body"] == plain_text
    assert data["mime_parts"][1]["decoded_body"] == html_text
    assert "mime_decoded_body" not in data


def test_t03_invalid_base64():
    message = (
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"%%%"
    )

    event = parse_packet(make_packet(message), packet_id=3)
    data = event.application_data

    assert event.status == "OK"
    assert data["mime_decode_status"] == "ERROR"
    assert data["mime_parts"][0]["decode_status"] == "ERROR"
    assert "error" in data["mime_parts"][0]
    assert "mime_decoded_body" not in data


def test_t03_size_limit():
    message = (
        b"MIME-Version: 1.0\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        + b64encode(b"Hello SMTP")
    )

    event = NormalizedIDSEvent(
        packet_id=4,
        timestamp=1000.0,
        application_protocol="SMTP",
    )

    decode_smtp_mime(
        make_packet(message),
        event,
        max_message_bytes=16,
    )

    assert event.status == "OK"
    assert event.application_data["mime_decode_status"] == "SKIPPED"
    assert "mime_decoded_body" not in event.application_data


def test_t03_unencoded_body():
    message = (
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Hello SMTP"
    )

    event = parse_packet(make_packet(message), packet_id=5)

    assert event.status == "OK"
    assert "mime_decoded_body" not in event.application_data
    assert "mime_decode_status" not in event.application_data
