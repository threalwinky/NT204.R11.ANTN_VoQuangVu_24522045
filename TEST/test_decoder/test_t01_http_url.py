import pytest

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from modules.core import parse_packet


@pytest.mark.parametrize(
    "raw_uri, expected_uri",
    [
        (
            "/search?q=%27%20OR%201%3D1",
            "/search?q=' OR 1=1",
        ),
        (
            "/user/%E4%BD%A0%E5%A5%BD",
            "/user/你好",
        ),
    ],
)
def test_t01_http_url_decoding(raw_uri, expected_uri):
    request = (
        f"GET {raw_uri} HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n"
    ).encode("ascii")

    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, flags="PA")
        / Raw(load=request)
    )

    event = parse_packet(packet, packet_id=1)

    assert event.status == "OK"
    assert event.application_protocol == "HTTP"
    assert event.application_data["type"] == "request"
    assert event.application_data["uri"] == raw_uri
    assert event.application_data["decoded_uri"] == expected_uri
    assert event.application_data["decode_status"] == "OK"
