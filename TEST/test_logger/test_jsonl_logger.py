import json

from main.logger import JSONLLogger
from main.models import NormalizedIDSEvent


def test_jsonl_logger(tmp_path):
    
    output_file = tmp_path / "events.jsonl"

    event1 = NormalizedIDSEvent(
        packet_id=1,
        timestamp=1000.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        network_protocol="IPv4",
        transport_protocol="TCP",
    )

    event2 = NormalizedIDSEvent(
        packet_id=2,
        timestamp=1001.0,
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        network_protocol="IPv4",
        transport_protocol="TCP",
    )

    with JSONLLogger(output_file) as logger:
        logger.write(event1)
        logger.write(event2)

    lines = output_file.read_text(
        encoding="utf-8",
    ).splitlines()

    assert len(lines) == 2

    first_event = json.loads(lines[0])
    second_event = json.loads(lines[1])

    assert first_event["packet_id"] == 1
    assert first_event["src_ip"] == "10.0.0.1"

    assert second_event["packet_id"] == 2
    assert second_event["src_ip"] == "10.0.0.2"