from modules.models import NormalizedIDSEvent

event = NormalizedIDSEvent(
    packet_id=1,
    timestamp=1234567890.0,
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    network_protocol="IPv4",
)

print(event.to_dict())

event_dict = event.to_dict()

def test_event_to_dict():
    assert event_dict["packet_id"] == 1
    assert event_dict["timestamp"] == 1234567890.0
    assert event_dict["src_ip"] == "10.0.0.1"
    assert event_dict["dst_ip"] == "10.0.0.2"
    assert event_dict["network_protocol"] == "IPv4"
    assert event_dict["status"] == "OK"
    assert event_dict["application_data"] == {}
