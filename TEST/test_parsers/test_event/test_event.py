from main.models import NormalizedIDSEvent

event = NormalizedIDSEvent(
    packet_id=1,
    timestamp=1234567890.0,
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    network_protocol="IPv4",
)

print(event.to_dict())