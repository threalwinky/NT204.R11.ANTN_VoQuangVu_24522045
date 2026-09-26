from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

@dataclass
class NormalizedIDSEvent:

    packet_id: int
    timestamp: float

    # Network layer
    src_ip: str | None = None
    dst_ip: str | None = None
    network_protocol: str | None = None

    # Transport layer
    transport_protocol: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None

    # Application layer
    application_protocol: str | None = None

    # Payload information
    payload_length: int = 0

    # Protocol-specific parsed data
    application_data: dict[str, Any] = field(default_factory=dict)

    # Parsing status
    status: str = "OK"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)