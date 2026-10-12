from dataclasses import dataclass
from ipaddress import IPv4Address
from math import isfinite

from ..models import NormalizedIDSEvent


@dataclass
class FlowRecord:
    flow_id: str
    protocol: str
    initiator: tuple[str, int]
    responder: tuple[str, int]
    first_seen: float
    last_seen: float


class FlowTracker:
    def __init__(self):
        self.flows = {}
        self._next_flow_number = 1

    def track(
        self,
        event: NormalizedIDSEvent,
    ) -> NormalizedIDSEvent:

        if event.preprocess_status == "invalid":
            return event

        if event.network_protocol != "IPv4":
            return event

        if event.transport_protocol not in ("TCP", "UDP"):
            return event

        if not all(
            isinstance(value, str)
            for value in (event.src_ip, event.dst_ip)
        ):
            return event

        try:
            IPv4Address(event.src_ip)
            IPv4Address(event.dst_ip)
        except ValueError:
            return event

        if not all(
            type(port) is int and 0 <= port <= 65535
            for port in (event.src_port, event.dst_port)
        ):
            return event

        if (
            type(event.timestamp) not in (int, float)
            or not isfinite(event.timestamp)
            or event.timestamp < 0
        ):
            return event

        source = (event.src_ip, event.src_port)
        destination = (event.dst_ip, event.dst_port)

        endpoints = tuple(sorted((source, destination)))
        flow_key = (event.transport_protocol, *endpoints)

        flow = self.flows.get(flow_key)

        if flow is None:
            flow = FlowRecord(
                flow_id=f"flow-{self._next_flow_number:06d}",
                protocol=event.transport_protocol,
                initiator=source,
                responder=destination,
                first_seen=float(event.timestamp),
                last_seen=float(event.timestamp),
            )

            self.flows[flow_key] = flow
            self._next_flow_number += 1

        else:
            flow.last_seen = max(
                flow.last_seen,
                float(event.timestamp),
            )

        event.flow_id = flow.flow_id

        if source == flow.initiator:
            event.flow_direction = "forward"
        else:
            event.flow_direction = "backward"

        return event
