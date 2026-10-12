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
    tcp_state: str | None = None
    syn_from_initiator: bool = False
    syn_ack_from_responder: bool = False
    fin_from_initiator: bool = False
    fin_from_responder: bool = False


class FlowTracker:
    def __init__(self):
        self.flows = {}
        self._next_flow_number = 1

    def _update_tcp_state(
        self,
        flow: FlowRecord,
        event: NormalizedIDSEvent,
    ) -> None:

        if flow.protocol != "TCP":
            return

        if flow.tcp_state is None:
            flow.tcp_state = "NEW"

        if flow.tcp_state in ("CLOSED", "RESET"):
            event.tcp_state = flow.tcp_state
            return

        flags = event.tcp_flags if isinstance(event.tcp_flags, str) else ""
        forward = event.flow_direction == "forward"

        if "R" in flags:
            flow.tcp_state = "RESET"

        elif "F" in flags:
            if forward:
                flow.fin_from_initiator = True
            else:
                flow.fin_from_responder = True

            flow.tcp_state = "CLOSING"

        elif flow.fin_from_initiator or flow.fin_from_responder:
            if (
                flow.fin_from_initiator
                and flow.fin_from_responder
                and "A" in flags
            ):
                flow.tcp_state = "CLOSED"
            else:
                flow.tcp_state = "CLOSING"

        elif "S" in flags and "A" not in flags:
            if forward:
                flow.syn_from_initiator = True

        elif "S" in flags and "A" in flags:
            if not forward and flow.syn_from_initiator:
                flow.syn_ack_from_responder = True
                flow.tcp_state = "HANDSHAKE"

        elif "A" in flags and forward:
            if flow.syn_from_initiator and flow.syn_ack_from_responder:
                flow.tcp_state = "ESTABLISHED"

        event.tcp_state = flow.tcp_state

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

        self._update_tcp_state(flow, event)

        return event
