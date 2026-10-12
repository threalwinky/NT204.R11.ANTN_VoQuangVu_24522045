from collections.abc import Callable
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
    packet_count: int = 0
    byte_count: int = 0
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    application_protocol: str | None = None
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def to_dict(self) -> dict[str, object]:
        return {
            "flow_id": self.flow_id,
            "transport_protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "initiator": {
                "ip": self.initiator[0],
                "port": self.initiator[1],
            },
            "responder": {
                "ip": self.responder[0],
                "port": self.responder[1],
            },
            "first_seen": self.first_seen,
            "start_time": self.first_seen,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "tcp_state": self.tcp_state,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "forward_packets": self.forward_packets,
            "backward_packets": self.backward_packets,
            "forward_bytes": self.forward_bytes,
            "backward_bytes": self.backward_bytes,
            "SYN_count": self.syn_count,
            "ACK_count": self.ack_count,
            "FIN_count": self.fin_count,
            "RST_count": self.rst_count,
        }


class FlowTracker:
    def __init__(
        self,
        tcp_timeout: float = 300.0,
        udp_timeout: float = 60.0,
        on_flow_expired: Callable[[dict[str, object]], None] | None = None,
    ):
        if on_flow_expired is not None and not callable(on_flow_expired):
            raise TypeError("on_flow_expired must be callable")

        self.on_flow_expired = on_flow_expired

        for name, value in (
            ("tcp_timeout", tcp_timeout),
            ("udp_timeout", udp_timeout),
        ):
            if (
                type(value) not in (int, float)
                or not isfinite(value)
                or value <= 0
            ):
                raise ValueError(
                    f"{name} must be a positive finite number"
                )

        self.tcp_timeout = float(tcp_timeout)
        self.udp_timeout = float(udp_timeout)
        self.flows = {}
        self._next_flow_number = 1

    def expire_flows(
        self,
        now: float,
    ) -> list[FlowRecord]:

        if (
            type(now) not in (int, float)
            or not isfinite(now)
            or now < 0
        ):
            raise ValueError(
                "now must be a nonnegative finite timestamp"
            )

        expired = []

        for key, flow in list(self.flows.items()):
            timeout = (
                self.tcp_timeout
                if flow.protocol == "TCP"
                else self.udp_timeout
            )

            if float(now) - flow.last_seen >= timeout:
                if self.on_flow_expired is not None:
                    snapshot = flow.to_dict()
                    snapshot["record_type"] = "flow_expired"
                    snapshot["end_reason"] = "idle_timeout"
                    snapshot["expired_at"] = float(now)
                    self.on_flow_expired(snapshot)

                expired.append(self.flows.pop(key))

        return expired

    def get_flow_stats(
        self,
        flow_id: str,
    ) -> dict[str, object] | None:

        for flow in self.flows.values():
            if flow.flow_id == flow_id:
                return flow.to_dict()

        return None

    def get_stats(self) -> dict[str, object]:
        flows = list(self.flows.values())
        states = {}

        for flow in flows:
            if flow.protocol == "TCP":
                state = flow.tcp_state or "NEW"
                states[state] = states.get(state, 0) + 1

        return {
            "active_flows": len(flows),
            "total_flows_created": self._next_flow_number - 1,
            "tcp_flows": sum(
                flow.protocol == "TCP" for flow in flows
            ),
            "udp_flows": sum(
                flow.protocol == "UDP" for flow in flows
            ),
            "total_packets": sum(
                flow.packet_count for flow in flows
            ),
            "total_bytes": sum(
                flow.byte_count for flow in flows
            ),
            "forward_packets": sum(
                flow.forward_packets for flow in flows
            ),
            "backward_packets": sum(
                flow.backward_packets for flow in flows
            ),
            "forward_bytes": sum(
                flow.forward_bytes for flow in flows
            ),
            "backward_bytes": sum(
                flow.backward_bytes for flow in flows
            ),
            "tcp_states": states,
            "SYN_count": sum(flow.syn_count for flow in flows),
            "ACK_count": sum(flow.ack_count for flow in flows),
            "FIN_count": sum(flow.fin_count for flow in flows),
            "RST_count": sum(flow.rst_count for flow in flows),
        }

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

        self.expire_flows(float(event.timestamp))

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

        if (
            isinstance(event.application_protocol, str)
            and event.application_protocol
        ):
            flow.application_protocol = event.application_protocol

        if flow.protocol == "TCP":
            flags = (
                event.tcp_flags
                if isinstance(event.tcp_flags, str)
                else ""
            )

            flow.syn_count += int("S" in flags)
            flow.ack_count += int("A" in flags)
            flow.fin_count += int("F" in flags)
            flow.rst_count += int("R" in flags)

        payload_bytes = (
            event.payload_length
            if type(event.payload_length) is int
            and event.payload_length >= 0
            else 0
        )

        flow.packet_count += 1
        flow.byte_count += payload_bytes

        if event.flow_direction == "forward":
            flow.forward_packets += 1
            flow.forward_bytes += payload_bytes
        else:
            flow.backward_packets += 1
            flow.backward_bytes += payload_bytes

        event.flow_statistics = flow.to_dict()

        return event
