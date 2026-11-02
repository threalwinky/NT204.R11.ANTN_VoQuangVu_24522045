from collections.abc import Iterable
from copy import deepcopy
from dataclasses import asdict, dataclass

from ..models import NormalizedIDSEvent
from .evaluator import EvaluationResult, RuleMatch


@dataclass(frozen=True)
class DetectionEvent:

    timestamp: float
    packet_id: int

    # Snort rule information
    sid: int
    rev: int
    msg: str

    # Network information
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    network_protocol: str | None
    transport_protocol: str | None
    application_protocol: str | None

    # Flow information
    flow_id: str | None

    # Match information
    matched_info: dict[str, object]

    # Optional rule metadata
    classtype: str | None = None
    priority: int | None = None

    # Additional context
    flow_direction: str | None = None
    tcp_state: str | None = None

    action: str = "alert"
    record_type: str = "detection"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class DetectionEventGenerator:

    def _create_detection(
        self,
        event: NormalizedIDSEvent,
        match: RuleMatch,
    ) -> DetectionEvent:

        rule = match.rule

        if (
            type(rule.sid) is not int
            or rule.sid <= 0
            or type(rule.rev) is not int
            or rule.rev <= 0
            or not isinstance(rule.msg, str)
        ):
            raise ValueError(
                "matched rule requires valid sid, rev and msg"
            )

        return DetectionEvent(
            timestamp=event.timestamp,
            packet_id=event.packet_id,

            sid=rule.sid,
            rev=rule.rev,
            msg=rule.msg,

            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            src_port=event.src_port,
            dst_port=event.dst_port,
            network_protocol=event.network_protocol,
            transport_protocol=event.transport_protocol,
            application_protocol=event.application_protocol,

            flow_id=event.flow_id,

            matched_info=deepcopy(match.details),

            classtype=rule.classtype,
            priority=rule.priority,

            flow_direction=event.flow_direction,
            tcp_state=event.tcp_state,

            action=rule.header.action,
        )

    def generate(
        self,
        result: EvaluationResult,
    ) -> list[DetectionEvent]:

        return [
            self._create_detection(
                result.event,
                match,
            )
            for match in result.matches
        ]

    def generate_many(
        self,
        results: Iterable[EvaluationResult],
    ) -> list[DetectionEvent]:

        detections = []

        for result in results:
            detections.extend(
                self.generate(result)
            )

        return detections
