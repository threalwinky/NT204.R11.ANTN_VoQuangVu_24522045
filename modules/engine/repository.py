from collections.abc import Iterable

from ..models import NormalizedIDSEvent
from .models import SnortRule


def _port_matches(value: str, port: int) -> bool:
    if value.lower() == "any":
        return True

    if ":" in value:
        first, last = value.split(":", 1)
        start = int(first) if first else 0
        end = int(last) if last else 65535

        return start <= port <= end

    return int(value) == port


def _matches_ports(
    rule: SnortRule,
    src_port: int,
    dst_port: int,
) -> bool:
    header = rule.header

    forward = (
        _port_matches(header.src_port, src_port)
        and _port_matches(header.dst_port, dst_port)
    )

    if forward:
        return True

    return (
        header.direction == "<>"
        and _port_matches(header.dst_port, src_port)
        and _port_matches(header.src_port, dst_port)
    )


class RuleRepository:

    def __init__(self) -> None:
        self.rules: dict[int, SnortRule] = {}
        self._order: dict[int, int] = {}

        self._forward_exact: dict[
            tuple[str, int], set[int]
        ] = {}
        self._forward_flexible: dict[
            str, set[int]
        ] = {}

        self._reverse_exact: dict[
            tuple[str, int], set[int]
        ] = {}
        self._reverse_flexible: dict[
            str, set[int]
        ] = {}

    def _index_port(
        self,
        sid: int,
        protocol: str,
        port: str,
        reverse: bool = False,
    ) -> None:
        exact = (
            self._reverse_exact
            if reverse else self._forward_exact
        )

        flexible = (
            self._reverse_flexible
            if reverse else self._forward_flexible
        )

        if port.isascii() and port.isdecimal():
            exact.setdefault(
                (protocol, int(port)), set()
            ).add(sid)

        else:
            flexible.setdefault(
                protocol, set()
            ).add(sid)

    def add(self, rule: SnortRule) -> None:
        if not isinstance(rule, SnortRule):
            raise TypeError(
                "rule must be a SnortRule"
            )

        if type(rule.sid) is not int or rule.sid < 1:
            raise ValueError(
                "rule must have a positive SID"
            )

        if rule.sid in self.rules:
            raise ValueError(
                f"duplicate SID: {rule.sid}"
            )

        header = rule.header
        protocol = header.protocol.lower()

        if protocol not in ("tcp", "udp"):
            raise ValueError(
                f"unsupported protocol: {header.protocol}"
            )

        if header.direction not in ("->", "<>"):
            raise ValueError(
                f"invalid direction: {header.direction}"
            )

        self._order[rule.sid] = len(self._order)
        self.rules[rule.sid] = rule

        self._index_port(
            rule.sid,
            protocol,
            header.dst_port,
        )

        if header.direction == "<>":
            self._index_port(
                rule.sid,
                protocol,
                header.src_port,
                reverse=True,
            )

    def add_many(
        self,
        rules: Iterable[SnortRule],
    ) -> int:
        count = 0

        for rule in rules:
            self.add(rule)
            count += 1

        return count

    def get(
        self,
        sid: int,
    ) -> SnortRule | None:
        return self.rules.get(sid)

    def get_candidates(
        self,
        event: NormalizedIDSEvent,
    ) -> list[SnortRule]:
        protocol = event.transport_protocol
        src_port = event.src_port
        dst_port = event.dst_port

        if not isinstance(protocol, str):
            return []

        protocol = protocol.lower()

        if protocol not in ("tcp", "udp"):
            return []

        if not all(
            type(port) is int and 0 <= port <= 65535
            for port in (src_port, dst_port)
        ):
            return []

        candidates = set()

        candidates.update(
            self._forward_exact.get(
                (protocol, dst_port), ()
            )
        )

        candidates.update(
            self._forward_flexible.get(
                protocol, ()
            )
        )

        candidates.update(
            self._reverse_exact.get(
                (protocol, dst_port), ()
            )
        )

        candidates.update(
            self._reverse_flexible.get(
                protocol, ()
            )
        )

        return [
            self.rules[sid]
            for sid in sorted(
                candidates,
                key=self._order.__getitem__,
            )
            if _matches_ports(
                self.rules[sid],
                src_port,
                dst_port,
            )
        ]

    def clear(self) -> None:
        self.rules.clear()
        self._order.clear()

        self._forward_exact.clear()
        self._forward_flexible.clear()

        self._reverse_exact.clear()
        self._reverse_flexible.clear()

    def __len__(self) -> int:
        return len(self.rules)
