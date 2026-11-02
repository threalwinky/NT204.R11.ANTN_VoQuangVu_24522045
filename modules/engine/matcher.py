from ipaddress import IPv4Address, IPv4Network

from ..models import NormalizedIDSEvent
from .models import SnortRule


def _ip_matches(
    expression: str,
    address: str | None,
) -> bool:
    if not isinstance(address, str):
        return False

    try:
        ip = IPv4Address(address)

        if expression.lower() == "any":
            return True

        if "/" in expression:
            return ip in IPv4Network(
                expression,
                strict=False,
            )

        return ip == IPv4Address(expression)

    except ValueError:
        return False


def _port_matches(
    expression: str,
    port: int | None,
) -> bool:
    if type(port) is not int or not 0 <= port <= 65535:
        return False

    if expression.lower() == "any":
        return True

    try:
        if ":" in expression:
            first, last = expression.split(":", 1)
            start = int(first) if first else 0
            end = int(last) if last else 65535

            return start <= port <= end

        return int(expression) == port

    except ValueError:
        return False


def _endpoints_match(
    rule: SnortRule,
    event: NormalizedIDSEvent,
    reverse: bool = False,
) -> bool:
    header = rule.header

    if reverse:
        src_ip, dst_ip = header.dst_ip, header.src_ip
        src_port, dst_port = header.dst_port, header.src_port

    else:
        src_ip, dst_ip = header.src_ip, header.dst_ip
        src_port, dst_port = header.src_port, header.dst_port

    return (
        _ip_matches(src_ip, event.src_ip)
        and _ip_matches(dst_ip, event.dst_ip)
        and _port_matches(src_port, event.src_port)
        and _port_matches(dst_port, event.dst_port)
    )


def _get_flow_direction(
    event: NormalizedIDSEvent,
    context: dict[str, object] | None,
) -> str | None:
    if event.flow_direction in ("forward", "backward"):
        return event.flow_direction

    if not isinstance(context, dict):
        return None

    initiator = context.get("initiator")
    responder = context.get("responder")

    if not isinstance(initiator, dict):
        return None

    if not isinstance(responder, dict):
        return None

    src = (event.src_ip, event.src_port)
    dst = (event.dst_ip, event.dst_port)

    first = (
        initiator.get("ip"),
        initiator.get("port"),
    )

    second = (
        responder.get("ip"),
        responder.get("port"),
    )

    if src == first and dst == second:
        return "forward"

    if src == second and dst == first:
        return "backward"

    return None


def _get_tcp_state(
    event: NormalizedIDSEvent,
    context: dict[str, object] | None,
) -> str | None:
    if isinstance(event.tcp_state, str):
        return event.tcp_state.upper()

    if isinstance(context, dict):
        state = context.get("tcp_state")

        if isinstance(state, str):
            return state.upper()

    return None


class RuleMatcher:

    def match_header(
        self,
        rule: SnortRule,
        event: NormalizedIDSEvent,
    ) -> bool:
        if event.preprocess_status == "invalid":
            return False

        if event.network_protocol != "IPv4":
            return False

        if not isinstance(event.transport_protocol, str):
            return False

        if (
            event.transport_protocol.lower()
            != rule.header.protocol.lower()
        ):
            return False

        if _endpoints_match(rule, event):
            return True

        return (
            rule.header.direction == "<>"
            and _endpoints_match(
                rule,
                event,
                reverse=True,
            )
        )

    def match_flow(
        self,
        rule: SnortRule,
        event: NormalizedIDSEvent,
        flow_context: dict[str, object] | None = None,
    ) -> bool:
        flow_options = [
            option
            for option in rule.options
            if option.keyword == "flow"
        ]

        if not flow_options:
            return True

        context = (
            event.flow_statistics
            if flow_context is None
            else flow_context
        )

        if context is not None and not isinstance(context, dict):
            return False

        if isinstance(context, dict):
            context_id = context.get("flow_id")

            if (
                event.flow_id is not None
                and context_id is not None
                and event.flow_id != context_id
            ):
                return False

        for option in flow_options:
            if not isinstance(option.value, str):
                return False

            terms = {
                item.strip().lower()
                for item in option.value.split(",")
            }

            if not terms or "" in terms:
                return False

            if terms - {
                "to_server",
                "to_client",
                "established",
                "not_established",
            }:
                return False

            if "to_server" in terms or "to_client" in terms:
                direction = _get_flow_direction(
                    event,
                    context,
                )

                if (
                    "to_server" in terms
                    and direction != "forward"
                ):
                    return False

                if (
                    "to_client" in terms
                    and direction != "backward"
                ):
                    return False

            if (
                "established" in terms
                or "not_established" in terms
            ):
                if (
                    not isinstance(event.transport_protocol, str)
                    or event.transport_protocol.upper() != "TCP"
                ):
                    return False

                state = _get_tcp_state(
                    event,
                    context,
                )

                if (
                    "established" in terms
                    and state != "ESTABLISHED"
                ):
                    return False

                if (
                    "not_established" in terms
                    and state not in (
                        "NEW",
                        "HANDSHAKE",
                        "CLOSED",
                        "RESET",
                    )
                ):
                    return False

        return True

    def match_header_flow(
        self,
        rule: SnortRule,
        event: NormalizedIDSEvent,
        flow_context: dict[str, object] | None = None,
    ) -> bool:
        return (
            self.match_header(rule, event)
            and self.match_flow(
                rule,
                event,
                flow_context,
            )
        )
