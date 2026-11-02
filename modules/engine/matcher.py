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

    @staticmethod
    def _decode_content(value: str) -> bytes | None:
        pattern = bytearray()
        index = 0

        while index < len(value):
            char = value[index]

            if char == "\\":
                index += 1
                if index >= len(value):
                    return None
                char = value[index]

            elif char == "|":
                end = value.find("|", index + 1)
                if end < 0:
                    return None
                try:
                    pattern.extend(bytes.fromhex(value[index + 1:end]))
                except ValueError:
                    return None
                index = end + 1
                continue

            if ord(char) > 255:
                return None

            pattern.append(ord(char))
            index += 1

        return bytes(pattern) if pattern else None

    def _content_specs(self, rule: SnortRule) -> list[dict] | None:
        specs = []
        modifiers = {"nocase", "offset", "depth", "distance", "within"}

        for option in rule.options:
            if option.keyword == "content":
                if not isinstance(option.value, str):
                    return None

                pattern = self._decode_content(option.value)
                if not pattern:
                    return None

                specs.append({
                    "pattern": pattern,
                    "content": option.value,
                    "nocase": False,
                    "offset": None,
                    "depth": None,
                    "distance": None,
                    "within": None,
                    "seen": set(),
                })

            elif option.keyword in modifiers:
                if not specs:
                    return None

                current = specs[-1]
                if option.keyword in current["seen"]:
                    return None
                current["seen"].add(option.keyword)

                if option.keyword == "nocase":
                    if option.value is not None:
                        return None
                    current["nocase"] = True
                    continue

                value = option.value
                if (
                    not isinstance(value, str)
                    or not value.isascii()
                    or not value.isdecimal()
                ):
                    return None

                current[option.keyword] = int(value)

        for index, spec in enumerate(specs):
            absolute = spec["offset"] is not None or spec["depth"] is not None
            relative = spec["distance"] is not None or spec["within"] is not None

            if (absolute and relative) or (index == 0 and relative):
                return None

        return specs

    @staticmethod
    def _application_buffers(event: NormalizedIDSEvent):
        data = event.application_data
        if not isinstance(data, dict):
            return

        fields = (
            "decoded_uri", "normalized_uri", "uri",
            "decoded_body", "body", "normalized_domain", "domain",
            "mime_decoded_body", "command", "argument", "message",
        )

        for name in fields:
            value = data.get(name)
            if isinstance(value, str):
                yield f"application_data.{name}", value.encode("utf-8")

        for name in ("headers", "normalized_headers", "answer"):
            values = data.get(name)
            if isinstance(values, dict):
                for key, value in values.items():
                    if isinstance(value, str):
                        yield (
                            f"application_data.{name}.{key}",
                            value.encode("utf-8"),
                        )

        decoded_form = data.get("decoded_form")
        if isinstance(decoded_form, list):
            for index, item in enumerate(decoded_form):
                if not isinstance(item, dict):
                    continue
                for name in ("name", "value"):
                    value = item.get(name)
                    if isinstance(value, str):
                        yield (
                            f"application_data.decoded_form[{index}].{name}",
                            value.encode("utf-8"),
                        )

        mime_parts = data.get("mime_parts")
        if isinstance(mime_parts, list):
            for index, part in enumerate(mime_parts):
                if not isinstance(part, dict):
                    continue
                value = part.get("decoded_body")
                if isinstance(value, str):
                    yield (
                        f"application_data.mime_parts[{index}].decoded_body",
                        value.encode("utf-8"),
                    )

    @staticmethod
    def _search_contents(payload: bytes, specs: list[dict]):
        from functools import lru_cache

        @lru_cache(maxsize=4096)
        def search(index: int, previous_end: int):
            if index == len(specs):
                return ()

            spec = specs[index]
            pattern = spec["pattern"]
            relative = (
                spec["distance"] is not None
                or spec["within"] is not None
            )

            if relative:
                start = previous_end + (spec["distance"] or 0)
                limit = (
                    start + spec["within"]
                    if spec["within"] is not None
                    else len(payload)
                )
            else:
                start = spec["offset"] or 0
                limit = (
                    start + spec["depth"]
                    if spec["depth"] is not None
                    else len(payload)
                )

            start = max(0, start)
            limit = min(len(payload), limit)

            if limit - start < len(pattern):
                return None

            haystack = payload.lower() if spec["nocase"] else payload
            needle = pattern.lower() if spec["nocase"] else pattern
            position = start

            while position <= limit - len(pattern):
                found = haystack.find(needle, position, limit)
                if found < 0:
                    break

                end = found + len(pattern)
                remaining = search(index + 1, end)

                if remaining is not None:
                    return ((found, end),) + remaining

                position = found + 1

            return None

        return search(0, 0)

    def _match_contents(
        self,
        rule: SnortRule,
        event: NormalizedIDSEvent,
    ) -> dict[str, object] | None:
        specs = self._content_specs(rule)
        if specs is None:
            return None

        if not specs:
            return {"matched_field": None, "matched_content": []}

        buffers = []
        if isinstance(event.payload, bytes):
            buffers.append(("payload", event.payload))

        buffers.extend(self._application_buffers(event))

        for name, payload in buffers:
            positions = self._search_contents(payload, specs)
            if positions is None:
                continue

            return {
                "matched_field": name,
                "matched_content": [
                    {
                        "content": specs[index]["content"],
                        "start": start,
                        "end": end,
                    }
                    for index, (start, end) in enumerate(positions)
                ],
            }

        return None

    def match_content(
        self,
        rule: SnortRule,
        event: NormalizedIDSEvent,
    ) -> bool:
        return self._match_contents(rule, event) is not None

    def match_packet(
        self,
        rule: SnortRule,
        event: NormalizedIDSEvent,
    ) -> bool:
        for option in rule.options:
            if option.keyword == "flags":
                if (
                    event.transport_protocol != "TCP"
                    or not isinstance(event.tcp_flags, str)
                    or not isinstance(option.value, str)
                ):
                    return False

                actual = (
                    set() if event.tcp_flags == "0"
                    else set(event.tcp_flags.upper())
                )
                expected = (
                    set() if option.value == "0"
                    else set(option.value.upper())
                )

                if actual != expected:
                    return False

            elif option.keyword == "dsize":
                size = event.payload_length
                value = option.value

                if (
                    type(size) is not int
                    or size < 0
                    or not isinstance(value, str)
                ):
                    return False

                try:
                    if "<>" in value:
                        low, high = value.split("<>", 1)
                        matched = int(low) < size < int(high)
                    elif value.startswith(">"):
                        matched = size > int(value[1:])
                    elif value.startswith("<"):
                        matched = size < int(value[1:])
                    else:
                        matched = size == int(value)
                except ValueError:
                    return False

                if not matched:
                    return False

        return True

    def match_with_info(
        self,
        rule: SnortRule,
        event: NormalizedIDSEvent,
        flow_context: dict[str, object] | None = None,
    ) -> dict[str, object] | None:
        if not self.match_header_flow(rule, event, flow_context):
            return None

        if not self.match_packet(rule, event):
            return None

        details = self._match_contents(rule, event)
        if details is None:
            return None

        return details

    def match(
        self,
        rule: SnortRule,
        event: NormalizedIDSEvent,
        flow_context: dict[str, object] | None = None,
    ) -> bool:
        return self.match_with_info(rule, event, flow_context) is not None
