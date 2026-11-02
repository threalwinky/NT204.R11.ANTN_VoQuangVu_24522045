import re
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network

from .models import (
    RuleHeader,
    RuleOption,
    RuleSource,
    RuleValidationResult,
    SnortRule,
)


SUPPORTED_OPTIONS = {
    "msg", "sid", "rev", "content", "nocase", "offset", "depth",
    "distance", "within", "flags", "dsize", "flow", "classtype",
    "priority",
}

FLOW_KEYWORDS = {
    "to_server", "to_client", "established", "not_established",
}

SINGLE_OPTIONS = {
    "msg", "sid", "rev", "flags", "dsize", "flow", "classtype",
    "priority",
}


class UnsupportedRuleError(ValueError):
    pass


def _split_options(text: str) -> list[str]:
    parts = []
    current = []
    quoted = False
    escaped = False

    for char in text:
        if escaped:
            current.append(char)
            escaped = False

        elif char == "\\" and quoted:
            current.append(char)
            escaped = True

        elif char == '"':
            quoted = not quoted
            current.append(char)

        elif char == ";" and not quoted:
            option = "".join(current).strip()

            if not option:
                raise ValueError("empty rule option")

            parts.append(option)
            current = []

        else:
            current.append(char)

    if quoted or escaped:
        raise ValueError("unterminated quoted option")

    if "".join(current).strip() or not text.rstrip().endswith(";"):
        raise ValueError("rule options must end with ';'")

    if not parts:
        raise ValueError("missing rule options")

    return parts


def _quoted_value(text: str, name: str) -> str:
    if not re.fullmatch(r'"(?:\\.|[^"\\])*"', text):
        raise ValueError(f"{name} requires a quoted value")

    return text[1:-1]


def _positive_int(
    text: str,
    name: str,
    allow_zero: bool = False,
) -> int:

    if not text.isascii() or not text.isdecimal():
        raise ValueError(f"{name} must be an integer")

    number = int(text)

    if number < (0 if allow_zero else 1):
        raise ValueError(f"{name} must be positive")

    return number


def _validate_ip(value: str) -> None:
    if value.lower() == "any":
        return

    if value.startswith(("!", "$", "[")):
        raise UnsupportedRuleError(
            f"unsupported IP expression: {value}"
        )

    try:
        if "/" in value:
            IPv4Network(value, strict=False)
        else:
            IPv4Address(value)

    except ValueError as error:
        raise ValueError(
            f"invalid IPv4 address/CIDR: {value}"
        ) from error


def _validate_port(value: str) -> None:
    if value.lower() == "any":
        return

    if value.startswith(("!", "$", "[")):
        raise UnsupportedRuleError(
            f"unsupported port expression: {value}"
        )

    if ":" not in value:
        port = _positive_int(
            value, "port", allow_zero=True
        )

        if port > 65535:
            raise ValueError("port outside 0..65535")

        return

    if value.count(":") != 1:
        raise ValueError(f"invalid port range: {value}")

    first, last = value.split(":")

    if not first and not last:
        raise ValueError("empty port range")

    start = (
        _positive_int(first, "port", True)
        if first else 0
    )

    end = (
        _positive_int(last, "port", True)
        if last else 65535
    )

    if start > end or end > 65535:
        raise ValueError(f"invalid port range: {value}")


def _parse_header(text: str) -> RuleHeader:
    fields = text.split()

    if len(fields) != 7:
        raise ValueError(
            "Snort header requires exactly 7 fields"
        )

    action, protocol, src_ip, src_port, direction, dst_ip, dst_port = fields

    action = action.lower()
    protocol = protocol.lower()

    if action != "alert":
        raise UnsupportedRuleError(
            f"unsupported rule action: {action}"
        )

    if protocol not in ("tcp", "udp"):
        raise UnsupportedRuleError(
            f"unsupported protocol: {protocol}"
        )

    if direction not in ("->", "<>"):
        raise ValueError(
            f"invalid direction: {direction}"
        )

    _validate_ip(src_ip)
    _validate_ip(dst_ip)
    _validate_port(src_port)
    _validate_port(dst_port)

    return RuleHeader(
        action=action,
        protocol=protocol,
        src_ip=src_ip,
        src_port=src_port,
        direction=direction,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )


def _validate_dsize(value: str) -> None:
    if re.fullmatch(
        r"(?:[<>]?\d+|\d+<>\d+)", value
    ) is None:
        raise UnsupportedRuleError(
            f"unsupported dsize expression: {value}"
        )

    if "<>" in value:
        low, high = value.split("<>")

        if int(low) >= int(high):
            raise ValueError("invalid dsize range")


def _validate_content(value: str) -> None:
    index = 0

    while index < len(value):
        if value[index] == "\\":
            index += 2

            if index > len(value):
                raise ValueError("incomplete content escape")

        elif value[index] == "|":
            end = value.find("|", index + 1)

            if end == -1:
                raise ValueError("unterminated content hex block")

            hex_data = "".join(
                value[index + 1:end].split()
            )

            if (
                not hex_data
                or re.fullmatch(
                    r"[0-9A-Fa-f]+", hex_data
                ) is None
            ):
                raise ValueError("invalid content hex block")

            if len(hex_data) % 2:
                raise ValueError(
                    "content hex block requires full bytes"
                )

            index = end + 1

        else:
            index += 1


def _parse_options(
    text: str,
) -> tuple[list[RuleOption], dict[str, object]]:

    options = []
    fields = {}
    seen = set()
    has_content = False

    for fragment in _split_options(text):
        keyword, separator, raw_value = fragment.partition(":")

        keyword = keyword.strip().lower()
        value = raw_value.strip() if separator else None

        if not re.fullmatch(
            r"[a-z_][a-z_0-9]*", keyword
        ):
            raise ValueError(
                f"invalid option keyword: {keyword}"
            )

        if keyword not in SUPPORTED_OPTIONS:
            raise UnsupportedRuleError(
                f"unsupported keyword: {keyword}"
            )

        if keyword in SINGLE_OPTIONS and keyword in seen:
            raise ValueError(
                f"duplicate option: {keyword}"
            )

        seen.add(keyword)

        if keyword == "nocase":
            if value is not None:
                raise ValueError(
                    "nocase does not take a value"
                )

            if not has_content:
                raise ValueError(
                    "nocase requires preceding content"
                )

        else:
            if not value:
                raise ValueError(
                    f"{keyword} requires a value"
                )

            if keyword == "content":
                if value.startswith("!"):
                    raise UnsupportedRuleError(
                        "negated content is unsupported"
                    )

                value = _quoted_value(value, keyword)

                if not value:
                    raise ValueError(
                        "content must not be empty"
                    )

                _validate_content(value)
                has_content = True

            elif keyword == "msg":
                value = _quoted_value(value, keyword)

                fields["msg"] = re.sub(
                    r'\\(["\\])', r'\1', value
                )

            elif keyword in ("sid", "rev", "priority"):
                fields[keyword] = _positive_int(
                    value, keyword
                )

            elif keyword == "classtype":
                if not re.fullmatch(
                    r"[a-zA-Z0-9_-]+", value
                ):
                    raise ValueError("invalid classtype")

                fields["classtype"] = value

            elif keyword in (
                "offset", "depth", "distance", "within"
            ):
                if not has_content:
                    raise ValueError(
                        f"{keyword} requires preceding content"
                    )

                _positive_int(
                    value, keyword, allow_zero=True
                )

            elif keyword == "flags":
                if value == "0":
                    pass

                elif re.fullmatch(
                    r"[FSRPAUECfsrpauec]+", value
                ):
                    if len(set(value.upper())) != len(value):
                        raise ValueError(
                            "duplicate TCP flags"
                        )

                else:
                    raise UnsupportedRuleError(
                        f"unsupported flags expression: {value}"
                    )

            elif keyword == "dsize":
                _validate_dsize(value)

            elif keyword == "flow":
                terms = [
                    part.strip().lower()
                    for part in value.split(",")
                ]

                if not all(terms):
                    raise ValueError(
                        "empty flow keyword"
                    )

                unsupported = set(terms) - FLOW_KEYWORDS

                if unsupported:
                    raise UnsupportedRuleError(
                        "unsupported flow keyword: "
                        f"{sorted(unsupported)[0]}"
                    )

                if len(set(terms)) != len(terms):
                    raise ValueError(
                        "duplicate flow keyword"
                    )

                if {"to_server", "to_client"} <= set(terms):
                    raise ValueError(
                        "conflicting flow directions"
                    )

                if {
                    "established", "not_established"
                } <= set(terms):
                    raise ValueError(
                        "conflicting flow states"
                    )

        options.append(
            RuleOption(keyword=keyword, value=value)
        )

    for name in ("sid", "rev", "msg"):
        if name not in fields:
            raise ValueError(
                f"missing required option: {name}"
            )

    return options, fields


class RuleParser:

    def parse(
        self,
        source: RuleSource,
    ) -> RuleValidationResult:

        try:
            match = re.fullmatch(
                r"\s*(.*?)\s*\((.*)\)\s*",
                source.text,
            )

            if match is None:
                raise ValueError(
                    "invalid rule syntax: missing header/options"
                )

            header = _parse_header(match.group(1))
            options, fields = _parse_options(match.group(2))

            rule = SnortRule(
                source=source,
                header=header,
                options=options,
                **fields,
            )

            return RuleValidationResult(
                source=source,
                status="valid",
                rule=rule,
            )

        except UnsupportedRuleError as error:
            return RuleValidationResult(
                source=source,
                status="unsupported",
                reason=str(error),
            )

        except ValueError as error:
            return RuleValidationResult(
                source=source,
                status="invalid",
                reason=str(error),
            )

    def parse_many(
        self,
        sources: Iterable[RuleSource],
    ) -> list[RuleValidationResult]:

        return [
            self.parse(source)
            for source in sources
        ]
