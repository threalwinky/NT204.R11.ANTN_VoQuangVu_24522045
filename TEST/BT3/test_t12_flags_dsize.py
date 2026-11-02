"""BT3 T12: packet-level Snort flags and dsize matching.

Expectations describe the current RuleParser / RuleMatcher implementation:
flags compare sets of TCP flag letters; dsize uses event.payload_length.
"""

from pathlib import Path

import pytest

from modules.engine import (
    DetectionEventGenerator,
    RuleEvaluationEngine,
    RuleMatcher,
    RuleParser,
    RuleRepository,
    RuleSource,
)
from modules.models import NormalizedIDSEvent


TCP_HEADER = "alert tcp any any -> any 80"
UDP_HEADER = "alert udp any any -> any 53"


def make_rule(options, sid=12101, header=TCP_HEADER):
    source = RuleSource(
        path=Path("t12.rules"),
        line_number=sid,
        text=(
            f'{header} (msg:"T12 Packet"; '
            f'sid:{sid}; rev:1; {options})'
        ),
    )
    result = RuleParser().parse(source)
    assert result.status == "valid", result.reason
    assert result.rule is not None
    return result.rule


def make_event(payload=b"ABCD", payload_length=None, **changes):
    fields = {
        "packet_id": 1,
        "timestamp": 1000.0,
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.20",
        "src_port": 50000,
        "dst_port": 80,
        "tcp_flags": "S",
        "payload": payload,
        "payload_length": (
            len(payload) if payload_length is None else payload_length
        ),
    }
    fields.update(changes)
    return NormalizedIDSEvent(**fields)


@pytest.mark.parametrize(
    ("flags", "actual", "expected"),
    [
        pytest.param("S", "S", True, id="syn"),
        pytest.param("S", "s", True, id="syn-lowercase-event"),
        pytest.param("s", "S", True, id="syn-lowercase-rule"),
        pytest.param("A", "A", True, id="ack"),
        pytest.param("A", "a", True, id="ack-lowercase-event"),
        pytest.param("A", "S", False, id="ack-not-syn"),
        pytest.param("SA", "SA", True, id="syn-ack"),
        pytest.param("SA", "AS", True, id="flag-order-independent"),
        pytest.param("sa", "As", True, id="flag-case-independent"),
        pytest.param("SA", "S", False, id="missing-ack"),
        pytest.param("SA", "A", False, id="missing-syn"),
        pytest.param("SA", "SAR", False, id="extra-rst"),
        pytest.param("SA", "SAE", False, id="extra-ece"),
        pytest.param("F", "F", True, id="fin"),
        pytest.param("R", "R", True, id="rst"),
        pytest.param("P", "P", True, id="psh"),
        pytest.param("U", "U", True, id="urg"),
        pytest.param("E", "E", True, id="ece"),
        pytest.param("C", "C", True, id="cwr"),
        pytest.param("0", "0", True, id="no-flags"),
        pytest.param("0", "S", False, id="unexpected-syn"),
        pytest.param("S", "0", False, id="missing-all-flags"),
        pytest.param("S", None, False, id="missing-tcp-flags"),
        pytest.param("S", 1, False, id="nonstring-tcp-flags"),
        pytest.param("S", "", False, id="empty-event-flags"),
        pytest.param("FS", "FS", True, id="fin-syn"),
        pytest.param("FS", "SF", True, id="fin-syn-reordered"),
        pytest.param("FSRPAUEC", "FSRPAUEC", True, id="all-supported-flags"),
        pytest.param("FSRPAUEC", "CPRSAUEF", True, id="all-flags-reordered"),
        pytest.param("S", "SS", True, id="event-repeated-flag-treated-as-set"),
    ],
)
def test_t12_tcp_flag_matrix(flags, actual, expected):
    rule = make_rule(f"flags:{flags};")
    event = make_event(tcp_flags=actual)
    matcher = RuleMatcher()
    assert matcher.match_packet(rule, event) is expected
    assert matcher.match(rule, event) is expected


@pytest.mark.parametrize(
    ("expression", "size", "expected"),
    [
        pytest.param("0", 0, True, id="exact-zero"),
        pytest.param("0", 1, False, id="exact-zero-mismatch"),
        pytest.param("1", 1, True, id="exact-one"),
        pytest.param("1", 0, False, id="exact-one-mismatch"),
        pytest.param("10", 10, True, id="exact-ten"),
        pytest.param("10", 9, False, id="exact-ten-below"),
        pytest.param("10", 11, False, id="exact-ten-above"),
        pytest.param(">10", 10, False, id="greater-strict-boundary"),
        pytest.param(">10", 11, True, id="greater-one-above"),
        pytest.param(">10", 100, True, id="greater-far-above"),
        pytest.param(">10", 0, False, id="greater-zero"),
        pytest.param("<10", 9, True, id="less-one-below"),
        pytest.param("<10", 10, False, id="less-strict-boundary"),
        pytest.param("<10", 0, True, id="less-zero"),
        pytest.param("<10", 11, False, id="less-above"),
        pytest.param("10<>20", 9, False, id="range-below"),
        pytest.param("10<>20", 10, False, id="range-exclusive-lower"),
        pytest.param("10<>20", 11, True, id="range-first-interior"),
        pytest.param("10<>20", 15, True, id="range-middle"),
        pytest.param("10<>20", 19, True, id="range-last-interior"),
        pytest.param("10<>20", 20, False, id="range-exclusive-upper"),
        pytest.param("10<>20", 21, False, id="range-above"),
        pytest.param("0<>2", 0, False, id="range-zero-lower"),
        pytest.param("0<>2", 1, True, id="range-one-byte-interior"),
        pytest.param("0<>2", 2, False, id="range-two-upper"),
        pytest.param(">0", 0, False, id="greater-zero-boundary"),
        pytest.param(">0", 1, True, id="greater-zero-one-byte"),
        pytest.param("<1", 0, True, id="less-one-zero-byte"),
        pytest.param("<1", 1, False, id="less-one-boundary"),
        pytest.param("0010", 10, True, id="leading-zero"),
        pytest.param("0<>100", 50, True, id="large-open-range"),
        pytest.param("65535", 65535, True, id="large-exact-payload-size"),
    ],
)
def test_t12_dsize_matrix(expression, size, expected):
    rule = make_rule(f"dsize:{expression};")
    # payload_length is the source of truth, not len(payload).
    event = make_event(payload=b"abc", payload_length=size)
    matcher = RuleMatcher()
    assert matcher.match_packet(rule, event) is expected
    assert matcher.match(rule, event) is expected


@pytest.mark.parametrize(
    ("options", "expected_status", "expected_reason"),
    [
        pytest.param("flags:SS;", "invalid", "duplicate TCP flags", id="duplicate-flags"),
        pytest.param("flags:Ss;", "invalid", "duplicate TCP flags", id="duplicate-flags-different-case"),
        pytest.param("flags:S; flags:A;", "invalid", "duplicate option: flags", id="repeated-flags-option"),
        pytest.param("flags:+S;", "unsupported", "unsupported flags expression", id="flags-plus"),
        pytest.param("flags:!S;", "unsupported", "unsupported flags expression", id="flags-negation"),
        pytest.param("flags:X;", "unsupported", "unsupported flags expression", id="flags-unrecognized-character"),
        pytest.param("flags:1;", "unsupported", "unsupported flags expression", id="flags-one-not-zero"),
        pytest.param("flags:;", "invalid", "flags requires a value", id="flags-empty"),
        pytest.param("dsize:10<>10;", "invalid", "invalid dsize range", id="empty-dsize-range"),
        pytest.param("dsize:20<>10;", "invalid", "invalid dsize range", id="inverted-dsize-range"),
        pytest.param("dsize:>=10;", "unsupported", "unsupported dsize expression", id="greater-equal-unsupported"),
        pytest.param("dsize:<=10;", "unsupported", "unsupported dsize expression", id="less-equal-unsupported"),
        pytest.param("dsize:10-20;", "unsupported", "unsupported dsize expression", id="dash-range-unsupported"),
        pytest.param("dsize:abc;", "unsupported", "unsupported dsize expression", id="nonnumeric-dsize"),
        pytest.param("dsize:-1;", "unsupported", "unsupported dsize expression", id="negative-dsize"),
        pytest.param("dsize:;", "invalid", "dsize requires a value", id="empty-dsize"),
        pytest.param("dsize:10; dsize:11;", "invalid", "duplicate option: dsize", id="repeated-dsize-option"),
    ],
)
def test_t12_parser_rejects_bad_packet_options(options, expected_status, expected_reason):
    source = RuleSource(
        path=Path("t12_invalid.rules"),
        line_number=1,
        text=(
            f'{TCP_HEADER} (msg:"T12 Invalid"; '
            f'sid:12999; rev:1; {options})'
        ),
    )
    parsed = RuleParser().parse(source)
    assert parsed.status == expected_status
    assert parsed.rule is None
    assert parsed.reason is not None
    assert expected_reason in parsed.reason


@pytest.mark.parametrize(
    ("flags", "size", "protocol", "expected"),
    [
        pytest.param("SA", 4, "TCP", True, id="both-conditions-match"),
        pytest.param("AS", 4, "TCP", True, id="flags-order-independent"),
        pytest.param("S", 4, "TCP", False, id="missing-ack"),
        pytest.param("SAR", 4, "TCP", False, id="unexpected-rst"),
        pytest.param("SA", 3, "TCP", False, id="size-below"),
        pytest.param("SA", 5, "TCP", False, id="size-above"),
        pytest.param(None, 4, "TCP", False, id="missing-flags"),
        pytest.param("SA", 4, "UDP", False, id="flags-require-tcp"),
    ],
)
def test_t12_combined_flags_and_dsize(flags, size, protocol, expected):
    rule = make_rule("flags:SA; dsize:4;")
    event = make_event(
        payload_length=size,
        tcp_flags=flags,
        transport_protocol=protocol,
    )
    matcher = RuleMatcher()
    assert matcher.match_packet(rule, event) is expected
    assert matcher.match(rule, event) is expected


@pytest.mark.parametrize(
    "bad_size",
    [
        pytest.param(-1, id="negative-payload-length"),
        pytest.param(None, id="missing-payload-length"),
        pytest.param("4", id="string-payload-length"),
        pytest.param(4.0, id="float-payload-length"),
        pytest.param(True, id="boolean-payload-length"),
    ],
)
def test_t12_dsize_rejects_invalid_event_size(bad_size):
    rule = make_rule("dsize:4;")
    event = make_event(payload_length=4)
    event.payload_length = bad_size
    assert not RuleMatcher().match_packet(rule, event)
    assert RuleMatcher().match_with_info(rule, event) is None


def test_t12_no_packet_options_matches_packet():
    rule = make_rule('content:"AB";')
    event = make_event()
    matcher = RuleMatcher()
    assert matcher.match_packet(rule, event)
    assert matcher.match_with_info(rule, event) == {
        "matched_field": "payload",
        "matched_content": [{"content": "AB", "start": 0, "end": 2}],
    }


def test_t12_udp_dsize_without_flags():
    rule = make_rule("dsize:>3;", header=UDP_HEADER)
    event = make_event(transport_protocol="UDP", dst_port=53, payload_length=4)
    assert RuleMatcher().match_packet(rule, event)
    assert RuleMatcher().match(rule, event)
    event.payload_length = 3
    assert not RuleMatcher().match(rule, event)


def test_t12_dsize_uses_declared_length_not_payload_bytes():
    rule = make_rule("dsize:4;")
    matcher = RuleMatcher()
    short_declared = make_event(payload=b"A" * 100, payload_length=4)
    long_declared = make_event(payload=b"ABCD", payload_length=100)
    assert matcher.match_packet(rule, short_declared)
    assert not matcher.match_packet(rule, long_declared)


def test_t12_flags_not_allowed_on_udp():
    rule = make_rule("flags:S;", header=UDP_HEADER)
    event = make_event(transport_protocol="UDP", dst_port=53, tcp_flags="S")
    assert RuleMatcher().match_header(rule, event)
    assert not RuleMatcher().match_packet(rule, event)
    assert not RuleMatcher().match(rule, event)


def test_t12_evaluator_and_detection_details():
    repo = RuleRepository()
    repo.add_many([
        make_rule("flags:S; dsize:>5;", sid=12201),
        make_rule("flags:A; dsize:8;", sid=12202),
        make_rule("flags:S; dsize:8;", sid=12203),
        make_rule("dsize:7<>10;", sid=12204),
        make_rule("dsize:<8;", sid=12205),
        make_rule('content:"AB"; flags:S; dsize:8;', sid=12206),
        make_rule(
            "flags:S; dsize:8;", sid=12207,
            header="alert tcp any any -> any 443",
        ),
        make_rule("dsize:8;", sid=12208, header="alert udp any any -> any 80"),
    ])
    engine = RuleEvaluationEngine(repo)
    event = make_event(payload=b"ABxxxxxx", tcp_flags="S")
    result = engine.evaluate(event)
    assert result.status == "MATCH"
    assert result.candidate_count == 6
    assert result.matched_sids == [12201, 12203, 12204, 12206]
    assert result.match_count == 4
    assert result.matches[-1].details == {
        "matched_field": "payload",
        "matched_content": [{"content": "AB", "start": 0, "end": 2}],
    }
    second = engine.evaluate(make_event(payload=b"ABxxxxxx", tcp_flags="A"))
    assert second.matched_sids == [12202, 12204]
    assert engine.get_stats() == {
        "events_evaluated": 2,
        "candidate_rules": 12,
        "match_count": 6,
        "matched_events": 2,
    }
    detections = DetectionEventGenerator().generate(result)
    assert [item.sid for item in detections] == [12201, 12203, 12204, 12206]
    assert [item.matched_info for item in detections] == [
        match.details for match in result.matches
    ]


def test_t12_header_rejection_not_bypassed_by_packet_match():
    rule = make_rule("flags:S; dsize:4;")
    event = make_event(dst_port=443)
    matcher = RuleMatcher()
    assert matcher.match_packet(rule, event)
    assert not matcher.match_header(rule, event)
    assert matcher.match_with_info(rule, event) is None
