"""BT3 T10: Snort content offset/depth absolute search windows."""

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


HEADER = "alert tcp any any -> any 80"
PAYLOAD = b"XXGETYYGET"


def make_rule(options, sid=10001, header=HEADER):
    source = RuleSource(
        path=Path("t10.rules"),
        line_number=sid,
        text=(
            f'{header} (msg:"T10 Offset Depth"; '
            f'sid:{sid}; rev:1; {options})'
        ),
    )
    result = RuleParser().parse(source)
    assert result.status == "valid", result.reason
    assert result.rule is not None
    return result.rule


def make_event(payload=PAYLOAD, application_data=None, **changes):
    fields = {
        "packet_id": 1,
        "timestamp": 1000.0,
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.20",
        "src_port": 50000,
        "dst_port": 80,
        "payload": payload,
        "payload_length": len(payload),
        "application_data": (
            {} if application_data is None else application_data
        ),
    }
    fields.update(changes)
    return NormalizedIDSEvent(**fields)


@pytest.mark.parametrize(
    ("options", "payload", "expected"),
    [
        pytest.param('content:"GET"; offset:2; depth:3;', PAYLOAD, (2, 5, "GET"), id="exact-window"),
        pytest.param('content:"GET"; offset:2; depth:4;', PAYLOAD, (2, 5, "GET"), id="window-with-slack"),
        pytest.param('content:"GET"; offset:2; depth:2;', PAYLOAD, None, id="depth-too-short"),
        pytest.param('content:"GET"; offset:3; depth:3;', PAYLOAD, None, id="offset-past-first-match"),
        pytest.param('content:"GET"; offset:3; depth:5;', PAYLOAD, None, id="window-excludes-both-matches"),
        pytest.param('content:"GET"; offset:5; depth:5;', PAYLOAD, (7, 10, "GET"), id="second-match"),
        pytest.param('content:"GET"; offset:6; depth:4;', PAYLOAD, (7, 10, "GET"), id="second-match-at-right-edge"),
        pytest.param('content:"GET"; offset:6; depth:3;', PAYLOAD, None, id="second-match-truncated"),
        pytest.param('content:"GET"; offset:7; depth:3;', PAYLOAD, (7, 10, "GET"), id="second-match-exact-window"),
        pytest.param('content:"GET"; offset:8; depth:5;', PAYLOAD, None, id="offset-inside-second-match"),
        pytest.param('content:"GET"; offset:0; depth:5;', PAYLOAD, (2, 5, "GET"), id="depth-covers-first-match"),
        pytest.param('content:"GET"; offset:0; depth:4;', PAYLOAD, None, id="depth-ends-before-match-completes"),
        pytest.param('content:"GET"; depth:5;', PAYLOAD, (2, 5, "GET"), id="depth-only-boundary"),
        pytest.param('content:"GET"; depth:4;', PAYLOAD, None, id="depth-only-short"),
        pytest.param('content:"GET"; depth:10;', PAYLOAD, (2, 5, "GET"), id="depth-only-full-payload"),
        pytest.param('content:"GET"; depth:0;', PAYLOAD, None, id="zero-depth"),
        pytest.param('content:"GET"; offset:0; depth:0;', PAYLOAD, None, id="zero-offset-and-depth"),
        pytest.param('content:"GET"; offset:2;', PAYLOAD, (2, 5, "GET"), id="offset-only-first-match"),
        pytest.param('content:"GET"; offset:7;', PAYLOAD, (7, 10, "GET"), id="offset-only-second-match"),
        pytest.param('content:"GET"; offset:8;', PAYLOAD, None, id="offset-only-past-last-start"),
        pytest.param('content:"GET"; offset:10;', PAYLOAD, None, id="offset-at-payload-end"),
        pytest.param('content:"GET"; offset:20;', PAYLOAD, None, id="offset-beyond-payload"),
        pytest.param('content:"GET";', PAYLOAD, (2, 5, "GET"), id="unrestricted-first-match"),
        pytest.param('content:"YYGET"; offset:5; depth:5;', PAYLOAD, (5, 10, "YYGET"), id="long-pattern-exact-depth"),
        pytest.param('content:"get"; nocase; offset:2; depth:3;', PAYLOAD, (2, 5, "get"), id="nocase-first-match"),
        pytest.param('content:"get"; offset:7; depth:3; nocase;', PAYLOAD, (7, 10, "get"), id="nocase-modifier-order"),
        pytest.param('content:"get"; nocase; offset:3; depth:3;', PAYLOAD, None, id="nocase-cannot-bypass-window"),
        pytest.param('content:"GET"; offset:2; depth:3;', b"xxgetyyget", None, id="case-sensitive-mismatch"),
        pytest.param('content:"get"; offset:2; depth:3;', b"xxgetyyget", (2, 5, "get"), id="lowercase-exact-match"),
        pytest.param('content:"|00 FF|"; offset:2; depth:2;', b"XX\x00\xffYY", (2, 4, "|00 FF|"), id="binary-pattern-window"),
        pytest.param('content:"|00 FF|"; offset:2; depth:1;', b"XX\x00\xffYY", None, id="binary-pattern-too-short"),
        pytest.param('content:"|00 FF|"; offset:1; depth:3;', b"XX\x00\xffYY", (2, 4, "|00 FF|"), id="binary-pattern-at-right-edge"),
        pytest.param('content:"GET"; offset:2; depth:3;', b"\xc3\xa9GET", (2, 5, "GET"), id="utf8-prefix-counted-as-two-bytes"),
        pytest.param('content:"GET"; offset:1; depth:3;', b"\xc3\xa9GET", None, id="utf8-prefix-window-too-short"),
        pytest.param('content:"GET"; offset:0; depth:3;', b"GET", (0, 3, "GET"), id="whole-payload"),
        pytest.param('content:"GET"; offset:0; depth:2;', b"GET", None, id="whole-payload-one-byte-short"),
        pytest.param('content:"GET"; offset:0; depth:3;', b"", None, id="empty-payload"),
        pytest.param('content:"GET"; offset:0; depth:200;', b"GET", (0, 3, "GET"), id="depth-beyond-buffer-clamped"),
    ],
)
def test_t10_absolute_window_matrix(options, payload, expected):
    rule = make_rule(options)
    event = make_event(payload)
    matcher = RuleMatcher()
    details = matcher.match_with_info(rule, event)

    assert matcher.match_content(rule, event) is (expected is not None)
    assert matcher.match(rule, event) is (expected is not None)

    if expected is None:
        assert details is None
    else:
        start, end, content = expected
        assert details == {
            "matched_field": "payload",
            "matched_content": [
                {"content": content, "start": start, "end": end}
            ],
        }


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        pytest.param('offset:0; content:"GET";', "offset requires preceding content", id="offset-before-content"),
        pytest.param('depth:3; content:"GET";', "depth requires preceding content", id="depth-before-content"),
        pytest.param('content:"GET"; offset:-1;', "offset must be an integer", id="negative-offset"),
        pytest.param('content:"GET"; depth:-1;', "depth must be an integer", id="negative-depth"),
        pytest.param('content:"GET"; offset:abc;', "offset must be an integer", id="nonnumeric-offset"),
        pytest.param('content:"GET"; depth:abc;', "depth must be an integer", id="nonnumeric-depth"),
        pytest.param('content:"GET"; offset:;', "offset requires a value", id="empty-offset"),
        pytest.param('content:"GET"; depth:;', "depth requires a value", id="empty-depth"),
    ],
)
def test_t10_parser_rejects_invalid_modifier(options, reason):
    source = RuleSource(
        path=Path("t10_invalid.rules"),
        line_number=1,
        text=(
            f'{HEADER} (msg:"T10 Invalid"; sid:10999; '
            f'rev:1; {options})'
        ),
    )
    result = RuleParser().parse(source)
    assert result.status == "invalid"
    assert result.rule is None
    assert reason in result.reason


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        pytest.param(
            'content:"GET"; offset:2; depth:3; '
            'content:"YY"; offset:5; depth:2;',
            [("GET", 2, 5), ("YY", 5, 7)],
            id="separate-absolute-windows",
        ),
        pytest.param(
            'content:"GET"; offset:7; depth:3; '
            'content:"YY"; offset:5; depth:2;',
            [("GET", 7, 10), ("YY", 5, 7)],
            id="absolute-windows-do-not-require-order",
        ),
        pytest.param(
            'content:"GET"; offset:2; depth:3; '
            'content:"YY"; offset:4; depth:2;',
            None,
            id="second-window-misses-content",
        ),
        pytest.param(
            'content:"GET"; offset:2; depth:3; '
            'content:"YY"; offset:5; depth:1;',
            None,
            id="second-window-too-short",
        ),
        pytest.param(
            'content:"GET"; offset:2; depth:3; '
            'content:"yy"; nocase; offset:5; depth:2;',
            [("GET", 2, 5), ("yy", 5, 7)],
            id="nocase-modifies-second-content-only",
        ),
    ],
)
def test_t10_multiple_content_windows(options, expected):
    matcher = RuleMatcher()
    rule = make_rule(options)
    event = make_event()
    details = matcher.match_with_info(rule, event)

    if expected is None:
        assert details is None
    else:
        assert details == {
            "matched_field": "payload",
            "matched_content": [
                {"content": text, "start": start, "end": end}
                for text, start, end in expected
            ],
        }


@pytest.mark.parametrize(
    ("payload", "application_data", "expected_field", "expected_span"),
    [
        pytest.param(
            b"XXPOST", {"uri": "XXGETYY"},
            "application_data.uri", (2, 5),
            id="fallback-to-uri",
        ),
        pytest.param(
            b"XXXGET", {"uri": "XXGETYY"},
            "application_data.uri", (2, 5),
            id="payload-match-outside-window-falls-back",
        ),
        pytest.param(
            b"", {"uri": "\u00e9GET"},
            "application_data.uri", (2, 5),
            id="application-utf8-byte-offset",
        ),
        pytest.param(
            b"XXGETYY", {"uri": "XXGETYY"},
            "payload", (2, 5),
            id="payload-priority",
        ),
        pytest.param(
            b"", {"decoded_uri": "XXGET", "uri": "XXGET"},
            "application_data.decoded_uri", (2, 5),
            id="decoded-uri-priority",
        ),
        pytest.param(
            b"XXPOST", {"uri": "GE"},
            None, None,
            id="no-buffer-satisfies-window",
        ),
    ],
)
def test_t10_application_buffer_windows(
    payload, application_data, expected_field, expected_span
):
    rule = make_rule('content:"GET"; offset:2; depth:3;')
    event = make_event(payload, application_data=application_data)
    details = RuleMatcher().match_with_info(rule, event)

    if expected_field is None:
        assert details is None
    else:
        assert details == {
            "matched_field": expected_field,
            "matched_content": [
                {"content": "GET", "start": expected_span[0], "end": expected_span[1]}
            ],
        }


def test_t10_duplicate_modifier_is_rejected_at_match_time():
    # The parser accepts repeated offset/depth, but matcher must fail closed.
    rule = make_rule('content:"GET"; offset:2; offset:7; depth:3;')
    event = make_event()
    matcher = RuleMatcher()
    assert not matcher.match_content(rule, event)
    assert matcher.match_with_info(rule, event) is None


def test_t10_evaluator_and_detection_details():
    repository = RuleRepository()
    repository.add_many([
        make_rule('content:"GET"; offset:2; depth:3;', sid=10201),
        make_rule('content:"GET"; offset:3; depth:3;', sid=10202),
        make_rule('content:"get"; nocase; offset:7; depth:3;', sid=10203),
        make_rule('content:"POST"; offset:0; depth:4;', sid=10204),
        make_rule('content:"GET"; offset:2; depth:3;', sid=10205,
                  header="alert tcp any any -> any 443"),
    ])
    engine = RuleEvaluationEngine(repository)
    result = engine.evaluate(make_event(b"XXGETYYget"))

    assert result.status == "MATCH"
    assert result.candidate_count == 4
    assert result.matched_sids == [10201, 10203]
    assert result.match_count == 2
    assert [match.details for match in result.matches] == [
        {"matched_field": "payload", "matched_content": [
            {"content": "GET", "start": 2, "end": 5}
        ]},
        {"matched_field": "payload", "matched_content": [
            {"content": "get", "start": 7, "end": 10}
        ]},
    ]
    assert engine.get_stats() == {
        "events_evaluated": 1,
        "candidate_rules": 4,
        "match_count": 2,
        "matched_events": 1,
    }
    detections = DetectionEventGenerator().generate(result)
    assert [item.sid for item in detections] == [10201, 10203]
    assert [item.matched_info for item in detections] == [
        match.details for match in result.matches
    ]


def test_t10_header_rejection_is_not_bypassed_by_content():
    rule = make_rule('content:"GET"; offset:2; depth:3;')
    event = make_event(PAYLOAD, dst_port=443)
    matcher = RuleMatcher()
    assert matcher.match_content(rule, event)
    assert not matcher.match_header(rule, event)
    assert matcher.match_with_info(rule, event) is None
