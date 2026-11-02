"""BT3 T11: relative content search using distance / within.

Match positions use zero-based, half-open byte spans [start, end).
The current Matcher measures ``within`` from ``previous_end + distance``.
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


HEADER = "alert tcp any any -> any 80"


def make_rule(options, sid=11101, header=HEADER):
    source = RuleSource(
        path=Path("t11.rules"),
        line_number=sid,
        text=f'{header} (msg:"T11 Relative"; sid:{sid}; rev:1; {options})',
    )
    parsed = RuleParser().parse(source)
    assert parsed.status == "valid", parsed.reason
    assert parsed.rule is not None
    return parsed.rule


def make_event(payload=b"", application_data=None, **overrides):
    fields = {
        "packet_id": 1,
        "timestamp": 1000.0,
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.20",
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "src_port": 50000,
        "dst_port": 80,
        "payload": payload,
        "payload_length": len(payload),
        "application_data": application_data if application_data is not None else {},
    }
    fields.update(overrides)
    return NormalizedIDSEvent(**fields)


def match_details(options, payload, **kwargs):
    return RuleMatcher().match_with_info(
        make_rule(options), make_event(payload, **kwargs)
    )


def spans(*items):
    return {
        "matched_field": "payload",
        "matched_content": [
            {"content": content, "start": start, "end": end}
            for content, start, end in items
        ],
    }


@pytest.mark.parametrize(
    ("payload", "modifier", "positions"),
    [
        pytest.param(b"GET admin", "distance:1; within:5;", (0, 3, 4, 9), id="exact-distance-and-within"),
        pytest.param(b"GET admin", "distance:1; within:6;", (0, 3, 4, 9), id="within-larger-than-needle"),
        pytest.param(b"GET admin", "distance:1; within:4;", None, id="within-too-short"),
        pytest.param(b"GET admin", "distance:0; within:6;", (0, 3, 4, 9), id="distance-zero"),
        pytest.param(b"GET admin", "distance:0; within:5;", None, id="distance-zero-insufficient-within"),
        pytest.param(b"GET admin", "distance:1;", (0, 3, 4, 9), id="distance-only"),
        pytest.param(b"GET admin", "within:6;", (0, 3, 4, 9), id="within-only"),
        pytest.param(b"GET admin", "within:5;", None, id="within-only-short"),
        pytest.param(b"GET admin", "distance:2;", None, id="distance-skips-needle"),
        pytest.param(b"GET admin", "distance:0; within:0;", None, id="zero-within"),
        pytest.param(b"GET admin", "distance:1; within:100;", (0, 3, 4, 9), id="within-exceeds-payload"),
        pytest.param(b"GETadmin", "distance:0; within:5;", (0, 3, 3, 8), id="adjacent-content"),
        pytest.param(b"GETadmin", "distance:1;", None, id="adjacent-distance-one-fails"),
        pytest.param(b"GETadmin", "within:4;", None, id="adjacent-within-short"),
        pytest.param(b"GETxxadmin", "distance:2; within:5;", (0, 3, 5, 10), id="two-byte-gap-exact"),
        pytest.param(b"GETxxadmin", "distance:2; within:4;", None, id="two-byte-gap-window-short"),
        pytest.param(b"GETxxadmin", "distance:1; within:6;", (0, 3, 5, 10), id="needle-after-window-start"),
        pytest.param(b"GETxxadmin", "distance:1; within:5;", None, id="late-needle-crosses-window"),
        pytest.param(b"GETxxadmin", "distance:0; within:7;", (0, 3, 5, 10), id="within-covers-gap"),
        pytest.param(b"GETxxadmin", "distance:3;", None, id="distance-too-large"),
        pytest.param(b"GETxxxxxadmin", "distance:5; within:5;", (0, 3, 8, 13), id="five-byte-gap-exact"),
        pytest.param(b"GETxxxxxadmin", "distance:4; within:6;", (0, 3, 8, 13), id="five-byte-gap-later-in-window"),
        pytest.param(b"GETxxxxxadmin", "distance:4; within:5;", None, id="five-byte-gap-window-short"),
        pytest.param(b"GET admin GET admin", "distance:1; within:5;", (0, 3, 4, 9), id="first-complete-occurrence"),
        pytest.param(b"GETxxxxxxxGET admin", "distance:1; within:5;", (10, 13, 14, 19), id="backtrack-to-second-first-pattern"),
        pytest.param(b"GETzzzzGET admin", "distance:1; within:5;", (7, 10, 11, 16), id="backtrack-short-gap"),
        pytest.param(b"HELLO GET admin", "distance:1; within:5;", (6, 9, 10, 15), id="first-pattern-not-at-start"),
        pytest.param(b"GET admin", "distance:9; within:5;", None, id="distance-after-payload-end"),
        pytest.param(b"GET ", "distance:1; within:5;", None, id="missing-second-pattern"),
        pytest.param(b"admin GET", "distance:1; within:5;", None, id="second-pattern-only-before-first"),
        pytest.param(b"", "distance:1; within:5;", None, id="empty-payload"),
        pytest.param(b"GET\x00admin", "distance:1; within:5;", (0, 3, 4, 9), id="binary-gap"),
        pytest.param(b"GET\xffadmin", "distance:1; within:5;", (0, 3, 4, 9), id="non-ascii-binary-gap"),
        pytest.param(b"GET   admin", "distance:3; within:5;", (0, 3, 6, 11), id="three-spaces"),
        pytest.param(b"GET   admin", "distance:2; within:6;", (0, 3, 6, 11), id="three-spaces-later-in-window"),
        pytest.param(b"GET   admin", "distance:2; within:5;", None, id="three-spaces-incomplete-window"),
    ],
)
def test_t11_relative_search_matrix(payload, modifier, positions):
    options = f'content:"GET"; content:"admin"; {modifier}'
    matcher = RuleMatcher()
    rule = make_rule(options)
    event = make_event(payload)

    details = matcher.match_with_info(rule, event)
    assert matcher.match_content(rule, event) is (positions is not None)
    if positions is None:
        assert details is None
    else:
        first_start, first_end, second_start, second_end = positions
        assert details == spans(
            ("GET", first_start, first_end),
            ("admin", second_start, second_end),
        )


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        pytest.param('distance:1; content:"A";', "distance requires preceding content", id="distance-before-content"),
        pytest.param('within:1; content:"A";', "within requires preceding content", id="within-before-content"),
        pytest.param('content:"A"; content:"B"; distance:-1;', "distance must be an integer", id="negative-distance"),
        pytest.param('content:"A"; content:"B"; within:-1;', "within must be an integer", id="negative-within"),
        pytest.param('content:"A"; content:"B"; distance:abc;', "distance must be an integer", id="non-numeric-distance"),
        pytest.param('content:"A"; content:"B"; within:abc;', "within must be an integer", id="non-numeric-within"),
        pytest.param('content:"A"; content:"B"; distance:;', "distance requires a value", id="empty-distance"),
        pytest.param('content:"A"; content:"B"; within:;', "within requires a value", id="empty-within"),
    ],
)
def test_t11_parser_rejects_bad_relative_modifier(options, reason):
    source = RuleSource(
        path=Path("t11-invalid.rules"),
        line_number=1,
        text=f'{HEADER} (msg:"T11 Invalid"; sid:11999; rev:1; {options})',
    )
    result = RuleParser().parse(source)
    assert result.status == "invalid"
    assert result.rule is None
    assert result.reason is not None
    assert reason in result.reason


@pytest.mark.parametrize(
    ("options", "payload", "expected"),
    [
        pytest.param(
            'content:"GET"; distance:0; content:"admin";',
            b"GET admin", None,
            id="relative-on-first-content",
        ),
        pytest.param(
            'content:"GET"; within:6; content:"admin";',
            b"GET admin", None,
            id="within-on-first-content",
        ),
        pytest.param(
            'content:"GET"; offset:0; content:"admin"; distance:1; within:5;',
            b"GET admin", [("GET", 0, 3), ("admin", 4, 9)],
            id="absolute-first-relative-second",
        ),
        pytest.param(
            'content:"GET"; content:"admin"; distance:1; offset:4;',
            b"GET admin", None,
            id="mixed-relative-and-absolute-on-same-content",
        ),
        pytest.param(
            'content:"GET"; content:"admin"; within:5; depth:5;',
            b"GETadmin", None,
            id="mixed-within-and-depth-on-same-content",
        ),
        pytest.param(
            'content:"GET"; content:"admin"; distance:1; distance:1;',
            b"GET admin", None,
            id="duplicate-distance-on-second-content",
        ),
        pytest.param(
            'content:"GET"; content:"admin"; within:5; within:5;',
            b"GET admin", None,
            id="duplicate-within-on-second-content",
        ),
        pytest.param(
            'content:"GET"; content:"admin"; distance:1; within:5; nocase;',
            b"GET ADMIN", [("GET", 0, 3), ("admin", 4, 9)],
            id="nocase-second-content-only",
        ),
        pytest.param(
            'content:"GET"; nocase; content:"admin"; distance:1; within:5;',
            b"get admin", [("GET", 0, 3), ("admin", 4, 9)],
            id="nocase-first-content-only",
        ),
        pytest.param(
            'content:"GET"; nocase; content:"admin"; distance:1; within:5;',
            b"get ADMIN", None,
            id="nocase-not-inherited",
        ),
    ],
)
def test_t11_relative_modifier_combinations(options, payload, expected):
    details = match_details(options, payload)
    if expected is None:
        assert details is None
    else:
        assert details == spans(*expected)


@pytest.mark.parametrize(
    ("options", "payload", "expected"),
    [
        pytest.param(
            'content:"AA"; content:"BB"; distance:2; within:2; '
            'content:"CC"; distance:2; within:2;',
            b"AAxxBBxxCC", [("AA", 0, 2), ("BB", 4, 6), ("CC", 8, 10)],
            id="three-content-chain",
        ),
        pytest.param(
            'content:"AA"; content:"BB"; distance:2; within:2; '
            'content:"CC"; distance:2; within:1;',
            b"AAxxBBxxCC", None,
            id="third-content-window-too-short",
        ),
        pytest.param(
            'content:"AA"; content:"BB"; distance:1; within:3; '
            'content:"CC"; distance:2; within:2;',
            b"AAxxBBxxCC", [("AA", 0, 2), ("BB", 4, 6), ("CC", 8, 10)],
            id="three-content-with-later-hit",
        ),
        pytest.param(
            'content:"A"; content:"B"; within:3; content:"C"; within:3;',
            b"A-B-C", [("A", 0, 1), ("B", 2, 3), ("C", 4, 5)],
            id="three-content-within-only",
        ),
        pytest.param(
            'content:"A"; content:"B"; within:2; content:"C"; within:2;',
            b"A-B-C", [("A", 0, 1), ("B", 2, 3), ("C", 4, 5)],
            id="three-content-exact-minimum-window",
        ),
        pytest.param(
            'content:"A"; content:"B"; within:1; content:"C"; within:2;',
            b"A-B-C", None,
            id="three-content-middle-window-short",
        ),
    ],
)
def test_t11_multi_content_chain(options, payload, expected):
    result = match_details(options, payload)
    assert result == (None if expected is None else spans(*expected))


@pytest.mark.parametrize(
    ("payload", "application_data", "expected_field", "expected_positions"),
    [
        pytest.param(
            b"POST /", {"uri": "GET admin"},
            "application_data.uri", [("GET", 0, 3), ("admin", 4, 9)],
            id="fallback-uri",
        ),
        pytest.param(
            b"GET admin", {"uri": "GET admin"},
            "payload", [("GET", 0, 3), ("admin", 4, 9)],
            id="payload-preferred",
        ),
        pytest.param(
            b"GET xx", {"decoded_uri": "GET admin", "uri": "GET admin"},
            "application_data.decoded_uri", [("GET", 0, 3), ("admin", 4, 9)],
            id="decoded-uri-priority",
        ),
        pytest.param(
            b"", {"decoded_body": "éGET admin"},
            "application_data.decoded_body", [("GET", 2, 5), ("admin", 6, 11)],
            id="utf8-byte-positions",
        ),
        pytest.param(
            b"", {"headers": {"X-Test": "GET admin"}},
            "application_data.headers.X-Test", [("GET", 0, 3), ("admin", 4, 9)],
            id="headers-buffer",
        ),
        pytest.param(
            b"GET xx", {"uri": "GET nowhere"},
            None, None,
            id="no-buffer-has-both-contents",
        ),
    ],
)
def test_t11_application_buffer_relative_search(
    payload, application_data, expected_field, expected_positions
):
    options = 'content:"GET"; content:"admin"; distance:1; within:5;'
    details = match_details(options, payload, application_data=application_data)
    if expected_field is None:
        assert details is None
    else:
        assert details == {
            "matched_field": expected_field,
            "matched_content": [
                {"content": content, "start": start, "end": end}
                for content, start, end in expected_positions
            ],
        }


def test_t11_binary_pattern_relative_to_previous_end():
    rule = make_rule('content:"|00 FF|"; content:"AA"; distance:0; within:2;')
    event = make_event(b"\x00\xffAA")
    details = RuleMatcher().match_with_info(rule, event)
    assert details == spans(("|00 FF|", 0, 2), ("AA", 2, 4))


def test_t11_evaluator_and_detection_integration():
    repository = RuleRepository()
    repository.add_many([
        make_rule('content:"GET"; content:"admin"; distance:1; within:5;', 11201),
        make_rule('content:"GET"; content:"admin"; distance:1; within:4;', 11202),
        make_rule('content:"GET"; content:"admin"; distance:0; within:6;', 11203),
        make_rule('content:"GET"; content:"admin"; distance:2; within:5;', 11204),
        make_rule('content:"GET"; content:"admin"; distance:1; within:5;', 11205,
                  header="alert tcp any any -> any 443"),
    ])
    event = make_event(b"GET admin")
    engine = RuleEvaluationEngine(repository)
    result = engine.evaluate(event)
    assert result.status == "MATCH"
    assert result.candidate_count == 4
    assert result.match_count == 2
    assert result.matched_sids == [11201, 11203]
    assert [match.details for match in result.matches] == [
        spans(("GET", 0, 3), ("admin", 4, 9)),
        spans(("GET", 0, 3), ("admin", 4, 9)),
    ]
    assert engine.get_stats() == {
        "events_evaluated": 1,
        "candidate_rules": 4,
        "match_count": 2,
        "matched_events": 1,
    }
    generated = DetectionEventGenerator().generate(result)
    assert [item.sid for item in generated] == [11201, 11203]
    assert [item.matched_info for item in generated] == [m.details for m in result.matches]


def test_t11_header_rejection_cannot_be_bypassed():
    rule = make_rule('content:"GET"; content:"admin"; distance:1; within:5;')
    event = make_event(b"GET admin", dst_port=443)
    matcher = RuleMatcher()
    assert matcher.match_content(rule, event)
    assert not matcher.match_header(rule, event)
    assert matcher.match_with_info(rule, event) is None


def test_t11_last_content_match_is_reported_once():
    options = 'content:"GET"; content:"admin"; distance:1; within:5;'
    result = match_details(options, b"GETxxxxGET admin")
    assert result == spans(("GET", 7, 10), ("admin", 11, 16))

