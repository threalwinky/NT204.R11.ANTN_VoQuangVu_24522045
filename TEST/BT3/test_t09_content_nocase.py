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


def make_rule(options, sid=9101, header=TCP_HEADER):
    source = RuleSource(
        path=Path("t09.rules"),
        line_number=sid,
        text=(
            f'{header} (msg:"T09 Content"; '
            f'sid:{sid}; rev:1; {options})'
        ),
    )
    parsed = RuleParser().parse(source)
    assert parsed.status == "valid", parsed.reason
    assert parsed.rule is not None
    return parsed.rule


def make_event(payload=b"", application_data=None, **changes):
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
            application_data if application_data is not None else {}
        ),
    }
    fields.update(changes)
    return NormalizedIDSEvent(**fields)


@pytest.mark.parametrize(
    ("options", "payload", "expected"),
    [
        pytest.param('content:"GET";', b"GET /admin", True, id="case-sensitive-exact"),
        pytest.param('content:"GET";', b"get /admin", False, id="case-sensitive-lower-rejected"),
        pytest.param('content:"get";', b"GET /admin", False, id="case-sensitive-upper-rejected"),
        pytest.param('content:"GET"; nocase;', b"get /admin", True, id="nocase-lower"),
        pytest.param('content:"GET"; nocase;', b"GeT /admin", True, id="nocase-mixed"),
        pytest.param('content:"GET"; nocase;', b"POST /admin", False, id="nocase-does-not-match-unrelated"),
        pytest.param('content:"admin";', b"GET /admin HTTP/1.1", True, id="substring"),
        pytest.param('content:"GET";', b"", False, id="empty-payload"),
        pytest.param('content:"GET";', b"POST /", False, id="absent-pattern"),
        pytest.param('content:"GET";', b"XGETY", True, id="substring-not-anchored"),
        pytest.param('content:"a;b";', b"a;b", True, id="quoted-semicolon"),
        pytest.param('content:"A B";', b"A B", True, id="content-with-spaces"),
        pytest.param('content:"|00 FF|";', b"A\x00\xffZ", True, id="binary-hex"),
        pytest.param('content:"|00 FF|";', b"A\x00\x00Z", False, id="binary-hex-not-found"),
        pytest.param('content:"A|00 FF|B";', b"A\x00\xffB", True, id="mixed-ascii-and-hex"),
        pytest.param('content:"|47 45 54|";', b"GET /", True, id="hex-encoded-ascii"),
        pytest.param(r'content:"A\|B";', b"A|B", True, id="escaped-pipe-literal"),
        pytest.param(r'content:"say \"hi\"";', b'say "hi"', True, id="escaped-quote"),
        pytest.param('content:"foo"; content:"bar";', b"foo bar", True, id="two-contents-forward"),
        pytest.param('content:"foo"; content:"bar";', b"bar foo", True, id="two-contents-reverse-order"),
        pytest.param('content:"foo"; content:"bar";', b"foo baz", False, id="missing-second-content"),
        pytest.param('content:"foo"; nocase; content:"BAR";', b"FOO BAR", True, id="nocase-only-first-content"),
        pytest.param('content:"foo"; nocase; content:"BAR";', b"FOO bar", False, id="second-content-remains-sensitive"),
        pytest.param('content:"foo"; content:"BAR"; nocase;', b"FOO bar", False, id="nocase-only-second-content"),
        pytest.param('content:"foo"; content:"BAR"; nocase;', b"foo bar", True, id="second-content-nocase"),
    ],
)
def test_t09_content_matching_matrix(options, payload, expected):
    rule = make_rule(options)
    event = make_event(payload=payload)
    matcher = RuleMatcher()
    assert matcher.match_content(rule, event) is expected
    assert matcher.match(rule, event) is expected


@pytest.mark.parametrize(
    ("application_data", "expected_field", "payload", "start"),
    [
        pytest.param({"uri": "/admin"}, "application_data.uri", b"", 1, id="http-uri"),
        pytest.param({"decoded_uri": "/admin"}, "application_data.decoded_uri", b"", 1, id="decoded-uri"),
        pytest.param({"normalized_uri": "/admin"}, "application_data.normalized_uri", b"", 1, id="normalized-uri"),
        pytest.param({"body": "id=admin"}, "application_data.body", b"", 3, id="http-body"),
        pytest.param({"headers": {"X-User": "admin"}}, "application_data.headers.X-User", b"", 0, id="http-header"),
        pytest.param({"decoded_form": [{"name": "user", "value": "admin"}]}, "application_data.decoded_form[0].value", b"", 0, id="decoded-form-value"),
        pytest.param({"mime_parts": [{"decoded_body": "admin"}]}, "application_data.mime_parts[0].decoded_body", b"", 0, id="mime-decoded-body"),
        pytest.param({"uri": "/admin"}, "payload", b"admin", 0, id="payload-priority"),
    ],
)
def test_t09_application_buffers(application_data, expected_field, payload, start):
    rule = make_rule('content:"ADMIN"; nocase;')
    event = make_event(payload=payload, application_data=application_data)
    details = RuleMatcher().match_with_info(rule, event)
    assert details == {
        "matched_field": expected_field,
        "matched_content": [
            {"content": "ADMIN", "start": start, "end": start + 5}
        ],
    }


def test_t09_match_info_positions_use_byte_offsets():
    rule = make_rule('content:"GET"; nocase;')
    event = make_event(payload=b"\x00\xffget /admin")
    result = RuleMatcher().match_with_info(rule, event)
    assert result == {
        "matched_field": "payload",
        "matched_content": [
            {"content": "GET", "start": 2, "end": 5}
        ],
    }


def test_t09_multiple_content_positions():
    rule = make_rule('content:"GET"; content:"admin";')
    event = make_event(payload=b"GET /admin HTTP/1.1")
    result = RuleMatcher().match_with_info(rule, event)
    assert result == {
        "matched_field": "payload",
        "matched_content": [
            {"content": "GET", "start": 0, "end": 3},
            {"content": "admin", "start": 5, "end": 10},
        ],
    }


def test_t09_first_occurrence_is_reported():
    rule = make_rule('content:"GET";')
    event = make_event(payload=b"XXGET--GET")
    details = RuleMatcher().match_with_info(rule, event)
    assert details["matched_content"] == [
        {"content": "GET", "start": 2, "end": 5}
    ]


def test_t09_application_fallback_and_precedence():
    rule = make_rule('content:"admin";')
    event = make_event(
        payload=b"not here",
        application_data={
            "uri": "/admin",
            "decoded_uri": "/admin",
            "normalized_uri": "/admin",
        },
    )
    details = RuleMatcher().match_with_info(rule, event)
    assert details is not None
    assert details["matched_field"] == "application_data.decoded_uri"
    assert details["matched_content"] == [
        {"content": "admin", "start": 1, "end": 6}
    ]


def test_t09_dns_domain_buffer():
    rule = make_rule('content:"EXAMPLE.COM"; nocase;', header=UDP_HEADER)
    event = make_event(
        payload=b"",
        transport_protocol="UDP",
        dst_port=53,
        application_data={"domain": "example.com"},
    )
    details = RuleMatcher().match_with_info(rule, event)
    assert details == {
        "matched_field": "application_data.domain",
        "matched_content": [
            {"content": "EXAMPLE.COM", "start": 0, "end": 11}
        ],
    }


def test_t09_content_missing_all_buffers():
    rule = make_rule('content:"admin";')
    event = make_event(
        payload=b"not here",
        application_data={"uri": "/public", "body": "none"},
    )
    assert RuleMatcher().match_with_info(rule, event) is None


def test_t09_rule_without_content_has_empty_match_info():
    rule = make_rule("")
    event = make_event()
    assert RuleMatcher().match_with_info(rule, event) == {
        "matched_field": None,
        "matched_content": [],
    }


def test_t09_engine_detection_event_integration():
    repository = RuleRepository()
    repository.add_many([
        make_rule('content:"GET";', sid=9201),
        make_rule('content:"GET"; nocase;', sid=9202),
        make_rule('content:"POST";', sid=9203),
        make_rule('content:"admin"; nocase;', sid=9204),
    ])
    engine = RuleEvaluationEngine(repository)
    event = make_event(payload=b"get /ADMIN")
    result = engine.evaluate(event)

    assert result.status == "MATCH"
    assert result.candidate_count == 4
    assert result.match_count == 2
    assert result.matched_sids == [9202, 9204]
    assert engine.get_stats() == {
        "events_evaluated": 1,
        "candidate_rules": 4,
        "match_count": 2,
        "matched_events": 1,
    }

    detections = DetectionEventGenerator().generate(result)
    assert [item.sid for item in detections] == [9202, 9204]
    assert all(item.record_type == "detection" for item in detections)
    assert detections[0].matched_info == {
        "matched_field": "payload",
        "matched_content": [
            {"content": "GET", "start": 0, "end": 3}
        ],
    }
    assert detections[1].matched_info == {
        "matched_field": "payload",
        "matched_content": [
            {"content": "admin", "start": 5, "end": 10}
        ],
    }
