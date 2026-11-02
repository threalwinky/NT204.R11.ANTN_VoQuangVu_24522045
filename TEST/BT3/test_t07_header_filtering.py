from pathlib import Path

import pytest

from modules.engine import (
    RuleEvaluationEngine,
    RuleMatcher,
    RuleParser,
    RuleRepository,
    RuleSource,
)
from modules.models import NormalizedIDSEvent


EXACT = "alert tcp 10.0.0.10 1500 -> 192.168.1.20 443"
CIDR = "alert tcp 10.0.0.0/24 1000:2000 -> 192.168.1.0/24 443"
BIDIR = "alert tcp 10.0.0.0/24 1000:2000 <> 192.168.1.0/24 443"
UDP = "alert udp any any -> any 53"
ANY = "alert tcp any any -> any any"
OPEN_LOW = "alert tcp any :1024 -> any 443"
OPEN_HIGH = "alert tcp any 1024: -> any 443"

REVERSE = {
    "src_ip": "192.168.1.20",
    "src_port": 443,
    "dst_ip": "10.0.0.10",
    "dst_port": 1500,
}


def make_rule(header, sid=7101, options=""):
    source = RuleSource(
        path=Path("t07.rules"),
        line_number=sid,
        text=(
            f'{header} (msg:"T07 Header"; sid:{sid}; rev:1; {options})'
        ),
    )

    parsed = RuleParser().parse(source)

    assert parsed.status == "valid", parsed.reason
    assert parsed.rule is not None

    return parsed.rule


def make_event(**changes):
    fields = {
        "packet_id": 1,
        "timestamp": 1000.0,
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.20",
        "src_port": 1500,
        "dst_port": 443,
        "payload": b"GET /",
        "payload_length": 5,
    }

    fields.update(changes)

    return NormalizedIDSEvent(**fields)


@pytest.mark.parametrize(
    ("header", "changes", "expected"),
    [
        pytest.param(EXACT, {}, True, id="exact-ip-port"),
        pytest.param(EXACT, {"src_ip": "10.0.0.11"}, False, id="wrong-source-ip"),
        pytest.param(EXACT, {"dst_ip": "192.168.1.21"}, False, id="wrong-dest-ip"),
        pytest.param(EXACT, {"src_port": 1501}, False, id="wrong-source-port"),
        pytest.param(EXACT, {"dst_port": 444}, False, id="wrong-dest-port"),
        pytest.param(EXACT, {"transport_protocol": "UDP"}, False, id="wrong-protocol"),
        pytest.param(EXACT, {"transport_protocol": "tcp"}, True, id="protocol-case-insensitive"),
        pytest.param(EXACT, {"network_protocol": "IPv6"}, False, id="non-ipv4"),
        pytest.param(EXACT, {"network_protocol": None}, False, id="missing-network-protocol"),
        pytest.param(EXACT, {"preprocess_status": "invalid"}, False, id="invalid-preprocessed-event"),
        pytest.param(EXACT, {"src_ip": None}, False, id="missing-source-ip"),
        pytest.param(EXACT, {"dst_ip": None}, False, id="missing-dest-ip"),
        pytest.param(EXACT, {"src_ip": "999.0.0.1"}, False, id="malformed-source-ip"),
        pytest.param(EXACT, {"dst_ip": "::1"}, False, id="ipv6-dest-ip"),
        pytest.param(EXACT, {"src_port": -1}, False, id="negative-source-port"),
        pytest.param(EXACT, {"dst_port": 65536}, False, id="overflow-dest-port"),
        pytest.param(EXACT, {"src_port": True}, False, id="boolean-source-port"),
        pytest.param(EXACT, {"dst_port": 443.0}, False, id="float-dest-port"),

        pytest.param(CIDR, {}, True, id="cidr-inside"),
        pytest.param(
            CIDR,
            {"src_ip": "10.0.0.0", "dst_ip": "192.168.1.0"},
            True,
            id="cidr-low-boundaries",
        ),
        pytest.param(
            CIDR,
            {"src_ip": "10.0.0.255", "dst_ip": "192.168.1.255"},
            True,
            id="cidr-high-boundaries",
        ),
        pytest.param(CIDR, {"src_ip": "10.0.1.10"}, False, id="cidr-source-outside"),
        pytest.param(CIDR, {"dst_ip": "192.168.2.20"}, False, id="cidr-dest-outside"),
        pytest.param(CIDR, {"src_port": 1000}, True, id="range-lower-bound"),
        pytest.param(CIDR, {"src_port": 2000}, True, id="range-upper-bound"),
        pytest.param(CIDR, {"src_port": 999}, False, id="range-below"),
        pytest.param(CIDR, {"src_port": 2001}, False, id="range-above"),

        pytest.param(BIDIR, {}, True, id="bidirectional-forward"),
        pytest.param(BIDIR, REVERSE, True, id="bidirectional-reverse"),
        pytest.param(
            BIDIR,
            {**REVERSE, "src_ip": "192.168.2.20"},
            False,
            id="bidirectional-reverse-wrong-ip",
        ),
        pytest.param(
            BIDIR,
            {**REVERSE, "dst_port": 2001},
            False,
            id="bidirectional-reverse-wrong-port",
        ),
        pytest.param(EXACT, REVERSE, False, id="unidirectional-reverse-rejected"),

        pytest.param(
            UDP,
            {"transport_protocol": "UDP", "dst_port": 53},
            True,
            id="udp-correct-protocol-port",
        ),
        pytest.param(
            UDP,
            {"transport_protocol": "TCP", "dst_port": 53},
            False,
            id="udp-protocol-mismatch",
        ),
        pytest.param(
            UDP,
            {"transport_protocol": "UDP", "dst_port": 54},
            False,
            id="udp-port-mismatch",
        ),

        pytest.param(ANY, {}, True, id="wildcard-valid-ip"),
        pytest.param(
            ANY,
            {"src_ip": "invalid"},
            False,
            id="wildcard-requires-valid-ip",
        ),

        pytest.param(OPEN_LOW, {"src_port": 0}, True, id="open-low-port-zero"),
        pytest.param(OPEN_LOW, {"src_port": 1024}, True, id="open-low-boundary"),
        pytest.param(OPEN_LOW, {"src_port": 1025}, False, id="open-low-outside"),
        pytest.param(OPEN_HIGH, {"src_port": 65535}, True, id="open-high-maximum"),
        pytest.param(OPEN_HIGH, {"src_port": 1023}, False, id="open-high-outside"),
    ],
)
def test_t07_header_filter_matrix(header, changes, expected):
    rule = make_rule(header)
    event = make_event(**changes)

    assert RuleMatcher().match_header(rule, event) is expected


@pytest.fixture
def repository():
    repo = RuleRepository()

    repo.add_many([
        make_rule(CIDR, 7201),
        make_rule(
            "alert tcp 172.16.0.0/16 1000:2000 "
            "-> 192.168.1.0/24 443",
            7202,
        ),
        make_rule(ANY, 7203),
        make_rule(
            "alert udp any any -> any 443",
            7204,
        ),
        make_rule(
            "alert tcp any any -> any 80",
            7205,
        ),
        make_rule(BIDIR, 7206),
    ])

    return repo


def test_t07_candidate_with_wrong_ip_rejected(repository):
    event = make_event()
    candidates = repository.get_candidates(event)

    assert [rule.sid for rule in candidates] == [
        7201, 7202, 7203, 7206
    ]

    matcher = RuleMatcher()

    matched = [
        rule.sid
        for rule in candidates
        if matcher.match_header(rule, event)
    ]

    assert matched == [7201, 7203, 7206]

    result = RuleEvaluationEngine(repository).evaluate(event)

    assert result.candidate_count == 4
    assert result.matched_sids == [7201, 7203, 7206]
    assert result.match_count == 3


def test_t07_bidirectional_reverse_after_indexing(repository):
    event = make_event(**REVERSE)

    assert [
        rule.sid
        for rule in repository.get_candidates(event)
    ] == [7203, 7206]

    result = RuleEvaluationEngine(repository).evaluate(event)

    assert result.candidate_count == 2
    assert result.matched_sids == [7203, 7206]


def test_t07_all_specific_ip_rules_rejected(repository):
    event = make_event(src_ip="198.51.100.10")

    assert [
        rule.sid
        for rule in repository.get_candidates(event)
    ] == [7201, 7202, 7203, 7206]

    result = RuleEvaluationEngine(repository).evaluate(event)

    assert result.candidate_count == 4
    assert result.matched_sids == [7203]


def test_t07_udp_protocol_isolation(repository):
    event = make_event(transport_protocol="UDP")

    assert [
        rule.sid
        for rule in repository.get_candidates(event)
    ] == [7204]

    result = RuleEvaluationEngine(repository).evaluate(event)

    assert result.candidate_count == 1
    assert result.matched_sids == [7204]


def test_t07_header_match_does_not_bypass_content_filter():
    repo = RuleRepository()

    rule = make_rule(
        EXACT,
        7301,
        'content:"GET";',
    )

    repo.add(rule)

    event = make_event(
        payload=b"POST",
        payload_length=4,
    )

    matcher = RuleMatcher()

    assert matcher.match_header(rule, event) is True
    assert matcher.match(rule, event) is False

    result = RuleEvaluationEngine(repo).evaluate(event)

    assert result.candidate_count == 1
    assert result.status == "NO_MATCH"
    assert result.matched_sids == []


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param(
            {"preprocess_status": "invalid"},
            id="invalid-preprocessing",
        ),
        pytest.param(
            {"processing_action": "skip"},
            id="skip-processing-policy",
        ),
        pytest.param(
            {"status": "ERROR"},
            id="error-event-status",
        ),
    ],
)
def test_t07_evaluator_skips_unusable_events(repository, changes):
    result = RuleEvaluationEngine(repository).evaluate(
        make_event(**changes)
    )

    assert result.candidate_count == 0
    assert result.matches == []
    assert result.status == "NO_MATCH"


def test_t07_evaluator_multi_event_statistics(repository):
    engine = RuleEvaluationEngine(repository)

    results = [
        engine.evaluate(make_event()),
        engine.evaluate(make_event(**REVERSE)),
        engine.evaluate(
            make_event(src_ip="198.51.100.10")
        ),
        engine.evaluate(
            make_event(transport_protocol="UDP")
        ),
    ]

    assert [
        result.candidate_count
        for result in results
    ] == [4, 2, 4, 1]

    assert [
        result.matched_sids
        for result in results
    ] == [
        [7201, 7203, 7206],
        [7203, 7206],
        [7203],
        [7204],
    ]

    assert engine.get_stats() == {
        "events_evaluated": 4,
        "candidate_rules": 11,
        "match_count": 7,
        "matched_events": 4,
    }
