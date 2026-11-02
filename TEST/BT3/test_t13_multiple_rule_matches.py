"""BT3 T13: multiple Snort rule matches per normalized event."""

from pathlib import Path

import pytest

from modules.engine import (
    DetectionEventGenerator,
    RuleEvaluationEngine,
    RuleParser,
    RuleRepository,
    RuleSource,
)
from modules.models import NormalizedIDSEvent


TCP = "alert tcp any any -> any 80"
UDP = "alert udp any any -> any 80"
TCP_443 = "alert tcp any any -> any 443"
WRONG_IP = "alert tcp 172.16.0.0/16 any -> any 80"
BIDIR = "alert tcp any any <> any any"


def make_rule(sid, options="", header=TCP):
    source = RuleSource(
        path=Path("t13.rules"),
        line_number=sid,
        text=(
            f'{header} (msg:"T13 Rule {sid}"; '
            f'sid:{sid}; rev:1; {options})'
        ),
    )
    parsed = RuleParser().parse(source)
    assert parsed.status == "valid", parsed.reason
    assert parsed.rule is not None
    return parsed.rule


def make_event(payload=b"GET /ADMIN", **changes):
    fields = {
        "packet_id": 1,
        "timestamp": 1000.0,
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.20",
        "src_port": 50000,
        "dst_port": 80,
        "tcp_flags": "SA",
        "flow_direction": "forward",
        "tcp_state": "ESTABLISHED",
        "payload": payload,
        "payload_length": len(payload),
    }
    fields.update(changes)
    return NormalizedIDSEvent(**fields)


def make_repository(specs):
    repository = RuleRepository()
    repository.add_many([
        make_rule(sid, options, header)
        for sid, options, header in specs
    ])
    return repository


def spec(sid, options="", header=TCP):
    return (sid, options, header)


@pytest.mark.parametrize(
    ("rules", "event_changes", "candidates", "matches"),
    [
        pytest.param([], {}, [], [], id="empty-repository"),
        pytest.param(
            [spec(13001, 'content:"GET";')],
            {}, [13001], [13001], id="one-rule-matches",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";'),
             spec(13002, 'content:"ADMIN";')],
            {}, [13001, 13002], [13001, 13002],
            id="two-content-rules-match",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";'),
             spec(13003, 'content:"POST";')],
            {}, [13001, 13003], [13001],
            id="matching-and-nonmatching-content",
        ),
        pytest.param(
            [spec(13003, 'content:"POST";')],
            {}, [13003], [], id="candidate-without-match",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";', TCP_443)],
            {}, [], [], id="port-index-filter",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";', UDP)],
            {}, [], [], id="protocol-index-filter",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";', WRONG_IP)],
            {}, [13001], [], id="header-ip-filter-after-index",
        ),
        pytest.param(
            [spec(13001)],
            {}, [13001], [13001], id="rule-without-content",
        ),
        pytest.param(
            [spec(13001, 'flow:to_server;'),
             spec(13002, 'flow:to_client;')],
            {}, [13001, 13002], [13001],
            id="different-flow-requirements",
        ),
        pytest.param(
            [spec(13001, 'flags:SA;'),
             spec(13002, 'flags:S;')],
            {}, [13001, 13002], [13001],
            id="different-tcp-flags",
        ),
        pytest.param(
            [spec(13001, 'dsize:10;'),
             spec(13002, 'dsize:>10;')],
            {}, [13001, 13002], [13001],
            id="different-payload-length-conditions",
        ),
        pytest.param(
            [spec(13001, 'content:"get"; nocase;'),
             spec(13002, 'content:"get";')],
            {}, [13001, 13002], [13001],
            id="nocase-applies-per-rule",
        ),
        pytest.param(
            [spec(13001, 'content:"GET"; flags:SA; dsize:10;')],
            {}, [13001], [13001],
            id="all-conditions-match",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";', UDP),
             spec(13002, 'content:"GET";')],
            {"transport_protocol": "UDP"},
            [13001], [13001], id="udp-event-isolation",
        ),
        pytest.param(
            [spec(13001, 'content:"GET"; content:"ADMIN";')],
            {}, [13001], [13001],
            id="multiple-contents-one-rule-one-match",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";', WRONG_IP),
             spec(13002, 'content:"GET";')],
            {}, [13001, 13002], [13002],
            id="wrong-ip-does-not-block-other-rules",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";')],
            {"payload": b"", "payload_length": 0},
            [13001], [], id="empty-payload-does-not-match",
        ),
        pytest.param(
            [spec(13001), spec(13002, 'content:"GET";')],
            {"payload": b"", "payload_length": 0},
            [13001, 13002], [13001],
            id="empty-payload-still-matches-header-only",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";')],
            {"preprocess_status": "invalid"},
            [13001], [], id="invalid-preprocessed-event-skipped",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";')],
            {"processing_action": "skip"},
            [13001], [], id="skip-policy-event",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";')],
            {"status": "ERROR"},
            [13001], [], id="error-event",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";')],
            {"payload": b"POST", "payload_length": 4,
             "application_data": {"decoded_uri": "/GET"}},
            [13001], [13001],
            id="fallback-to-application-buffer",
        ),
        pytest.param(
            [spec(13001, 'content:"GET"; content:"ADMIN";'),
             spec(13002, 'content:"GET";'),
             spec(13003, 'content:"ADMIN";')],
            {"payload": b"GET", "payload_length": 3,
             "application_data": {"uri": "/ADMIN"}},
            [13001, 13002, 13003], [13002, 13003],
            id="multiple-contents-must-share-one-buffer",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";', BIDIR)],
            {"src_port": 80, "dst_port": 80},
            [13001], [13001],
            id="overlapping-indexes-do-not-duplicate",
        ),
        pytest.param(
            [spec(
                13001, 'content:"GET";',
                "alert tcp any 50000 <> any 80",
            ),
             spec(
                13002, 'content:"GET";',
                "alert tcp any 50000 -> any 80",
            )],
            {"src_port": 80, "dst_port": 50000},
            [13001], [13001],
            id="reverse-direction-only-bidirectional",
        ),
        pytest.param(
            [spec(13001, 'content:"GET";')],
            {"dst_port": 443},
            [], [], id="event-with-unindexed-port",
        ),
    ],
)
def test_t13_match_matrix(
    rules, event_changes, candidates, matches
):
    repository = make_repository(rules)
    event = make_event(**event_changes)

    assert [
        rule.sid for rule in repository.get_candidates(event)
    ] == candidates

    result = RuleEvaluationEngine(repository).evaluate(event)

    skipped = (
        event.preprocess_status == "invalid"
        or event.processing_action == "skip"
        or event.status == "ERROR"
    )

    assert result.candidate_count == (
        0 if skipped else len(candidates)
    )
    assert result.matched_sids == matches
    assert result.match_count == len(matches)
    assert result.status == (
        "MATCH" if matches else "NO_MATCH"
    )

    assert len(
        DetectionEventGenerator().generate(result)
    ) == len(matches)


def test_t13_many_matching_rules_preserve_insertion_order():
    specs = [
        spec(13409, 'content:"GET";'),
        spec(13401, 'content:"ADMIN";'),
        spec(13407, 'content:"GET"; nocase;'),
        spec(13403, 'content:"POST";'),
        spec(13402, 'dsize:10;'),
        spec(13405, 'flags:SA;'),
        spec(13404, 'flow:to_server,established;'),
        spec(13406, 'content:"GET";', WRONG_IP),
        spec(13408, 'content:"GET";', UDP),
        spec(13411, 'content:"GET";', TCP_443),
        spec(13410, 'content:"ADMIN";', BIDIR),
    ]

    repo = make_repository(specs)
    result = RuleEvaluationEngine(repo).evaluate(make_event())

    expected = [
        13409, 13401, 13407,
        13402, 13405, 13404, 13410,
    ]

    assert result.candidate_count == 9
    assert result.matched_sids == expected
    assert result.match_count == len(expected)

    assert [
        match.rule.sid for match in result.matches
    ] == expected

    detections = DetectionEventGenerator().generate(result)

    assert [d.sid for d in detections] == expected
    assert [d.msg for d in detections] == [
        f"T13 Rule {sid}" for sid in expected
    ]


def test_t13_detected_content_details_independent_for_each_sid():
    repo = make_repository([
        spec(13501, 'content:"GET";'),
        spec(13502, 'content:"ADMIN";'),
        spec(13503, 'content:"GET"; content:"ADMIN";'),
        spec(13504, 'content:"POST";'),
    ])

    result = RuleEvaluationEngine(repo).evaluate(make_event())

    assert result.candidate_count == 4
    assert result.matched_sids == [13501, 13502, 13503]

    assert [match.details for match in result.matches] == [
        {
            "matched_field": "payload",
            "matched_content": [
                {"content": "GET", "start": 0, "end": 3},
            ],
        },
        {
            "matched_field": "payload",
            "matched_content": [
                {"content": "ADMIN", "start": 5, "end": 10},
            ],
        },
        {
            "matched_field": "payload",
            "matched_content": [
                {"content": "GET", "start": 0, "end": 3},
                {"content": "ADMIN", "start": 5, "end": 10},
            ],
        },
    ]

    detections = DetectionEventGenerator().generate(result)

    assert [d.matched_info for d in detections] == [
        match.details for match in result.matches
    ]

    # Detection metadata must be deep-copied.
    detections[0].matched_info[
        "matched_content"
    ][0]["start"] = 999

    assert result.matches[0].details[
        "matched_content"
    ][0]["start"] == 0

    assert detections[2].matched_info[
        "matched_content"
    ][0]["start"] == 0


def test_t13_repeated_substring_is_one_match_per_sid():
    repo = make_repository([
        spec(13601, 'content:"GET";'),
        spec(13602, 'content:"GET"; nocase;'),
    ])

    result = RuleEvaluationEngine(repo).evaluate(
        make_event(b"GET GET GET")
    )

    assert result.candidate_count == 2
    assert result.matched_sids == [13601, 13602]
    assert result.match_count == 2

    assert [
        m.details["matched_content"][0]
        for m in result.matches
    ] == [
        {"content": "GET", "start": 0, "end": 3},
        {"content": "GET", "start": 0, "end": 3},
    ]


def test_t13_bidirectional_indexes_do_not_duplicate_sid():
    repo = make_repository([
        spec(13701, 'content:"GET";', BIDIR),
        spec(
            13702, 'content:"GET";',
            "alert tcp any 80 <> any 80",
        ),
        spec(13703, 'content:"POST";', BIDIR),
    ])

    event = make_event(src_port=80, dst_port=80)

    candidates = repo.get_candidates(event)

    assert [r.sid for r in candidates] == [
        13701, 13702, 13703
    ]

    result = RuleEvaluationEngine(repo).evaluate(event)

    assert result.candidate_count == 3
    assert result.matched_sids == [13701, 13702]

    assert len(set(result.matched_sids)) == result.match_count

    assert [
        d.sid for d in DetectionEventGenerator().generate(result)
    ] == [13701, 13702]


def test_t13_forward_reverse_have_different_match_sets():
    repo = make_repository([
        spec(
            13801, 'content:"GET";',
            "alert tcp any 50000 <> any 80",
        ),
        spec(
            13802, 'content:"GET";',
            "alert tcp any 50000 -> any 80",
        ),
        spec(13803, 'content:"GET";', BIDIR),
    ])

    engine = RuleEvaluationEngine(repo)

    forward = engine.evaluate(make_event())
    reverse = engine.evaluate(
        make_event(src_port=80, dst_port=50000)
    )

    assert forward.candidate_count == 3
    assert forward.matched_sids == [
        13801, 13802, 13803
    ]

    assert reverse.candidate_count == 2
    assert reverse.matched_sids == [
        13801, 13803
    ]

    assert engine.get_stats() == {
        "events_evaluated": 2,
        "candidate_rules": 5,
        "match_count": 5,
        "matched_events": 2,
    }


def test_t13_evaluate_many_aggregates_stats_by_event():
    repo = make_repository([
        spec(13901, 'content:"GET";'),
        spec(13902, 'content:"POST";'),
        spec(13903, 'dsize:>0;'),
        spec(13904, 'flow:to_server;'),
    ])

    engine = RuleEvaluationEngine(repo)

    events = [
        make_event(b"GET", packet_id=1),
        make_event(b"POST", packet_id=2),
        make_event(
            b"GET", packet_id=3,
            flow_direction="backward",
        ),
        make_event(
            b"GET", packet_id=4,
            preprocess_status="invalid",
        ),
    ]

    results = engine.evaluate_many(events)

    assert [
        r.candidate_count for r in results
    ] == [4, 4, 4, 0]

    assert [
        r.matched_sids for r in results
    ] == [
        [13901, 13903, 13904],
        [13902, 13903, 13904],
        [13901, 13903],
        [],
    ]

    assert engine.get_stats() == {
        "events_evaluated": 4,
        "candidate_rules": 12,
        "match_count": 8,
        "matched_events": 3,
    }

    detections = DetectionEventGenerator().generate_many(results)

    assert [
        (d.packet_id, d.sid) for d in detections
    ] == [
        (1, 13901), (1, 13903), (1, 13904),
        (2, 13902), (2, 13903), (2, 13904),
        (3, 13901), (3, 13903),
    ]


def test_t13_reset_stats_keeps_repository_and_rules():
    repo = make_repository([
        spec(14001, 'content:"GET";'),
        spec(14002, 'content:"ADMIN";'),
    ])

    engine = RuleEvaluationEngine(repo)

    first = engine.evaluate(make_event())

    assert first.matched_sids == [14001, 14002]

    engine.reset_stats()

    assert len(repo) == 2

    assert engine.get_stats() == {
        "events_evaluated": 0,
        "candidate_rules": 0,
        "match_count": 0,
        "matched_events": 0,
    }

    again = engine.evaluate(make_event())

    assert again.matched_sids == [14001, 14002]

    assert engine.get_stats() == {
        "events_evaluated": 1,
        "candidate_rules": 2,
        "match_count": 2,
        "matched_events": 1,
    }


def test_t13_many_rules_same_packet_no_lost_matches():
    repo = make_repository([
        spec(
            15000 + i,
            'content:"GET";'
            if i % 2 == 0
            else 'content:"POST";',
        )
        for i in range(40)
    ])

    result = RuleEvaluationEngine(repo).evaluate(make_event())

    assert result.candidate_count == 40
    assert result.matched_sids == [
        15000 + i for i in range(0, 40, 2)
    ]
    assert result.match_count == 20

    assert len(
        DetectionEventGenerator().generate(result)
    ) == 20


def test_t13_no_candidates_no_matches_no_detections():
    repo = make_repository([
        spec(16001, 'content:"GET";', UDP),
        spec(16002, 'content:"GET";', TCP_443),
    ])

    engine = RuleEvaluationEngine(repo)
    result = engine.evaluate(make_event())

    assert result.status == "NO_MATCH"
    assert result.candidate_count == 0
    assert result.match_count == 0
    assert result.matched_sids == []

    assert DetectionEventGenerator().generate(result) == []

    assert engine.get_stats() == {
        "events_evaluated": 1,
        "candidate_rules": 0,
        "match_count": 0,
        "matched_events": 0,
    }
