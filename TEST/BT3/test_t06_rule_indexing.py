from pathlib import Path

import pytest

from modules.engine import (
    RuleEvaluationEngine,
    RuleParser,
    RuleRepository,
    RuleSource,
)
from modules.models import NormalizedIDSEvent


RULE_SPECS = [
    (6101, "alert tcp any any -> any 80"),
    (6102, "alert udp any any -> any 80"),
    (6103, "alert tcp any any -> any any"),
    (6104, "alert udp any any -> any any"),
    (6105, "alert tcp any 1000:2000 -> any 443"),
    (6106, "alert tcp any any -> any 8000:9000"),
    (6107, "alert tcp any any -> any :1024"),
    (6108, "alert tcp any any -> any 49152:"),
    (6109, "alert tcp any 1234 <> any 443"),
    (
        6110,
        "alert tcp 10.0.0.0/24 2222 "
        "-> 192.0.2.0/24 443",
    ),
    (6111, "alert tcp any 0 -> any 0"),
    (6112, "alert tcp any 65535 -> any 65535"),
    (6113, "alert udp any 5353 <> any 53"),
    (6114, "alert tcp any 80 -> any any"),
]


def make_rule(header, sid):
    source = RuleSource(
        path=Path("t06.rules"),
        line_number=sid,
        text=(
            f'{header} '
            f'(msg:"T06 Index"; sid:{sid}; rev:1;)'
        ),
    )

    result = RuleParser().parse(source)

    assert result.status == "valid", result.reason
    assert result.rule is not None

    return result.rule


def make_event(
    protocol="TCP",
    src_port=1500,
    dst_port=80,
    **changes,
):
    fields = {
        "packet_id": 1,
        "timestamp": 1000.0,
        "network_protocol": "IPv4",
        "transport_protocol": protocol,
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.20",
        "src_port": src_port,
        "dst_port": dst_port,
        "payload": b"",
        "payload_length": 0,
    }

    fields.update(changes)

    return NormalizedIDSEvent(**fields)


def candidate_sids(repository, event):
    return [
        rule.sid
        for rule in repository.get_candidates(event)
    ]


@pytest.fixture
def repository():
    repo = RuleRepository()

    rules = [
        make_rule(header, sid)
        for sid, header in RULE_SPECS
    ]

    assert repo.add_many(rules) == len(RULE_SPECS)
    assert len(repo) == len(RULE_SPECS)

    return repo


@pytest.mark.parametrize(
    ("protocol", "src_port", "dst_port", "expected"),
    [
        pytest.param(
            "TCP", 50000, 80,
            [6101, 6103, 6107],
            id="tcp-exact-80",
        ),
        pytest.param(
            "UDP", 50000, 80,
            [6102, 6104],
            id="udp-exact-80",
        ),
        pytest.param(
            "TCP", 1500, 443,
            [6103, 6105, 6107],
            id="tcp-source-range",
        ),
        pytest.param(
            "TCP", 1000, 443,
            [6103, 6105, 6107],
            id="source-range-lower-bound",
        ),
        pytest.param(
            "TCP", 2000, 443,
            [6103, 6105, 6107],
            id="source-range-upper-bound",
        ),
        pytest.param(
            "TCP", 999, 443,
            [6103, 6107],
            id="source-range-below",
        ),
        pytest.param(
            "TCP", 2001, 443,
            [6103, 6107],
            id="source-range-above",
        ),
        pytest.param(
            "TCP", 1234, 443,
            [6103, 6105, 6107, 6109],
            id="bidirectional-forward",
        ),
        pytest.param(
            "TCP", 443, 1234,
            [6103, 6109],
            id="bidirectional-reverse",
        ),
        pytest.param(
            "TCP", 443, 1235,
            [6103],
            id="bidirectional-wrong-reverse-port",
        ),
        pytest.param(
            "TCP", 80, 12345,
            [6103, 6114],
            id="source-exact-destination-any",
        ),
        pytest.param(
            "TCP", 1500, 8000,
            [6103, 6106],
            id="destination-range-lower",
        ),
        pytest.param(
            "TCP", 1500, 9000,
            [6103, 6106],
            id="destination-range-upper",
        ),
        pytest.param(
            "TCP", 1500, 7999,
            [6103],
            id="destination-range-below",
        ),
        pytest.param(
            "TCP", 1500, 9001,
            [6103],
            id="destination-range-above",
        ),
        pytest.param(
            "TCP", 1500, 1024,
            [6103, 6107],
            id="open-lower-range-boundary",
        ),
        pytest.param(
            "TCP", 1500, 1025,
            [6103],
            id="open-lower-range-outside",
        ),
        pytest.param(
            "TCP", 1500, 49152,
            [6103, 6108],
            id="open-upper-range-boundary",
        ),
        pytest.param(
            "TCP", 1500, 65535,
            [6103, 6108],
            id="open-upper-range-maximum",
        ),
        pytest.param(
            "TCP", 0, 0,
            [6103, 6107, 6111],
            id="minimum-port-zero",
        ),
        pytest.param(
            "TCP", 65535, 65535,
            [6103, 6108, 6112],
            id="maximum-port-65535",
        ),
        pytest.param(
            "TCP", 2222, 443,
            [6103, 6107, 6110],
            id="cidr-rule-candidate",
        ),
        pytest.param(
            "UDP", 5353, 53,
            [6104, 6113],
            id="udp-bidirectional-forward",
        ),
        pytest.param(
            "UDP", 53, 5353,
            [6104, 6113],
            id="udp-bidirectional-reverse",
        ),
        pytest.param(
            "UDP", 5354, 53,
            [6104],
            id="udp-bidirectional-source-mismatch",
        ),
        pytest.param(
            "TCP", 1500, 53,
            [6103, 6107],
            id="tcp-not-matched-with-udp-53",
        ),
        pytest.param(
            "TCP", 80, 80,
            [6101, 6103, 6107, 6114],
            id="multiple-index-buckets",
        ),
        pytest.param(
            "UDP", 0, 0,
            [6104],
            id="udp-any-port",
        ),
    ],
)
def test_t06_candidate_index_matrix(
    repository,
    protocol,
    src_port,
    dst_port,
    expected,
):
    event = make_event(
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
    )

    assert candidate_sids(repository, event) == expected


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param(
            {"transport_protocol": None},
            id="missing-protocol",
        ),
        pytest.param(
            {"transport_protocol": "ICMP"},
            id="unsupported-protocol",
        ),
        pytest.param(
            {"transport_protocol": ""},
            id="empty-protocol",
        ),
        pytest.param(
            {"transport_protocol": 6},
            id="numeric-protocol",
        ),
        pytest.param(
            {"src_port": None},
            id="missing-source-port",
        ),
        pytest.param(
            {"src_port": -1},
            id="negative-source-port",
        ),
        pytest.param(
            {"dst_port": 65536},
            id="destination-port-overflow",
        ),
        pytest.param(
            {"src_port": True},
            id="boolean-source-port",
        ),
        pytest.param(
            {"dst_port": 80.0},
            id="float-destination-port",
        ),
        pytest.param(
            {"src_port": "1500"},
            id="string-source-port",
        ),
    ],
)
def test_t06_invalid_event_returns_no_candidates(
    repository,
    changes,
):
    event = make_event(**changes)

    assert repository.get_candidates(event) == []


def test_t06_add_many_and_get():
    repo = RuleRepository()

    rules = [
        make_rule(header, sid)
        for sid, header in RULE_SPECS
    ]

    assert repo.add_many(rules) == 14
    assert len(repo) == 14

    for rule in rules:
        assert repo.get(rule.sid) is rule

    assert repo.get(999999) is None


def test_t06_protocol_case_insensitive(repository):
    tcp_event = make_event(
        protocol="tCp",
        src_port=1500,
        dst_port=443,
    )

    udp_event = make_event(
        protocol="uDp",
        src_port=50000,
        dst_port=80,
    )

    assert candidate_sids(repository, tcp_event) == [
        6103, 6105, 6107
    ]

    assert candidate_sids(repository, udp_event) == [
        6102, 6104
    ]


def test_t06_preserve_insertion_order_not_sid_order():
    repo = RuleRepository()

    rules = [
        make_rule("alert tcp any any -> any 80", 6303),
        make_rule("alert tcp any any -> any any", 6301),
        make_rule("alert tcp any any -> any 80", 6302),
    ]

    assert repo.add_many(rules) == 3

    event = make_event(
        src_port=50000,
        dst_port=80,
    )

    assert candidate_sids(repo, event) == [
        6303, 6301, 6302
    ]


def test_t06_bidirectional_overlapping_indexes_no_duplicates():
    repo = RuleRepository()

    repo.add_many([
        make_rule(
            "alert tcp any any <> any any",
            6201,
        ),
        make_rule(
            "alert tcp any 1234 <> any 1234",
            6202,
        ),
    ])

    event = make_event(
        src_port=1234,
        dst_port=1234,
    )

    candidates = repo.get_candidates(event)
    sids = [rule.sid for rule in candidates]

    assert sids == [6201, 6202]
    assert len(sids) == len(set(sids))


def test_t06_repository_filters_ports_but_not_ip(repository):
    event = make_event(
        src_port=2222,
        dst_port=443,
        src_ip="172.16.1.10",
        dst_ip="192.168.1.20",
    )

    # SID 6110 has matching protocol/ports,
    # but the source/destination IPs do not match.
    assert candidate_sids(repository, event) == [
        6103, 6107, 6110
    ]

    result = RuleEvaluationEngine(repository).evaluate(event)

    assert result.candidate_count == 3
    assert result.matched_sids == [6103, 6107]

    # With IPs matching SID 6110, it also matches fully.
    matching_event = make_event(
        src_port=2222,
        dst_port=443,
        src_ip="10.0.0.20",
        dst_ip="192.0.2.50",
    )

    matching_result = RuleEvaluationEngine(
        repository
    ).evaluate(matching_event)

    assert matching_result.matched_sids == [
        6103, 6107, 6110
    ]


def test_t06_duplicate_sid_keeps_existing_indexes(repository):
    original = repository.get(6101)

    before = candidate_sids(
        repository,
        make_event(src_port=50000, dst_port=80),
    )

    with pytest.raises(ValueError, match="duplicate SID"):
        repository.add(
            make_rule(
                "alert tcp any any -> any 9999",
                6101,
            )
        )

    assert len(repository) == 14
    assert repository.get(6101) is original

    assert candidate_sids(
        repository,
        make_event(src_port=50000, dst_port=80),
    ) == before

    assert candidate_sids(
        repository,
        make_event(src_port=1500, dst_port=9999),
    ) == [6103]


def test_t06_clear_resets_forward_reverse_indexes(repository):
    tcp_event = make_event(
        src_port=1234,
        dst_port=443,
    )

    reverse_event = make_event(
        src_port=443,
        dst_port=1234,
    )

    assert 6109 in candidate_sids(repository, tcp_event)
    assert 6109 in candidate_sids(repository, reverse_event)

    repository.clear()

    assert len(repository) == 0
    assert repository.get(6109) is None

    assert repository.get_candidates(tcp_event) == []
    assert repository.get_candidates(reverse_event) == []

    repository.add(
        make_rule(
            "alert udp any any -> any 53",
            6999,
        )
    )

    assert len(repository) == 1

    assert candidate_sids(
        repository,
        make_event(
            protocol="UDP",
            src_port=50000,
            dst_port=53,
        ),
    ) == [6999]

    assert repository.get_candidates(tcp_event) == []


def test_t06_repository_evaluator_integration(repository):
    engine = RuleEvaluationEngine(repository)

    tcp_event = make_event(
        protocol="TCP",
        src_port=1234,
        dst_port=443,
    )

    udp_event = make_event(
        protocol="UDP",
        src_port=5353,
        dst_port=53,
    )

    tcp_result = engine.evaluate(tcp_event)
    udp_result = engine.evaluate(udp_event)

    assert tcp_result.status == "MATCH"
    assert tcp_result.candidate_count == 4
    assert tcp_result.matched_sids == [
        6103, 6105, 6107, 6109
    ]

    assert udp_result.status == "MATCH"
    assert udp_result.candidate_count == 2
    assert udp_result.matched_sids == [
        6104, 6113
    ]

    assert engine.get_stats() == {
        "events_evaluated": 2,
        "candidate_rules": 6,
        "match_count": 6,
        "matched_events": 2,
    }
