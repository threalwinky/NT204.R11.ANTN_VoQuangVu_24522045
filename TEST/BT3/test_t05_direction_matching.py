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


CLIENT = "10.0.0.10"
SERVER = "192.168.1.20"

SINGLE = (
    "alert tcp 10.0.0.10 1500 -> 192.168.1.20 443"
)

DOUBLE = (
    "alert tcp 10.0.0.10 1500 <> 192.168.1.20 443"
)

CIDR_UNI = (
    "alert tcp 10.0.0.0/24 1000:2000 "
    "-> 192.168.1.0/24 443"
)

CIDR_BI = (
    "alert tcp 10.0.0.0/24 1000:2000 "
    "<> 192.168.1.0/24 443"
)

UDP_UNI = (
    "alert udp 10.0.0.10 1500 -> 192.168.1.20 443"
)

UDP_BI = (
    "alert udp 10.0.0.10 1500 <> 192.168.1.20 443"
)


def make_rule(header, sid=5101):
    source = RuleSource(
        path=Path("t05.rules"),
        line_number=1,
        text=(
            f'{header} '
            f'(msg:"T05 Direction"; sid:{sid}; rev:1;)'
        ),
    )

    result = RuleParser().parse(source)

    assert result.status == "valid", result.reason
    assert result.rule is not None

    return result.rule


def make_event(reverse=False, **changes):
    fields = {
        "packet_id": 1,
        "timestamp": 1000.0,
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "src_ip": CLIENT,
        "dst_ip": SERVER,
        "src_port": 1500,
        "dst_port": 443,
        "payload": b"",
        "payload_length": 0,
    }

    if reverse:
        fields["src_ip"], fields["dst_ip"] = (
            fields["dst_ip"],
            fields["src_ip"],
        )

        fields["src_port"], fields["dst_port"] = (
            fields["dst_port"],
            fields["src_port"],
        )

    fields.update(changes)

    return NormalizedIDSEvent(**fields)


@pytest.mark.parametrize(
    ("header", "reverse", "changes", "expected"),
    [
        pytest.param(
            SINGLE, False, {}, True,
            id="tcp-oneway-forward",
        ),
        pytest.param(
            SINGLE, True, {}, False,
            id="tcp-oneway-reverse-rejected",
        ),
        pytest.param(
            DOUBLE, False, {}, True,
            id="tcp-bidirectional-forward",
        ),
        pytest.param(
            DOUBLE, True, {}, True,
            id="tcp-bidirectional-reverse",
        ),
        pytest.param(
            CIDR_UNI, False, {}, True,
            id="cidr-oneway-forward",
        ),
        pytest.param(
            CIDR_UNI, True, {}, False,
            id="cidr-oneway-reverse-rejected",
        ),
        pytest.param(
            CIDR_BI, True, {}, True,
            id="cidr-bidirectional-reverse",
        ),
        pytest.param(
            CIDR_BI, False,
            {"src_ip": "10.0.1.10"},
            False,
            id="cidr-outside-source-network",
        ),
        pytest.param(
            SINGLE, False,
            {"src_port": 999},
            False,
            id="wrong-source-port",
        ),
        pytest.param(
            SINGLE, False,
            {"dst_port": 444},
            False,
            id="wrong-destination-port",
        ),
        pytest.param(
            DOUBLE, True,
            {"src_port": 444},
            False,
            id="bidirectional-wrong-reverse-port",
        ),
        pytest.param(
            UDP_UNI, False,
            {"transport_protocol": "UDP"},
            True,
            id="udp-oneway-forward",
        ),
        pytest.param(
            UDP_UNI, True,
            {"transport_protocol": "UDP"},
            False,
            id="udp-oneway-reverse-rejected",
        ),
        pytest.param(
            UDP_BI, True,
            {"transport_protocol": "UDP"},
            True,
            id="udp-bidirectional-reverse",
        ),
        pytest.param(
            UDP_BI, False, {}, False,
            id="protocol-mismatch",
        ),
        pytest.param(
            "alert tcp any any <> any any",
            True, {}, True,
            id="wildcard-bidirectional",
        ),
        pytest.param(
            CIDR_UNI, False,
            {"src_port": 1000},
            True,
            id="port-range-lower-bound",
        ),
        pytest.param(
            CIDR_UNI, False,
            {"src_port": 2000},
            True,
            id="port-range-upper-bound",
        ),
        pytest.param(
            CIDR_UNI, False,
            {"src_port": 2001},
            False,
            id="port-range-outside",
        ),
        pytest.param(
            DOUBLE, False,
            {"network_protocol": "IPv6"},
            False,
            id="non-ipv4-rejected",
        ),
    ],
)
def test_t05_header_direction(
    header, reverse, changes, expected
):
    rule = make_rule(header)
    event = make_event(reverse=reverse, **changes)

    matcher = RuleMatcher()

    assert matcher.match_header(rule, event) is expected


def test_t05_repository_candidates_both_directions():
    repository = RuleRepository()

    repository.add_many([
        make_rule(CIDR_UNI, 5201),
        make_rule(CIDR_BI, 5202),
        make_rule(
            "alert udp 10.0.0.0/24 1000:2000 "
            "<> 192.168.1.0/24 443",
            5203,
        ),
    ])

    forward = make_event()
    reverse = make_event(reverse=True)

    assert [
        rule.sid
        for rule in repository.get_candidates(forward)
    ] == [5201, 5202]

    assert [
        rule.sid
        for rule in repository.get_candidates(reverse)
    ] == [5202]

    udp_forward = make_event(
        transport_protocol="UDP",
    )
    udp_reverse = make_event(
        reverse=True,
        transport_protocol="UDP",
    )

    assert [
        rule.sid
        for rule in repository.get_candidates(udp_forward)
    ] == [5203]

    assert [
        rule.sid
        for rule in repository.get_candidates(udp_reverse)
    ] == [5203]


def test_t05_bidirectional_rule_is_not_duplicated():
    repository = RuleRepository()

    repository.add(
        make_rule(
            "alert tcp any any <> any any",
            sid=5301,
        )
    )

    event = make_event(
        src_ip="10.0.0.10",
        dst_ip="10.0.0.10",
        src_port=1500,
        dst_port=1500,
    )

    candidates = repository.get_candidates(event)

    assert len(candidates) == 1
    assert [rule.sid for rule in candidates] == [5301]

    result = RuleEvaluationEngine(repository).evaluate(event)

    assert result.status == "MATCH"
    assert result.candidate_count == 1
    assert result.match_count == 1
    assert result.matched_sids == [5301]


def test_t05_repository_candidate_still_requires_ip_match():
    repository = RuleRepository()

    repository.add(
        make_rule(
            "alert tcp 172.16.0.0/16 1000:2000 "
            "-> 192.168.1.20 443",
            sid=5401,
        )
    )

    event = make_event()

    # Repository indexes protocol and ports only.
    candidates = repository.get_candidates(event)

    assert [rule.sid for rule in candidates] == [5401]

    # Matcher must reject the incorrect source IP.
    matcher = RuleMatcher()

    assert not matcher.match_header(candidates[0], event)

    result = RuleEvaluationEngine(repository).evaluate(event)

    assert result.status == "NO_MATCH"
    assert result.candidate_count == 1
    assert result.match_count == 0


def test_t05_engine_multi_match_and_statistics():
    repository = RuleRepository()

    repository.add_many([
        make_rule(CIDR_UNI, 5501),
        make_rule(CIDR_BI, 5502),
        make_rule(
            "alert tcp 172.16.0.0/16 1000:2000 "
            "-> 192.168.1.20 443",
            5503,
        ),
    ])

    engine = RuleEvaluationEngine(repository)

    forward = engine.evaluate(make_event())
    reverse = engine.evaluate(make_event(reverse=True))

    assert forward.status == "MATCH"
    assert forward.candidate_count == 3
    assert forward.matched_sids == [5501, 5502]
    assert forward.match_count == 2

    assert reverse.status == "MATCH"
    assert reverse.candidate_count == 1
    assert reverse.matched_sids == [5502]
    assert reverse.match_count == 1

    assert engine.get_stats() == {
        "events_evaluated": 2,
        "candidate_rules": 4,
        "match_count": 3,
        "matched_events": 2,
    }


def test_t05_header_direction_independent_of_flow_direction():
    rule = make_rule(DOUBLE, sid=5601)

    # Reversed packet direction based on the Snort header.
    event = make_event(
        reverse=True,
        flow_direction="forward",
    )

    matcher = RuleMatcher()

    # Header direction is checked using packet endpoints,
    # not the FlowTracker's forward/backward label.
    assert matcher.match_header(rule, event)
    assert matcher.match_header_flow(rule, event)
