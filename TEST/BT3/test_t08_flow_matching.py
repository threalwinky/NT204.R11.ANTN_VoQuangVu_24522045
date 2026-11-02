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
CLIENT_PORT = 50000
SERVER_PORT = 80
HEADER = (
    "alert tcp 10.0.0.10 50000 "
    "<> 192.168.1.20 80"
)


def make_rule(flow=None, sid=8101, header=HEADER):
    option = f"flow:{flow}; " if flow is not None else ""
    source = RuleSource(
        path=Path("t08.rules"),
        line_number=sid,
        text=(
            f'{header} (msg:"T08 Flow"; sid:{sid}; '
            f'rev:1; {option})'
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
        "src_port": CLIENT_PORT,
        "dst_port": SERVER_PORT,
        "flow_id": "flow-t08",
        "flow_direction": "backward" if reverse else "forward",
        "tcp_state": "ESTABLISHED",
        "payload": b"",
        "payload_length": 0,
    }
    if reverse:
        fields["src_ip"], fields["dst_ip"] = (
            fields["dst_ip"], fields["src_ip"]
        )
        fields["src_port"], fields["dst_port"] = (
            fields["dst_port"], fields["src_port"]
        )
    fields.update(changes)
    return NormalizedIDSEvent(**fields)


def flow_context(**changes):
    context = {
        "flow_id": "flow-t08",
        "initiator": {"ip": CLIENT, "port": CLIENT_PORT},
        "responder": {"ip": SERVER, "port": SERVER_PORT},
        "tcp_state": "ESTABLISHED",
    }
    context.update(changes)
    return context


@pytest.mark.parametrize(
    ("flow", "reverse", "changes", "expected"),
    [
        pytest.param("to_server", False, {}, True, id="to-server-forward"),
        pytest.param("to_server", True, {}, False, id="to-server-backward"),
        pytest.param("to_client", True, {}, True, id="to-client-backward"),
        pytest.param("to_client", False, {}, False, id="to-client-forward"),
        pytest.param("established", False, {}, True, id="established"),
        pytest.param("established", False, {"tcp_state": "established"}, True, id="established-lowercase"),
        pytest.param("established", False, {"tcp_state": "NEW"}, False, id="established-reject-new"),
        pytest.param("established", False, {"tcp_state": "HANDSHAKE"}, False, id="established-reject-handshake"),
        pytest.param("established", False, {"tcp_state": "CLOSED"}, False, id="established-reject-closed"),
        pytest.param("established", False, {"tcp_state": "RESET"}, False, id="established-reject-reset"),
        pytest.param("established", False, {"tcp_state": None}, False, id="established-missing-state"),
        pytest.param("not_established", False, {"tcp_state": "NEW"}, True, id="not-established-new"),
        pytest.param("not_established", False, {"tcp_state": "HANDSHAKE"}, True, id="not-established-handshake"),
        pytest.param("not_established", False, {"tcp_state": "CLOSED"}, True, id="not-established-closed"),
        pytest.param("not_established", False, {"tcp_state": "RESET"}, True, id="not-established-reset"),
        pytest.param("not_established", False, {}, False, id="not-established-reject-established"),
        pytest.param("not_established", False, {"tcp_state": "UNKNOWN"}, False, id="not-established-unknown"),
        pytest.param("not_established", False, {"tcp_state": None}, False, id="not-established-missing-state"),
        pytest.param("to_server,established", False, {}, True, id="server-established"),
        pytest.param("to_server,established", True, {}, False, id="server-established-wrong-direction"),
        pytest.param("to_server,established", False, {"tcp_state": "NEW"}, False, id="server-established-wrong-state"),
        pytest.param("to_client,established", True, {}, True, id="client-established"),
        pytest.param("to_client,established", False, {}, False, id="client-established-wrong-direction"),
        pytest.param("to_client,established", True, {"tcp_state": "RESET"}, False, id="client-established-wrong-state"),
        pytest.param("to_server,not_established", False, {"tcp_state": "NEW"}, True, id="server-new"),
        pytest.param("to_server,not_established", True, {"tcp_state": "NEW"}, False, id="server-new-reversed"),
        pytest.param("to_client,not_established", True, {"tcp_state": "RESET"}, True, id="client-reset"),
        pytest.param("to_client,not_established", False, {"tcp_state": "RESET"}, False, id="client-reset-wrong-direction"),
        pytest.param("to_server", False, {"flow_direction": None}, False, id="missing-direction-server"),
        pytest.param("to_client", False, {"flow_direction": None}, False, id="missing-direction-client"),
        pytest.param(None, False, {"flow_direction": None, "tcp_state": None}, True, id="rule-without-flow-option"),
        pytest.param("TO_SERVER,ESTABLISHED", False, {}, True, id="uppercase-flow-terms"),
        pytest.param("established", False, {"transport_protocol": "UDP"}, False, id="udp-cannot-be-established"),
        pytest.param("not_established", False, {"transport_protocol": "UDP", "tcp_state": "NEW"}, False, id="udp-cannot-match-not-established"),
    ],
)
def test_t08_flow_option_matrix(flow, reverse, changes, expected):
    rule = make_rule(flow)
    event = make_event(reverse=reverse, **changes)
    assert RuleMatcher().match_flow(rule, event) is expected


@pytest.mark.parametrize(
    ("flow", "reverse", "event_changes", "context_changes", "expected"),
    [
        pytest.param("to_server,established", False, {}, {}, True, id="context-forward-established"),
        pytest.param("to_client,established", True, {}, {}, True, id="context-backward-established"),
        pytest.param("to_server", True, {}, {}, False, id="context-direction-mismatch"),
        pytest.param("to_server,established", False, {}, {"tcp_state": "NEW"}, False, id="context-state-new"),
        pytest.param("to_server", False, {}, {"flow_id": "another-flow"}, False, id="context-flow-id-mismatch"),
        pytest.param("to_server", False, {}, {"flow_id": None}, True, id="context-missing-flow-id"),
        pytest.param("to_server", False, {"flow_id": None}, {"flow_id": "another-flow"}, True, id="event-missing-flow-id"),
        pytest.param("to_server", False, {}, {"initiator": None}, False, id="missing-initiator"),
        pytest.param("to_client", True, {}, {"responder": None}, False, id="missing-responder"),
        pytest.param("to_server", False, {"flow_direction": "backward"}, {}, False, id="event-direction-precedence"),
        pytest.param("established", False, {"tcp_state": "NEW"}, {}, False, id="event-tcp-state-precedence"),
    ],
)
def test_t08_explicit_flow_context(
    flow, reverse, event_changes, context_changes, expected
):
    # Context is used when event fields are missing.
    fields = {"flow_direction": None, "tcp_state": None}
    fields.update(event_changes)
    event = make_event(reverse=reverse, **fields)
    context = flow_context(**context_changes)
    assert RuleMatcher().match_flow(rule=make_rule(flow), event=event, flow_context=context) is expected


def test_t08_implicit_event_flow_statistics():
    rule = make_rule("to_server,established")
    event = make_event(
        flow_direction=None,
        tcp_state=None,
        flow_statistics=flow_context(),
    )
    assert RuleMatcher().match_flow(rule, event)
    assert RuleMatcher().match_header_flow(rule, event)


def test_t08_explicit_context_overrides_event_statistics():
    rule = make_rule("to_server,established")
    event = make_event(
        flow_direction=None,
        tcp_state=None,
        flow_statistics=flow_context(flow_id="incorrect"),
    )
    matcher = RuleMatcher()
    assert not matcher.match_flow(rule, event)
    assert matcher.match_flow(rule, event, flow_context())


def test_t08_invalid_flow_context_and_no_flow_option():
    event = make_event(flow_direction=None, tcp_state=None)
    matcher = RuleMatcher()
    assert not matcher.match_flow(make_rule("to_server"), event, [])
    assert matcher.match_flow(make_rule(None), event, [])


def test_t08_header_direction_is_separate_from_flow_direction():
    rule = make_rule(
        "to_client",
        header="alert tcp 10.0.0.10 50000 -> 192.168.1.20 80",
    )
    event = make_event(reverse=True)
    matcher = RuleMatcher()
    assert matcher.match_flow(rule, event)
    assert not matcher.match_header(rule, event)
    assert not matcher.match_header_flow(rule, event)


def test_t08_engine_flow_rules_and_statistics():
    repository = RuleRepository()
    repository.add_many([
        make_rule("to_server,established", 8201),
        make_rule("to_client,established", 8202),
        make_rule("to_server,not_established", 8203),
        make_rule("to_client,not_established", 8204),
        make_rule(None, 8205),
    ])
    engine = RuleEvaluationEngine(repository)
    events = [
        make_event(),
        make_event(reverse=True),
        make_event(tcp_state="NEW"),
        make_event(reverse=True, tcp_state="RESET"),
    ]
    results = engine.evaluate_many(events)
    assert [result.candidate_count for result in results] == [5, 5, 5, 5]
    assert [result.matched_sids for result in results] == [
        [8201, 8205],
        [8202, 8205],
        [8203, 8205],
        [8204, 8205],
    ]
    assert all(result.status == "MATCH" for result in results)
    assert engine.get_stats() == {
        "events_evaluated": 4,
        "candidate_rules": 20,
        "match_count": 8,
        "matched_events": 4,
    }


def test_t08_engine_explicit_context_and_flow_id_guard():
    repository = RuleRepository()
    repository.add_many([
        make_rule("to_server,established", 8301),
        make_rule(None, 8302),
    ])
    engine = RuleEvaluationEngine(repository)
    event = make_event(flow_direction=None, tcp_state=None)

    accepted = engine.evaluate(event, flow_context())
    rejected = engine.evaluate(
        event,
        flow_context(flow_id="wrong-flow"),
    )

    assert accepted.matched_sids == [8301, 8302]
    # Flow ID protects only rules that require flow matching.
    assert rejected.matched_sids == [8302]
    assert engine.get_stats() == {
        "events_evaluated": 2,
        "candidate_rules": 4,
        "match_count": 3,
        "matched_events": 2,
    }
