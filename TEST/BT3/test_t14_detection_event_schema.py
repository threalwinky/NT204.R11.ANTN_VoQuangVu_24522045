"""BT3 T14: DetectionEvent schema, generation, and serialization.

These tests target the current modules.engine.detection implementation.
"""

import json
from dataclasses import FrozenInstanceError, asdict, fields, replace
from pathlib import Path

import pytest

from modules.engine import (
    DetectionEvent,
    DetectionEventGenerator,
    EvaluationResult,
    RuleEvaluationEngine,
    RuleMatch,
    RuleParser,
    RuleRepository,
    RuleSource,
)
from modules.models import NormalizedIDSEvent


HEADER = "alert tcp any any -> any 80"
GENERATOR = DetectionEventGenerator()


def make_rule(sid=14101, rev=1, msg="T14 Detection", options="", header=HEADER):
    source = RuleSource(
        path=Path("t14.rules"),
        line_number=sid,
        text=(
            f'{header} (msg:"{msg}"; sid:{sid}; '
            f'rev:{rev}; {options})'
        ),
    )
    parsed = RuleParser().parse(source)
    assert parsed.status == "valid", parsed.reason
    assert parsed.rule is not None
    return parsed.rule


def make_event(payload=b"GET /ADMIN", **changes):
    values = {
        "packet_id": 14,
        "timestamp": 1700000000.125,
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.20",
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "src_port": 50000,
        "dst_port": 80,
        "application_protocol": "HTTP",
        "tcp_flags": "SA",
        "payload": payload,
        "payload_length": len(payload),
        "flow_id": "flow-14",
        "flow_direction": "forward",
        "tcp_state": "ESTABLISHED",
    }
    values.update(changes)
    return NormalizedIDSEvent(**values)


def make_result(rule=None, event=None, details=None):
    rule = rule if rule is not None else make_rule()
    event = event if event is not None else make_event()
    if details is None:
        details = {
            "matched_field": "payload",
            "matched_content": [
                {"content": "GET", "start": 0, "end": 3},
            ],
        }
    return EvaluationResult(
        event=event,
        matches=[RuleMatch(rule=rule, details=details)],
    )


def one_detection(result=None):
    result = result if result is not None else make_result()
    detections = GENERATOR.generate(result)
    assert len(detections) == 1
    assert isinstance(detections[0], DetectionEvent)
    return detections[0]


def test_t14_schema_has_exact_expected_fields():
    names = {item.name for item in fields(DetectionEvent)}
    assert names == {
        "timestamp", "packet_id", "sid", "rev", "msg",
        "src_ip", "dst_ip", "src_port", "dst_port",
        "network_protocol", "transport_protocol", "application_protocol",
        "flow_id", "matched_info", "classtype", "priority",
        "flow_direction", "tcp_state", "action", "record_type",
    }
    assert set(one_detection().to_dict()) == names


def test_t14_full_detection_schema_values():
    rule = make_rule(
        sid=14102,
        rev=3,
        msg="T14 Full Record",
        options='classtype:attempted-admin; priority:2; content:"GET";',
    )
    event = make_event()
    repository = RuleRepository()
    repository.add(rule)
    evaluated = RuleEvaluationEngine(repository).evaluate(event)
    assert evaluated.matched_sids == [14102]
    detection = one_detection(evaluated)
    assert detection.to_dict() == {
        "timestamp": 1700000000.125,
        "packet_id": 14,
        "sid": 14102,
        "rev": 3,
        "msg": "T14 Full Record",
        "src_ip": "10.0.0.10",
        "dst_ip": "192.168.1.20",
        "src_port": 50000,
        "dst_port": 80,
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "application_protocol": "HTTP",
        "flow_id": "flow-14",
        "matched_info": {
            "matched_field": "payload",
            "matched_content": [
                {"content": "GET", "start": 0, "end": 3},
            ],
        },
        "classtype": "attempted-admin",
        "priority": 2,
        "flow_direction": "forward",
        "tcp_state": "ESTABLISHED",
        "action": "alert",
        "record_type": "detection",
    }


@pytest.mark.parametrize(
    ("name", "value"),
    [
        pytest.param("timestamp", 0.0, id="timestamp-zero"),
        pytest.param("timestamp", 2000000000.75, id="timestamp-fraction"),
        pytest.param("packet_id", 0, id="packet-id-zero"),
        pytest.param("packet_id", 987654, id="packet-id-large"),
        pytest.param("src_ip", None, id="missing-source-ip"),
        pytest.param("dst_ip", None, id="missing-destination-ip"),
        pytest.param("src_port", None, id="missing-source-port"),
        pytest.param("dst_port", None, id="missing-destination-port"),
        pytest.param("network_protocol", None, id="missing-network-protocol"),
        pytest.param("transport_protocol", None, id="missing-transport-protocol"),
        pytest.param("application_protocol", None, id="missing-app-protocol"),
        pytest.param("application_protocol", "DNS", id="dns-app-protocol"),
        pytest.param("flow_id", None, id="missing-flow-id"),
        pytest.param("flow_id", "other-flow", id="another-flow-id"),
        pytest.param("flow_direction", None, id="missing-flow-direction"),
        pytest.param("flow_direction", "backward", id="backward-flow"),
        pytest.param("tcp_state", None, id="missing-tcp-state"),
        pytest.param("tcp_state", "RESET", id="reset-state"),
    ],
)
def test_t14_event_metadata_is_copied_from_event(name, value):
    event = make_event(**{name: value})
    detection = one_detection(make_result(event=event))
    assert getattr(detection, name) == value
    assert detection.to_dict()[name] == value


@pytest.mark.parametrize(
    ("name", "value"),
    [
        pytest.param("sid", 1, id="minimum-valid-sid"),
        pytest.param("sid", 2**32, id="large-sid"),
        pytest.param("rev", 1, id="minimum-valid-rev"),
        pytest.param("rev", 99999, id="large-rev"),
        pytest.param("msg", "", id="empty-message-string-accepted"),
        pytest.param("msg", "Phát hiện bất thường", id="unicode-message"),
        pytest.param("msg", "new message", id="message-changed"),
        pytest.param("classtype", None, id="missing-classtype"),
        pytest.param("classtype", "web-application-attack", id="classtype-value"),
        pytest.param("priority", None, id="missing-priority"),
        pytest.param("priority", 1, id="priority-one"),
        pytest.param("priority", 0, id="priority-zero-copied"),
    ],
)
def test_t14_rule_metadata_is_copied_from_rule(name, value):
    rule = make_rule()
    setattr(rule, name, value)
    detection = one_detection(make_result(rule=rule))
    assert getattr(detection, name) == value
    assert detection.to_dict()[name] == value


@pytest.mark.parametrize(
    ("name", "value"),
    [
        pytest.param("sid", None, id="sid-none"),
        pytest.param("sid", 0, id="sid-zero"),
        pytest.param("sid", -1, id="sid-negative"),
        pytest.param("sid", True, id="sid-boolean"),
        pytest.param("sid", 14101.0, id="sid-float"),
        pytest.param("sid", "14101", id="sid-string"),
        pytest.param("sid", [], id="sid-list"),
        pytest.param("sid", {}, id="sid-dict"),
        pytest.param("rev", None, id="rev-none"),
        pytest.param("rev", 0, id="rev-zero"),
        pytest.param("rev", -1, id="rev-negative"),
        pytest.param("rev", True, id="rev-boolean"),
        pytest.param("rev", 1.0, id="rev-float"),
        pytest.param("rev", "1", id="rev-string"),
        pytest.param("rev", [], id="rev-list"),
        pytest.param("rev", {}, id="rev-dict"),
        pytest.param("msg", None, id="msg-none"),
        pytest.param("msg", 42, id="msg-integer"),
        pytest.param("msg", False, id="msg-boolean"),
        pytest.param("msg", b"text", id="msg-bytes"),
        pytest.param("msg", [], id="msg-list"),
        pytest.param("msg", {}, id="msg-dict"),
    ],
)
def test_t14_invalid_rule_metadata_raises_value_error(name, value):
    rule = make_rule()
    setattr(rule, name, value)
    result = make_result(rule=rule)
    with pytest.raises(ValueError, match="valid sid, rev and msg"):
        GENERATOR.generate(result)


def test_t14_rule_header_action_is_preserved():
    rule = make_rule()
    rule.header = replace(rule.header, action="drop")
    detection = one_detection(make_result(rule=rule))
    assert detection.action == "drop"
    assert detection.record_type == "detection"


def test_t14_optional_metadata_defaults_to_none():
    detection = one_detection()
    assert detection.classtype is None
    assert detection.priority is None
    assert detection.action == "alert"
    assert detection.record_type == "detection"


def test_t14_detection_is_frozen_but_nested_info_is_mutable():
    detection = one_detection()
    with pytest.raises(FrozenInstanceError):
        detection.sid = 20000
    with pytest.raises(FrozenInstanceError):
        detection.packet_id = 20000
    detection.matched_info["matched_content"][0]["start"] = 7
    assert detection.matched_info["matched_content"][0]["start"] == 7


def test_t14_generate_deepcopies_matched_info():
    details = {
        "matched_field": "payload",
        "matched_content": [{"content": "GET", "start": 0, "end": 3}],
        "nested": {"items": [{"value": 1}]},
    }
    result = make_result(details=details)
    detection = one_detection(result)
    assert detection.matched_info == details
    assert detection.matched_info is not details
    assert detection.matched_info["nested"] is not details["nested"]

    details["nested"]["items"][0]["value"] = 99
    assert detection.matched_info["nested"]["items"][0]["value"] == 1
    detection.matched_info["matched_content"][0]["start"] = 10
    assert details["matched_content"][0]["start"] == 0


def test_t14_generate_twice_produces_independent_objects():
    result = make_result()
    first = one_detection(result)
    second = one_detection(result)
    assert first is not second
    assert first.matched_info is not second.matched_info
    first.matched_info["matched_content"][0]["start"] = 8
    assert second.matched_info["matched_content"][0]["start"] == 0
    assert result.matches[0].details["matched_content"][0]["start"] == 0


def test_t14_to_dict_is_deepcopy_of_nested_info():
    detection = one_detection()
    record = detection.to_dict()
    assert record == asdict(detection)
    assert record["matched_info"] == detection.matched_info
    assert record["matched_info"] is not detection.matched_info
    record["matched_info"]["matched_content"][0]["start"] = 99
    assert detection.matched_info["matched_content"][0]["start"] == 0


def test_t14_json_roundtrip_of_detection_dictionary():
    detection = one_detection()
    record = detection.to_dict()
    encoded = json.dumps(record, ensure_ascii=False)
    restored = json.loads(encoded)
    assert restored == record
    assert isinstance(restored["matched_info"]["matched_content"], list)
    assert restored["record_type"] == "detection"
    assert "payload" not in restored
    assert "payload_base64" not in restored


def test_t14_no_matches_generates_no_detections():
    event = make_event()
    empty = EvaluationResult(event=event)
    assert empty.status == "NO_MATCH"
    assert GENERATOR.generate(empty) == []
    assert GENERATOR.generate_many([empty, empty]) == []


def test_t14_generate_many_accepts_generator_iterable():
    first = make_result(event=make_event(packet_id=101))
    second = EvaluationResult(event=make_event(packet_id=102))
    third = make_result(event=make_event(packet_id=103))
    results = (result for result in [first, second, third])
    detections = GENERATOR.generate_many(results)
    assert [item.packet_id for item in detections] == [101, 103]
    assert [item.sid for item in detections] == [14101, 14101]
    assert detections[0].matched_info is not detections[1].matched_info


def test_t14_same_event_multiple_rule_matches_have_distinct_details():
    event = make_event()
    first = make_rule(sid=14201, options='content:"GET";')
    second = make_rule(sid=14202, options='content:"ADMIN";')
    details1 = {
        "matched_field": "payload",
        "matched_content": [{"content": "GET", "start": 0, "end": 3}],
    }
    details2 = {
        "matched_field": "payload",
        "matched_content": [{"content": "ADMIN", "start": 5, "end": 10}],
    }
    result = EvaluationResult(event=event, matches=[
        RuleMatch(rule=first, details=details1),
        RuleMatch(rule=second, details=details2),
    ])
    detections = GENERATOR.generate(result)
    assert [d.sid for d in detections] == [14201, 14202]
    assert [d.matched_info for d in detections] == [details1, details2]
    detections[0].matched_info["matched_content"][0]["start"] = 99
    assert details1["matched_content"][0]["start"] == 0
    assert detections[1].matched_info["matched_content"][0]["start"] == 5


def test_t14_application_buffer_match_is_reflected_in_detection():
    rule = make_rule(options='content:"GET";')
    repo = RuleRepository()
    repo.add(rule)
    event = make_event(
        payload=b"POST",
        application_data={"decoded_uri": "/GET/index"},
    )
    result = RuleEvaluationEngine(repo).evaluate(event)
    detection = one_detection(result)
    assert detection.matched_info == {
        "matched_field": "application_data.decoded_uri",
        "matched_content": [{"content": "GET", "start": 1, "end": 4}],
    }
    assert detection.packet_id == event.packet_id


def test_t14_flow_context_used_to_match_but_not_substituted_in_output():
    rule = make_rule(options='flow:to_server,established;')
    repo = RuleRepository()
    repo.add(rule)
    event = make_event(tcp_state=None)
    result = RuleEvaluationEngine(repo).evaluate(
        event,
        flow_context={"flow_id": "flow-14", "tcp_state": "ESTABLISHED"},
    )
    assert result.matched_sids == [14101]
    detection = one_detection(result)
    assert detection.flow_id == "flow-14"
    assert detection.flow_direction == "forward"
    assert detection.tcp_state is None
    assert detection.matched_info == {
        "matched_field": None, "matched_content": [],
    }


def test_t14_udp_packet_preserves_protocol_and_missing_flow():
    rule = make_rule(
        header="alert udp any any -> any 53",
        options='dsize:4;',
    )
    repo = RuleRepository()
    repo.add(rule)
    event = make_event(
        payload=b"PING",
        transport_protocol="UDP",
        dst_port=53,
        application_protocol="DNS",
        flow_direction=None,
        tcp_state=None,
    )
    result = RuleEvaluationEngine(repo).evaluate(event)
    detection = one_detection(result)
    assert detection.transport_protocol == "UDP"
    assert detection.application_protocol == "DNS"
    assert detection.dst_port == 53
    assert detection.flow_direction is None
    assert detection.tcp_state is None


def test_t14_engine_generator_integration_multiple_rules():
    repo = RuleRepository()
    repo.add_many([
        make_rule(sid=14301, options='content:"GET";'),
        make_rule(sid=14302, options='content:"ADMIN";'),
        make_rule(sid=14303, options='content:"POST";'),
        make_rule(sid=14304, options='content:"GET"; nocase;'),
    ])
    engine = RuleEvaluationEngine(repo)
    result = engine.evaluate(make_event())
    assert result.candidate_count == 4
    assert result.matched_sids == [14301, 14302, 14304]
    assert result.match_count == 3
    detections = GENERATOR.generate(result)
    assert [d.sid for d in detections] == [14301, 14302, 14304]
    assert [d.matched_info for d in detections] == [
        match.details for match in result.matches
    ]
    assert detections[0].matched_info["matched_content"][0] == {
        "content": "GET", "start": 0, "end": 3,
    }
    assert detections[1].matched_info["matched_content"][0] == {
        "content": "ADMIN", "start": 5, "end": 10,
    }
    assert engine.get_stats() == {
        "events_evaluated": 1,
        "candidate_rules": 4,
        "match_count": 3,
        "matched_events": 1,
    }


def test_t14_generate_many_integrates_with_evaluate_many():
    repo = RuleRepository()
    repo.add_many([
        make_rule(sid=14401, options='content:"GET";'),
        make_rule(sid=14402, options='content:"POST";'),
    ])
    engine = RuleEvaluationEngine(repo)
    results = engine.evaluate_many([
        make_event(b"GET", packet_id=201),
        make_event(b"POST", packet_id=202),
        make_event(b"HEAD", packet_id=203),
    ])
    detections = GENERATOR.generate_many(results)
    assert [(d.packet_id, d.sid) for d in detections] == [
        (201, 14401), (202, 14402),
    ]
    assert engine.get_stats() == {
        "events_evaluated": 3,
        "candidate_rules": 6,
        "match_count": 2,
        "matched_events": 2,
    }
