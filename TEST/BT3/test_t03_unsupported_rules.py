from pathlib import Path

import pytest

from main import load_rule_engine
from modules.engine import RuleLoader, RuleParser, RuleSource
from modules.models import NormalizedIDSEvent


VALID_TCP = (
    'alert tcp any any -> any 80 '
    '(msg:"Valid TCP"; sid:3101; rev:1;)'
)

VALID_UDP = (
    'alert udp any any -> any 53 '
    '(msg:"Valid UDP"; sid:3102; rev:1;)'
)


@pytest.mark.parametrize(
    ("rule_text", "expected_reason"),
    [
        pytest.param(
            'drop tcp any any -> any 80 '
            '(msg:"Test"; sid:3001; rev:1;)',
            "unsupported rule action: drop",
            id="drop-action",
        ),
        pytest.param(
            'reject tcp any any -> any 80 '
            '(msg:"Test"; sid:3002; rev:1;)',
            "unsupported rule action: reject",
            id="reject-action",
        ),
        pytest.param(
            'log tcp any any -> any 80 '
            '(msg:"Test"; sid:3003; rev:1;)',
            "unsupported rule action: log",
            id="log-action",
        ),
        pytest.param(
            'alert icmp any any -> any any '
            '(msg:"Test"; sid:3004; rev:1;)',
            "unsupported protocol: icmp",
            id="icmp-protocol",
        ),
        pytest.param(
            'alert ip any any -> any any '
            '(msg:"Test"; sid:3005; rev:1;)',
            "unsupported protocol: ip",
            id="ip-protocol",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:3006; rev:1; pcre:"/admin/";)',
            "unsupported keyword: pcre",
            id="pcre-keyword",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:3007; rev:1; byte_test:4,>,1,0;)',
            "unsupported keyword: byte_test",
            id="byte-test-keyword",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:3008; rev:1; byte_jump:4,0;)',
            "unsupported keyword: byte_jump",
            id="byte-jump-keyword",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:3009; rev:1; http_uri;)',
            "unsupported keyword: http_uri",
            id="http-uri-keyword",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:3010; rev:1; file_data;)',
            "unsupported keyword: file_data",
            id="file-data-keyword",
        ),
        pytest.param(
            'alert tcp $HOME_NET any -> any 80 '
            '(msg:"Test"; sid:3011; rev:1;)',
            "unsupported IP expression",
            id="ip-variable",
        ),
        pytest.param(
            'alert tcp !192.168.1.10 any -> any 80 '
            '(msg:"Test"; sid:3012; rev:1;)',
            "unsupported IP expression",
            id="negated-ip",
        ),
        pytest.param(
            'alert tcp any $HTTP_PORTS -> any 80 '
            '(msg:"Test"; sid:3013; rev:1;)',
            "unsupported port expression",
            id="port-variable",
        ),
        pytest.param(
            'alert tcp any any -> any !80 '
            '(msg:"Test"; sid:3014; rev:1;)',
            "unsupported port expression",
            id="negated-port",
        ),
        pytest.param(
            'alert tcp any any -> any [80,443] '
            '(msg:"Test"; sid:3015; rev:1;)',
            "unsupported port expression",
            id="port-list",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:3016; rev:1; content:!"admin";)',
            "negated content is unsupported",
            id="negated-content",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:3017; rev:1; flow:only_stream;)',
            "unsupported flow keyword: only_stream",
            id="unsupported-flow",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:3018; rev:1; flags:Z;)',
            "unsupported flags expression",
            id="unsupported-flags",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:3019; rev:1; dsize:>=10;)',
            "unsupported dsize expression",
            id="unsupported-dsize",
        ),
    ],
)
def test_t03_unsupported_rule(rule_text, expected_reason):
    source = RuleSource(
        path=Path("unsupported.rules"),
        line_number=1,
        text=rule_text,
    )

    result = RuleParser().parse(source)

    assert result.status == "unsupported"
    assert result.rule is None
    assert result.source == source

    assert isinstance(result.reason, str)
    assert expected_reason in result.reason


def test_t03_classify_mixed_rule_statuses(tmp_path):
    rule_file = tmp_path / "mixed.rules"

    rule_file.write_text(
        "# Mixed rule statuses\n"
        f"{VALID_TCP}\n"
        'alert tcp any any -> any 80 '
        '(msg:"PCRE"; sid:3901; rev:1; pcre:"/admin/";)\n'
        'alert tcp any 70000 -> any 80 '
        '(msg:"Invalid Port"; sid:3902; rev:1;)\n'
        f"{VALID_UDP}\n"
        'alert tcp any any -> any 80 '
        '(msg:"Flow"; sid:3903; rev:1; flow:only_stream;)\n',
        encoding="utf-8",
    )

    loaded = RuleLoader().load(rule_file)

    assert loaded.warnings == []
    assert len(loaded.rules) == 5

    results = RuleParser().parse_many(loaded.rules)

    assert [item.status for item in results] == [
        "valid",
        "unsupported",
        "invalid",
        "valid",
        "unsupported",
    ]

    assert [item.source.line_number for item in results] == [
        2, 3, 4, 5, 6
    ]

    assert all(
        item.rule is None and item.reason
        for item in results
        if item.status != "valid"
    )

    assert [
        item.rule.sid
        for item in results
        if item.status == "valid"
    ] == [3101, 3102]


def test_t03_engine_skips_unsupported_rules(
    tmp_path,
    capsys,
):
    rule_file = tmp_path / "engine.rules"

    rule_file.write_text(
        f"{VALID_TCP}\n"
        'alert tcp any any -> any 80 '
        '(msg:"PCRE"; sid:3901; rev:1; pcre:"/admin/";)\n'
        'alert tcp any 70000 -> any 80 '
        '(msg:"Invalid"; sid:3902; rev:1;)\n'
        f"{VALID_UDP}\n"
        'alert tcp any any -> any 80 '
        '(msg:"Flow"; sid:3903; rev:1; flow:only_stream;)\n',
        encoding="utf-8",
    )

    engine = load_rule_engine([str(rule_file)])

    assert len(engine.repository) == 2
    assert engine.repository.get(3101) is not None
    assert engine.repository.get(3102) is not None
    assert engine.repository.get(3901) is None
    assert engine.repository.get(3902) is None
    assert engine.repository.get(3903) is None

    output = capsys.readouterr().err

    assert output.count("[RULE UNSUPPORTED]") == 2
    assert output.count("[RULE INVALID]") == 1
    assert "loaded=2" in output
    assert "invalid=1" in output
    assert "unsupported=2" in output
    assert "rejected=0" in output
    assert "file_warnings=0" in output

    assert "unsupported keyword: pcre" in output
    assert "unsupported flow keyword: only_stream" in output


def test_t03_all_unsupported_rules_do_not_crash(
    tmp_path,
    capsys,
):
    rule_file = tmp_path / "all_unsupported.rules"

    rule_file.write_text(
        'drop tcp any any -> any 80 '
        '(msg:"Drop"; sid:3901; rev:1;)\n'
        'alert tcp any any -> any 80 '
        '(msg:"PCRE"; sid:3902; rev:1; pcre:"/test/";)\n',
        encoding="utf-8",
    )

    engine = load_rule_engine([str(rule_file)])

    assert len(engine.repository) == 0

    output = capsys.readouterr().err

    assert output.count("[RULE UNSUPPORTED]") == 2
    assert "loaded=0" in output
    assert "unsupported=2" in output
    assert "invalid=0" in output
    assert "No active valid Snort rules loaded" in output

    event = NormalizedIDSEvent(
        packet_id=1,
        timestamp=1000.0,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        network_protocol="IPv4",
        transport_protocol="TCP",
        src_port=50000,
        dst_port=80,
        payload=b"GET /",
        payload_length=5,
    )

    result = engine.evaluate(event)

    assert result.status == "NO_MATCH"
    assert result.candidate_count == 0
    assert result.matches == []


def test_t03_unsupported_file_does_not_block_valid_file(
    tmp_path,
    capsys,
):
    unsupported_file = tmp_path / "unsupported.rules"
    valid_file = tmp_path / "valid.rules"

    unsupported_file.write_text(
        'alert tcp any any -> any 80 '
        '(msg:"PCRE"; sid:3901; rev:1; pcre:"/test/";)\n'
        'alert icmp any any -> any any '
        '(msg:"ICMP"; sid:3902; rev:1;)\n',
        encoding="utf-8",
    )

    valid_file.write_text(
        f"{VALID_TCP}\n"
        f"{VALID_UDP}\n",
        encoding="utf-8",
    )

    engine = load_rule_engine([
        str(unsupported_file),
        str(valid_file),
    ])

    assert len(engine.repository) == 2
    assert engine.repository.get(3101) is not None
    assert engine.repository.get(3102) is not None

    output = capsys.readouterr().err

    assert output.count("[RULE UNSUPPORTED]") == 2
    assert f"{unsupported_file.resolve()}:1" in output
    assert f"{unsupported_file.resolve()}:2" in output
    assert "loaded=2" in output
    assert "unsupported=2" in output
    assert "file_warnings=0" in output
