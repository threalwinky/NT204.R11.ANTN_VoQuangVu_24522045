from pathlib import Path

import pytest

from main import load_rule_engine
from modules.engine import RuleLoader, RuleParser, RuleSource


VALID_TCP = (
    'alert tcp any any -> any 80 '
    '(msg:"Valid TCP"; sid:2101; rev:1;)'
)

VALID_UDP = (
    'alert udp any any -> any 53 '
    '(msg:"Valid UDP"; sid:2102; rev:1;)'
)


@pytest.mark.parametrize(
    ("rule_text", "expected_reason"),
    [
        pytest.param(
            'alert tcp any any -> any 80',
            "missing header/options",
            id="missing-options",
        ),
        pytest.param(
            'alert tcp any -> any 80 '
            '(msg:"Test"; sid:1001; rev:1;)',
            "exactly 7 fields",
            id="invalid-header-field-count",
        ),
        pytest.param(
            'alert tcp any any => any 80 '
            '(msg:"Test"; sid:1001; rev:1;)',
            "invalid direction",
            id="invalid-direction",
        ),
        pytest.param(
            'alert tcp 300.1.1.1 any -> any 80 '
            '(msg:"Test"; sid:1001; rev:1;)',
            "invalid IPv4 address/CIDR",
            id="invalid-ipv4",
        ),
        pytest.param(
            'alert tcp 10.0.0.0/33 any -> any 80 '
            '(msg:"Test"; sid:1001; rev:1;)',
            "invalid IPv4 address/CIDR",
            id="invalid-cidr",
        ),
        pytest.param(
            'alert tcp any 70000 -> any 80 '
            '(msg:"Test"; sid:1001; rev:1;)',
            "port outside",
            id="port-out-of-range",
        ),
        pytest.param(
            'alert tcp any any -> any 9000:1000 '
            '(msg:"Test"; sid:1001; rev:1;)',
            "invalid port range",
            id="inverted-port-range",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(sid:1001; rev:1;)',
            "missing required option: msg",
            id="missing-msg",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; rev:1;)',
            "missing required option: sid",
            id="missing-sid",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:1001;)',
            "missing required option: rev",
            id="missing-rev",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:abc; rev:1;)',
            "sid must be an integer",
            id="non-numeric-sid",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:1001; rev:0;)',
            "rev must be positive",
            id="invalid-rev",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:1001; sid:1002; rev:1;)',
            "duplicate option: sid",
            id="duplicate-sid-option",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:Test; sid:1001; rev:1;)',
            "msg requires a quoted value",
            id="unquoted-message",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:1001; rev:1)',
            "must end with ';'",
            id="missing-semicolon",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:1001; rev:1; '
            'content:"|GG|";)',
            "invalid content hex block",
            id="invalid-hex-content",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:1001; rev:1; '
            'nocase; content:"GET";)',
            "nocase requires preceding content",
            id="nocase-before-content",
        ),
        pytest.param(
            'alert tcp any any -> any 80 '
            '(msg:"Test"; sid:1001; rev:1; '
            'flow:to_server,to_client;)',
            "conflicting flow directions",
            id="conflicting-flow-direction",
        ),
    ],
)
def test_t02_reject_invalid_rule(rule_text, expected_reason):
    source = RuleSource(
        path=Path("invalid.rules"),
        line_number=1,
        text=rule_text,
    )

    result = RuleParser().parse(source)

    assert result.status == "invalid"
    assert result.rule is None
    assert result.source == source

    assert isinstance(result.reason, str)
    assert expected_reason in result.reason


def test_t02_invalid_rules_do_not_stop_parsing(tmp_path):
    rule_file = tmp_path / "mixed.rules"

    rule_file.write_text(
        "# Valid and invalid rules\n"
        f"{VALID_TCP}\n"
        'alert tcp any 70000 -> any 80 '
        '(msg:"Bad Port"; sid:9991; rev:1;)\n'
        'alert tcp any any -> any 80 '
        '(msg:"Missing SID"; rev:1;)\n'
        f"{VALID_UDP}\n",
        encoding="utf-8",
    )

    loaded = RuleLoader().load(rule_file)

    assert loaded.warnings == []
    assert len(loaded.rules) == 4

    results = RuleParser().parse_many(loaded.rules)

    assert [item.status for item in results] == [
        "valid",
        "invalid",
        "invalid",
        "valid",
    ]

    assert [item.source.line_number for item in results] == [
        2, 3, 4, 5
    ]

    assert all(
        item.reason is not None and item.rule is None
        for item in results
        if item.status == "invalid"
    )

    valid_sids = [
        item.rule.sid
        for item in results
        if item.status == "valid"
    ]

    assert valid_sids == [2101, 2102]


def test_t02_engine_skips_invalid_and_keeps_valid_rules(
    tmp_path,
    capsys,
):
    rule_file = tmp_path / "engine.rules"

    rule_file.write_text(
        f"{VALID_TCP}\n"
        'alert tcp any 70000 -> any 80 '
        '(msg:"Bad Port"; sid:9991; rev:1;)\n'
        f"{VALID_UDP}\n"
        'alert udp any any -> any 53 '
        '(msg:"Missing SID"; rev:1;)\n',
        encoding="utf-8",
    )

    engine = load_rule_engine([str(rule_file)])

    assert len(engine.repository) == 2
    assert engine.repository.get(2101) is not None
    assert engine.repository.get(2102) is not None
    assert engine.repository.get(9991) is None

    captured = capsys.readouterr()

    assert captured.err.count("[RULE INVALID]") == 2
    assert "loaded=2" in captured.err
    assert "invalid=2" in captured.err
    assert "unsupported=0" in captured.err
    assert "rejected=0" in captured.err


def test_t02_duplicate_sid_does_not_stop_loading(
    tmp_path,
    capsys,
):
    rule_file = tmp_path / "duplicates.rules"

    rule_file.write_text(
        f"{VALID_TCP}\n"
        'alert tcp any any -> any 443 '
        '(msg:"Duplicate SID"; sid:2101; rev:1;)\n'
        f"{VALID_UDP}\n",
        encoding="utf-8",
    )

    engine = load_rule_engine([str(rule_file)])

    assert len(engine.repository) == 2
    assert engine.repository.get(2101).msg == "Valid TCP"
    assert engine.repository.get(2102).msg == "Valid UDP"

    captured = capsys.readouterr()

    assert "duplicate SID: 2101" in captured.err
    assert "loaded=2" in captured.err
    assert "invalid=0" in captured.err
    assert "rejected=1" in captured.err


def test_t02_missing_file_does_not_stop_other_files(
    tmp_path,
):
    missing = tmp_path / "missing.rules"
    valid_file = tmp_path / "valid.rules"

    valid_file.write_text(
        f"{VALID_TCP}\n",
        encoding="utf-8",
    )

    loaded = RuleLoader().load([
        missing,
        valid_file,
    ])

    assert len(loaded.warnings) == 1
    assert loaded.warnings[0].path == missing.resolve()

    assert len(loaded.rules) == 1
    assert loaded.rules[0].path == valid_file.resolve()

    parsed = RuleParser().parse_many(loaded.rules)

    assert len(parsed) == 1
    assert parsed[0].status == "valid"
    assert parsed[0].rule.sid == 2101


def test_t02_all_invalid_rules_do_not_crash(
    tmp_path,
    capsys,
):
    rule_file = tmp_path / "all_invalid.rules"

    rule_file.write_text(
        'alert tcp any any -> any 80 '
        '(msg:"No SID"; rev:1;)\n'
        'alert tcp any 70000 -> any 80 '
        '(msg:"Bad Port"; sid:9991; rev:1;)\n',
        encoding="utf-8",
    )

    engine = load_rule_engine([str(rule_file)])

    assert len(engine.repository) == 0

    captured = capsys.readouterr()

    assert captured.err.count("[RULE INVALID]") == 2
    assert "loaded=0" in captured.err
    assert "invalid=2" in captured.err
    assert "No active valid Snort rules loaded" in captured.err
