from dataclasses import FrozenInstanceError, astuple
from pathlib import Path

import pytest

from modules.engine import (
    RuleHeader,
    RuleLoader,
    RuleParser,
    RuleSource,
)


@pytest.mark.parametrize(
    ("header_text", "expected"),
    [
        pytest.param(
            "alert tcp any any -> any 80",
            ("alert", "tcp", "any", "any", "->", "any", "80"),
            id="basic-tcp",
        ),
        pytest.param(
            "alert udp any any -> any 53",
            ("alert", "udp", "any", "any", "->", "any", "53"),
            id="basic-udp",
        ),
        pytest.param(
            "alert tcp 192.168.1.10 50000 -> 10.0.0.1 443",
            ("alert", "tcp", "192.168.1.10", "50000",
             "->", "10.0.0.1", "443"),
            id="specific-ipv4",
        ),
        pytest.param(
            "alert tcp 192.168.1.0/24 any -> any 80",
            ("alert", "tcp", "192.168.1.0/24", "any",
             "->", "any", "80"),
            id="source-cidr",
        ),
        pytest.param(
            "alert udp any any -> 10.0.0.0/8 53",
            ("alert", "udp", "any", "any",
             "->", "10.0.0.0/8", "53"),
            id="destination-cidr",
        ),
        pytest.param(
            "alert tcp 172.16.1.25/24 any -> any 8080",
            ("alert", "tcp", "172.16.1.25/24", "any",
             "->", "any", "8080"),
            id="cidr-host-bits",
        ),
        pytest.param(
            "alert tcp 10.0.0.0/8 any -> 192.168.0.0/16 443",
            ("alert", "tcp", "10.0.0.0/8", "any",
             "->", "192.168.0.0/16", "443"),
            id="both-cidr",
        ),
        pytest.param(
            "alert udp any any -> any any",
            ("alert", "udp", "any", "any",
             "->", "any", "any"),
            id="any-ports",
        ),
        pytest.param(
            "alert tcp any 0 -> any 0",
            ("alert", "tcp", "any", "0", "->", "any", "0"),
            id="minimum-port",
        ),
        pytest.param(
            "alert tcp any 65535 -> any 65535",
            ("alert", "tcp", "any", "65535",
             "->", "any", "65535"),
            id="maximum-port",
        ),
        pytest.param(
            "alert tcp any 1000:2000 -> any 80",
            ("alert", "tcp", "any", "1000:2000",
             "->", "any", "80"),
            id="source-port-range",
        ),
        pytest.param(
            "alert tcp any any -> any 8000:9000",
            ("alert", "tcp", "any", "any",
             "->", "any", "8000:9000"),
            id="destination-port-range",
        ),
        pytest.param(
            "alert udp any :1024 -> any 53",
            ("alert", "udp", "any", ":1024",
             "->", "any", "53"),
            id="source-open-lower-range",
        ),
        pytest.param(
            "alert tcp any 1024: -> any 443",
            ("alert", "tcp", "any", "1024:",
             "->", "any", "443"),
            id="source-open-upper-range",
        ),
        pytest.param(
            "alert tcp any any -> any :1024",
            ("alert", "tcp", "any", "any",
             "->", "any", ":1024"),
            id="destination-open-lower-range",
        ),
        pytest.param(
            "alert udp any any -> any 49152:",
            ("alert", "udp", "any", "any",
             "->", "any", "49152:"),
            id="destination-open-upper-range",
        ),
        pytest.param(
            "alert tcp 10.0.0.1 1234 <> 10.0.0.2 4321",
            ("alert", "tcp", "10.0.0.1", "1234",
             "<>", "10.0.0.2", "4321"),
            id="bidirectional-tcp",
        ),
        pytest.param(
            "alert udp any any <> any 53",
            ("alert", "udp", "any", "any",
             "<>", "any", "53"),
            id="bidirectional-udp",
        ),
        pytest.param(
            "ALERT TCP any any -> any 80",
            ("alert", "tcp", "any", "any",
             "->", "any", "80"),
            id="uppercase-action-protocol",
        ),
        pytest.param(
            "alert tcp 0.0.0.0/0 any -> 255.255.255.255 65535",
            ("alert", "tcp", "0.0.0.0/0", "any",
             "->", "255.255.255.255", "65535"),
            id="ipv4-boundaries",
        ),
    ],
)
def test_t04_parse_valid_headers(header_text, expected):
    source = RuleSource(
        path=Path("header.rules"),
        line_number=1,
        text=(
            f'{header_text} '
            '(msg:"Header Test"; sid:4101; rev:1;)'
        ),
    )

    result = RuleParser().parse(source)

    assert result.status == "valid", result.reason
    assert result.reason is None
    assert result.rule is not None
    assert isinstance(result.rule.header, RuleHeader)

    assert astuple(result.rule.header) == expected

    assert result.rule.sid == 4101
    assert result.rule.rev == 1
    assert result.rule.msg == "Header Test"


def test_t04_header_with_rule_metadata():
    source = RuleSource(
        path=Path("metadata.rules"),
        line_number=10,
        text=(
            "alert tcp 192.168.1.0/24 1024: "
            "-> 10.0.0.10 443 "
            '(msg:"HTTPS Detection"; '
            'sid:4201; rev:2; '
            'classtype:web-application-attack; '
            'priority:2;)'
        ),
    )

    result = RuleParser().parse(source)

    assert result.status == "valid", result.reason
    assert result.rule is not None

    rule = result.rule
    header = rule.header

    assert header.action == "alert"
    assert header.protocol == "tcp"
    assert header.src_ip == "192.168.1.0/24"
    assert header.src_port == "1024:"
    assert header.direction == "->"
    assert header.dst_ip == "10.0.0.10"
    assert header.dst_port == "443"

    assert rule.sid == 4201
    assert rule.rev == 2
    assert rule.msg == "HTTPS Detection"
    assert rule.classtype == "web-application-attack"
    assert rule.priority == 2


def test_t04_load_and_parse_multiple_headers(tmp_path):
    rule_file = tmp_path / "multiple.rules"

    rule_file.write_text(
        "# Header test\n"
        "\n"
        'alert tcp any any -> 192.168.1.10 80 '
        '(msg:"HTTP"; sid:4301; rev:1;)\n'
        "# Another comment\n"
        'alert udp 10.0.0.0/8 1024: <> any 53 '
        '(msg:"DNS"; sid:4302; rev:1;)\n',
        encoding="utf-8",
    )

    loaded = RuleLoader().load(rule_file)

    assert loaded.warnings == []
    assert len(loaded.rules) == 2

    results = RuleParser().parse_many(loaded.rules)

    assert [item.status for item in results] == [
        "valid",
        "valid",
    ]

    first = results[0].rule
    second = results[1].rule

    assert first is not None
    assert second is not None

    assert first.header.protocol == "tcp"
    assert first.header.dst_ip == "192.168.1.10"
    assert first.header.dst_port == "80"
    assert first.sid == 4301

    assert second.header.protocol == "udp"
    assert second.header.src_ip == "10.0.0.0/8"
    assert second.header.src_port == "1024:"
    assert second.header.direction == "<>"
    assert second.header.dst_port == "53"
    assert second.sid == 4302

    assert [item.source.line_number for item in results] == [
        3,
        5,
    ]


def test_t04_preserve_source_and_whitespace(tmp_path):
    source = RuleSource(
        path=tmp_path / "whitespace.rules",
        line_number=15,
        text=(
            '   alert   tcp   10.1.1.0/24   1024:   '
            '<>   any   :65535   '
            '(msg:"Whitespace"; sid:4401; rev:1;)   '
        ),
    )

    result = RuleParser().parse(source)

    assert result.status == "valid", result.reason
    assert result.source == source
    assert result.rule is not None
    assert result.rule.source == source

    header = result.rule.header

    assert header.src_ip == "10.1.1.0/24"
    assert header.src_port == "1024:"
    assert header.direction == "<>"
    assert header.dst_ip == "any"
    assert header.dst_port == ":65535"


def test_t04_rule_header_is_immutable():
    source = RuleSource(
        path=Path("immutable.rules"),
        line_number=1,
        text=(
            'alert tcp any any -> any 80 '
            '(msg:"Immutable Header"; sid:4501; rev:1;)'
        ),
    )

    result = RuleParser().parse(source)

    assert result.status == "valid"
    assert result.rule is not None

    header = result.rule.header

    with pytest.raises(FrozenInstanceError):
        header.dst_port = "443"
