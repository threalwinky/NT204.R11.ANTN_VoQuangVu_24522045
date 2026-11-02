from pathlib import Path

from modules.engine import RuleLoader, RuleParser


TCP_RULE = (
    'alert tcp any any -> any 80 '
    '(msg:"HTTP Rule"; sid:100001; rev:1;)'
)

UDP_RULE = (
    'alert udp any any -> any 53 '
    '(msg:"DNS Rule"; sid:100002; rev:1;)'
)


def test_t01_load_valid_rules_and_skip_comments(tmp_path):
    rule_file = tmp_path / "local.rules"

    rule_file.write_text(
        "# This is a comment\n"
        "\n"
        "   # Another comment\n"
        "   \t\n"
        f"{TCP_RULE}\n"
        "\n"
        f"{UDP_RULE}\n",
        encoding="utf-8",
    )

    result = RuleLoader().load(rule_file)

    assert result.warnings == []
    assert len(result.rules) == 2

    assert [rule.text for rule in result.rules] == [
        TCP_RULE,
        UDP_RULE,
    ]

    assert [rule.line_number for rule in result.rules] == [
        5,
        7,
    ]


def test_t01_preserve_rule_source_information(tmp_path):
    rule_file = tmp_path / "source.rules"

    rule_file.write_text(
        f"\n{TCP_RULE}\n",
        encoding="utf-8",
    )

    result = RuleLoader().load(rule_file)

    assert len(result.rules) == 1

    source = result.rules[0]

    assert isinstance(source.path, Path)
    assert source.path == rule_file.resolve()
    assert source.line_number == 2
    assert source.text == TCP_RULE


def test_t01_load_multiple_rule_files(tmp_path):
    first_file = tmp_path / "first.rules"
    second_file = tmp_path / "second.rules"

    first_file.write_text(
        f"{TCP_RULE}\n",
        encoding="utf-8",
    )

    second_file.write_text(
        f"# Comment\n{UDP_RULE}\n",
        encoding="utf-8",
    )

    result = RuleLoader().load([
        first_file,
        second_file,
    ])

    assert result.warnings == []
    assert len(result.rules) == 2

    assert [rule.text for rule in result.rules] == [
        TCP_RULE,
        UDP_RULE,
    ]

    assert [rule.path for rule in result.rules] == [
        first_file.resolve(),
        second_file.resolve(),
    ]

    assert [rule.line_number for rule in result.rules] == [
        1,
        2,
    ]

    parsed = RuleParser().parse_many(result.rules)

    assert all(
        item.status == "valid"
        for item in parsed
    )

    assert [item.rule.sid for item in parsed] == [
        100001,
        100002,
    ]


def test_t01_comment_only_and_utf8_bom(tmp_path):
    empty_file = tmp_path / "empty.rules"
    bom_file = tmp_path / "bom.rules"

    empty_file.write_text(
        "# Comment\n"
        "\n"
        "   # Another comment\n",
        encoding="utf-8",
    )

    empty_result = RuleLoader().load(empty_file)

    assert empty_result.rules == []
    assert empty_result.warnings == []

    bom_file.write_text(
        "\ufeff# UTF-8 BOM comment\n"
        f"{TCP_RULE}\n",
        encoding="utf-8",
    )

    bom_result = RuleLoader().load(bom_file)

    assert bom_result.warnings == []
    assert len(bom_result.rules) == 1
    assert bom_result.rules[0].line_number == 2
    assert bom_result.rules[0].text == TCP_RULE
