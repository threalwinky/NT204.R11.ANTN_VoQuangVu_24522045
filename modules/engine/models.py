from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class RuleSource:
    path: Path
    line_number: int
    text: str


@dataclass(frozen=True)
class RuleHeader:
    action: str
    protocol: str
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: str


@dataclass(frozen=True)
class RuleOption:
    keyword: str
    value: str | None = None


@dataclass
class SnortRule:
    source: RuleSource
    header: RuleHeader
    options: list[RuleOption] = field(default_factory=list)
    sid: int | None = None
    rev: int | None = None
    msg: str | None = None
    classtype: str | None = None
    priority: int | None = None


@dataclass
class RuleValidationResult:
    source: RuleSource
    status: Literal["valid", "invalid", "unsupported"]
    rule: SnortRule | None = None
    reason: str | None = None


@dataclass(frozen=True)
class RuleLoadWarning:
    path: Path
    reason: str


@dataclass
class RuleLoadResult:
    rules: list[RuleSource] = field(default_factory=list)
    warnings: list[RuleLoadWarning] = field(default_factory=list)
