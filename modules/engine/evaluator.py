from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Literal

from ..models import NormalizedIDSEvent
from .matcher import RuleMatcher
from .models import SnortRule
from .repository import RuleRepository


@dataclass(frozen=True)
class RuleMatch:
    rule: SnortRule
    details: dict[str, object]


@dataclass
class EvaluationResult:
    event: NormalizedIDSEvent
    candidate_count: int = 0
    matches: list[RuleMatch] = field(default_factory=list)

    @property
    def status(self) -> Literal["MATCH", "NO_MATCH"]:
        return "MATCH" if self.matches else "NO_MATCH"

    @property
    def match_count(self) -> int:
        return len(self.matches)

    @property
    def matched_sids(self) -> list[int]:
        return [
            match.rule.sid
            for match in self.matches
            if match.rule.sid is not None
        ]


@dataclass
class EvaluationStats:
    events_evaluated: int = 0
    candidate_rules: int = 0
    match_count: int = 0
    matched_events: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


class RuleEvaluationEngine:

    def __init__(
        self,
        repository: RuleRepository,
        matcher: RuleMatcher | None = None,
    ) -> None:
        self.repository = repository
        self.matcher = (
            matcher if matcher is not None
            else RuleMatcher()
        )
        self.stats = EvaluationStats()

    def evaluate(
        self,
        event: NormalizedIDSEvent,
        flow_context: dict[str, object] | None = None,
    ) -> EvaluationResult:

        self.stats.events_evaluated += 1

        result = EvaluationResult(event=event)

        if (
            event.processing_action == "skip"
            or event.preprocess_status == "invalid"
            or event.status == "ERROR"
        ):
            return result

        candidates = self.repository.get_candidates(event)

        result.candidate_count = len(candidates)
        self.stats.candidate_rules += len(candidates)

        for rule in candidates:
            details = self.matcher.match_with_info(
                rule,
                event,
                flow_context,
            )

            if details is None:
                continue

            result.matches.append(
                RuleMatch(
                    rule=rule,
                    details=details,
                )
            )

        self.stats.match_count += result.match_count

        if result.matches:
            self.stats.matched_events += 1

        return result

    def evaluate_many(
        self,
        events: Iterable[NormalizedIDSEvent],
    ) -> list[EvaluationResult]:
        return [
            self.evaluate(event)
            for event in events
        ]

    def get_stats(self) -> dict[str, int]:
        return self.stats.to_dict()

    def reset_stats(self) -> None:
        self.stats = EvaluationStats()
