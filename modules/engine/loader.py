from collections.abc import Iterable
from pathlib import Path

from .models import RuleLoadResult, RuleLoadWarning, RuleSource


class RuleLoader:

    def __init__(
        self,
        disabled_files: Iterable[str | Path] = (),
        disabled_rules: Iterable[tuple[str | Path, int]] = (),
    ) -> None:
        self.disabled_files = {
            Path(path).resolve() for path in disabled_files
        }
        self.disabled_rules = set()

        for path, line_number in disabled_rules:
            if type(line_number) is not int or line_number < 1:
                raise ValueError("rule line number must be a positive integer")

            self.disabled_rules.add((Path(path).resolve(), line_number))

    def load(
        self,
        paths: str | Path | Iterable[str | Path],
    ) -> RuleLoadResult:
        result = RuleLoadResult()

        if isinstance(paths, (str, Path)):
            paths = [paths]

        for source_path in paths:
            path = Path(source_path).resolve()

            if path in self.disabled_files:
                continue

            try:
                with path.open(encoding="utf-8-sig") as source:
                    for line_number, line in enumerate(source, start=1):
                        text = line.strip()

                        if not text or text.startswith("#"):
                            continue

                        if (path, line_number) in self.disabled_rules:
                            continue

                        result.rules.append(RuleSource(
                            path=path,
                            line_number=line_number,
                            text=text,
                        ))

            except (OSError, UnicodeError) as error:
                result.warnings.append(RuleLoadWarning(
                    path=path,
                    reason=str(error),
                ))

        return result
