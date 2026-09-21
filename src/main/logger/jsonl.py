import json
from pathlib import Path
from typing import TextIO

from main.models import NormalizedIDSEvent

class JSONLLogger:

    def __init__(self, output_path: str | Path):
        self.output_path = Path(output_path)
        self._file: TextIO | None = None

    def __enter__(self):
        self.output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._file = self.output_path.open(
            mode="w",
            encoding="utf-8",
        )

        return self

    def write(self, event: NormalizedIDSEvent) -> None:
        if self._file is None:
            raise RuntimeError("Logging file is not open")

        line = json.dumps(
            event.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
        )

        self._file.write(line + "\n")
        self._file.flush()

    def __exit__(self, exc_type, exc_value, traceback):
        if self._file is not None:
            self._file.close()
            self._file = None