"""A small elapsed-time helper used by every scanner to record durations."""

from __future__ import annotations

import time
from types import TracebackType


class Stopwatch:
    """Context manager that records elapsed wall-clock time in milliseconds."""

    def __init__(self) -> None:
        self._start: float = 0.0
        self.elapsed_ms: float = 0.0

    def __enter__(self) -> Stopwatch:
        self._start = time.perf_counter()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000
