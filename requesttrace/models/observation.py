"""A single normalized fact collected by a scanner or analyzer module."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from requesttrace.models.enums import Confidence, ModuleName


@dataclass(frozen=True, slots=True)
class Observation:
    """A normalized, typed observation emitted by exactly one module.

    Observations are the only thing rules are allowed to read. They carry a
    ``confidence`` so heuristic/inferred signals (e.g. CDN fingerprinting)
    can never silently masquerade as directly observed fact.
    """

    observation_id: str
    module: ModuleName
    type: str
    value: Any
    timestamp: dt.datetime
    confidence: Confidence = Confidence.OBSERVED
    metadata: dict[str, Any] = field(default_factory=dict)
