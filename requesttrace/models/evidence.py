"""Sanitized, citable evidence linked back to a source observation."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from requesttrace.models.enums import Confidence, ModuleName


@dataclass(frozen=True, slots=True)
class Evidence:
    """A redaction-safe evidence record that findings cite by ID.

    Evidence is distinct from :class:`~requesttrace.models.observation.Observation`:
    an observation is the raw normalized fact; evidence is the sanitized,
    report-safe projection of it (secrets/cookie values already redacted)
    that is safe to embed in JSON/Markdown/HTML/PDF output.
    """

    evidence_id: str
    observation_id: str
    module: ModuleName
    timestamp: dt.datetime
    normalized_value: Any
    source_method: str
    confidence: Confidence = Confidence.OBSERVED
    sanitized_raw: dict[str, Any] = field(default_factory=dict)
