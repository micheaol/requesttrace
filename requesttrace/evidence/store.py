"""In-memory observation/evidence store shared by all scanners during a scan.

Scanners never construct :class:`Observation`/:class:`Evidence` objects
directly — they call :meth:`EvidenceStore.record_observation` and
:meth:`EvidenceStore.record_evidence`, which guarantees IDs are generated
consistently and evidence always references a real observation.
"""

from __future__ import annotations

from typing import Any

from requesttrace.evidence.redaction import redact_headers, sanitize_text
from requesttrace.models.enums import Confidence, ModuleName
from requesttrace.models.evidence import Evidence
from requesttrace.models.identifiers import generate_evidence_id, generate_observation_id
from requesttrace.models.observation import Observation
from requesttrace.util.serialization import utc_now


class EvidenceStore:
    """Accumulates normalized observations and their sanitized evidence."""

    def __init__(self) -> None:
        self._observations: list[Observation] = []
        self._evidence: list[Evidence] = []

    def record_observation(
        self,
        module: ModuleName,
        observation_type: str,
        value: Any,
        *,
        confidence: Confidence = Confidence.OBSERVED,
        metadata: dict[str, Any] | None = None,
    ) -> Observation:
        observation = Observation(
            observation_id=generate_observation_id(),
            module=module,
            type=observation_type,
            value=value,
            timestamp=utc_now(),
            confidence=confidence,
            metadata=metadata or {},
        )
        self._observations.append(observation)
        return observation

    def record_evidence(
        self,
        observation: Observation,
        *,
        source_method: str,
        sanitized_raw: dict[str, Any] | None = None,
    ) -> Evidence:
        """Create the sanitized, report-safe evidence record for an observation.

        ``sanitized_raw`` must already be redaction-safe; header dicts should
        be passed through :func:`~requesttrace.evidence.redaction.redact_headers`
        first and free-form strings through
        :func:`~requesttrace.evidence.redaction.sanitize_text`.
        """
        evidence = Evidence(
            evidence_id=generate_evidence_id(),
            observation_id=observation.observation_id,
            module=observation.module,
            timestamp=observation.timestamp,
            normalized_value=observation.value,
            source_method=source_method,
            confidence=observation.confidence,
            sanitized_raw=_defensively_sanitize(sanitized_raw or {}),
        )
        self._evidence.append(evidence)
        return evidence

    def record_observation_with_evidence(
        self,
        module: ModuleName,
        observation_type: str,
        value: Any,
        *,
        source_method: str,
        confidence: Confidence = Confidence.OBSERVED,
        metadata: dict[str, Any] | None = None,
        sanitized_raw: dict[str, Any] | None = None,
    ) -> tuple[Observation, Evidence]:
        """Convenience wrapper for the common one-observation-to-one-evidence case."""
        observation = self.record_observation(module, observation_type, value, confidence=confidence, metadata=metadata)
        evidence = self.record_evidence(observation, source_method=source_method, sanitized_raw=sanitized_raw)
        return observation, evidence

    @property
    def observations(self) -> list[Observation]:
        return list(self._observations)

    @property
    def evidence(self) -> list[Evidence]:
        return list(self._evidence)

    def observations_for_module(self, module: ModuleName) -> list[Observation]:
        return [o for o in self._observations if o.module == module]

    def observations_of_type(self, module: ModuleName, observation_type: str) -> list[Observation]:
        return [o for o in self._observations if o.module == module and o.type == observation_type]


def _defensively_sanitize(raw: dict[str, Any]) -> dict[str, Any]:
    """Best-effort second pass: redact any nested ``headers`` dict and strings.

    Callers are expected to sanitize before calling ``record_evidence``; this
    exists as defense-in-depth so a missed call site cannot leak a secret.
    """
    sanitized: dict[str, Any] = {}
    for key, value in raw.items():
        if key.lower() == "headers" and isinstance(value, dict):
            sanitized[key] = redact_headers(value)
        elif isinstance(value, str):
            sanitized[key] = sanitize_text(value)
        else:
            sanitized[key] = value
    return sanitized
