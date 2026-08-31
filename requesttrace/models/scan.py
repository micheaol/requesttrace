"""The top-level Scan aggregate: metadata, target, evidence, findings, results."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from requesttrace.models.enums import AssessmentLabel, Severity
from requesttrace.models.evidence import Evidence
from requesttrace.models.finding import Finding
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.observation import Observation
from requesttrace.models.target import Target


@dataclass(frozen=True, slots=True)
class ScanConfigSnapshot:
    """A frozen, serializable record of the configuration used for a scan."""

    timeout_seconds: float
    max_redirects: int
    fail_on: str
    user_agent: str
    certificate_warning_days: int
    certificate_critical_days: int


@dataclass(frozen=True, slots=True)
class ScanMetadata:
    """Provenance metadata attached to every scan for reproducibility."""

    scan_id: str
    scanner_version: str
    ruleset_version: str
    schema_version: str
    runtime: str
    container_image: str | None
    started_at: dt.datetime
    completed_at: dt.datetime | None
    config: ScanConfigSnapshot


@dataclass(slots=True)
class Scan:
    """The complete, self-contained result of one RequestTrace assessment.

    This is the single object that every report renderer consumes — no
    renderer reaches back into scanner internals.
    """

    metadata: ScanMetadata
    target: Target
    observations: list[Observation] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    module_results: list[ModuleResult] = field(default_factory=list)
    assessment_label: AssessmentLabel = AssessmentLabel.ASSESSMENT_INCOMPLETE
    severity_summary: dict[Severity, int] = field(default_factory=dict)

    def findings_at_or_above(self, minimum_severity: Severity) -> list[Finding]:
        """Return findings whose severity rank meets or exceeds ``minimum_severity``."""
        return [f for f in self.findings if f.severity.rank >= minimum_severity.rank]

    def evidence_by_id(self, evidence_id: str) -> Evidence | None:
        return next((e for e in self.evidence if e.evidence_id == evidence_id), None)
