"""The professional finding record produced by the rule engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from requesttrace.models.enums import FindingStatus, Severity


@dataclass(frozen=True, slots=True)
class Finding:
    """An actionable, evidence-linked security or posture finding.

    Field order mirrors the Professional Finding Standard in the PRD so
    report renderers can iterate ``dataclasses.fields`` and stay in the
    documented order.
    """

    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    status: FindingStatus
    affected_asset: str
    description: str
    evidence_ids: list[str]
    security_impact: str
    recommendation: str
    how_to_fix: str
    verification: str
    priority: str
    references: list[str] = field(default_factory=list)
