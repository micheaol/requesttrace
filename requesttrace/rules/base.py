"""The rule contract, evaluation context and shared finding-construction helper."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from requesttrace.config import ScanConfig
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import FindingStatus, ModuleName, Severity
from requesttrace.models.finding import Finding
from requesttrace.models.identifiers import generate_finding_id
from requesttrace.models.target import Target


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Everything a rule is allowed to read: normalized observations only.

    Rules must never parse presentation/report text — only observations
    retrieved through ``store``.
    """

    target: Target
    config: ScanConfig
    store: EvidenceStore

    def latest_observation_value(self, module: ModuleName, observation_type: str) -> Any:
        matches = self.store.observations_of_type(module, observation_type)
        return matches[-1].value if matches else None

    def latest_observation_and_evidence_ids(self, module: ModuleName, observation_type: str) -> tuple[Any, list[str]]:
        """Return the newest observation's value plus its linked evidence IDs."""
        matches = self.store.observations_of_type(module, observation_type)
        if not matches:
            return None, []
        observation = matches[-1]
        evidence_ids = [e.evidence_id for e in self.store.evidence if e.observation_id == observation.observation_id]
        return observation.value, evidence_ids


class RuleEvaluator(Protocol):
    def __call__(self, context: RuleContext) -> list[Finding]: ...


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Metadata plus the evaluation function for a single, independently testable rule."""

    rule_id: str
    title: str
    default_severity: Severity
    evaluate: RuleEvaluator
    references: list[str] = field(default_factory=list)


def build_finding(
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    affected_asset: str,
    description: str,
    evidence_ids: list[str],
    security_impact: str,
    recommendation: str,
    how_to_fix: str,
    verification: str,
    priority: str,
    references: list[str] | None = None,
) -> Finding:
    """Construct a Finding with a fresh stable ID and OPEN status.

    The single choke point every rule uses, so the Professional Finding
    Standard (PRD §9) field set can never be produced incompletely.
    """
    return Finding(
        finding_id=generate_finding_id(),
        rule_id=rule_id,
        title=title,
        severity=severity,
        status=FindingStatus.OPEN,
        affected_asset=affected_asset,
        description=description,
        evidence_ids=evidence_ids,
        security_impact=security_impact,
        recommendation=recommendation,
        how_to_fix=how_to_fix,
        verification=verification,
        priority=priority,
        references=references or [],
    )
