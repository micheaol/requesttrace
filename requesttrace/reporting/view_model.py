"""The canonical report view model (RT-030).

Every renderer (Markdown, HTML, PDF, JSON) builds its output from this one
object so they stay semantically equivalent. It never invents data — every
field is derived directly from the :class:`~requesttrace.models.scan.Scan`
it wraps.
"""

from __future__ import annotations

from dataclasses import dataclass

from requesttrace.analyzers.request_path import PathStage, build_request_path
from requesttrace.models.enums import ModuleName, Severity
from requesttrace.models.evidence import Evidence
from requesttrace.models.finding import Finding
from requesttrace.models.scan import Scan

_SEVERITY_DISPLAY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
]


@dataclass(frozen=True, slots=True)
class ReportViewModel:
    """A render-agnostic projection of a completed Scan."""

    scan: Scan
    request_path: list[PathStage]

    # -- Section 2: Executive summary ------------------------------------------------

    @property
    def executive_summary(self) -> str:
        target = self.scan.target
        label = self.scan.assessment_label.value
        finding_count = len(self.scan.findings)
        return (
            f"RequestTrace assessed {target.normalized_url} and produced an overall "
            f"result of {label}, based on {finding_count} finding(s) across DNS, "
            f"connectivity, TLS, HTTP, header, cookie and edge-indicator checks."
        )

    # -- Section 3/4/5: Scope, methodology, limitations ------------------------------------------------

    @property
    def scope_statement(self) -> str:
        return (
            f"This assessment covers the externally observable request path for "
            f"{self.scan.target.normalized_url} only: DNS resolution, TCP "
            f"connectivity, TLS negotiation, and the HTTP response (headers, "
            f"cookies, redirects). No authentication, exploitation or internal "
            f"network access was attempted."
        )

    @property
    def methodology_statement(self) -> str:
        return (
            f"RequestTrace {self.scan.metadata.scanner_version} performed a single "
            f"bounded scan using ruleset {self.scan.metadata.ruleset_version} on "
            f"{self.scan.metadata.runtime}. Findings are generated exclusively from "
            f"normalized observations linked to sanitized evidence — never from "
            f"raw/unstructured output."
        )

    @property
    def limitations_statement(self) -> str:
        return (
            "RequestTrace observes only what is externally visible. It cannot see "
            "internal services, databases or private network hops, does not "
            "perform authenticated testing, exploitation, brute force or fuzzing, "
            "and does not certify compliance with any regulatory framework. "
            "'Not Tested' results reflect a runtime limitation and must never be "
            "read as a passing result."
        )

    # -- Module tables ------------------------------------------------

    def module_result(self, module: ModuleName):
        return next((m for m in self.scan.module_results if m.module == module), None)

    @property
    def performance_observations(self) -> dict[str, float | None]:
        http_observations = {o.type: o.value for o in self.scan.observations if o.module == ModuleName.HTTP}
        return {
            "ttfb_ms": http_observations.get("ttfb_ms"),
            "total_duration_ms": http_observations.get("total_duration_ms"),
        }

    # -- Findings ------------------------------------------------

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        grouped: dict[Severity, list[Finding]] = {severity: [] for severity in _SEVERITY_DISPLAY_ORDER}
        for finding in self.scan.findings:
            grouped[finding.severity].append(finding)
        return grouped

    @property
    def ordered_findings(self) -> list[Finding]:
        ordered: list[Finding] = []
        for severity in _SEVERITY_DISPLAY_ORDER:
            ordered += self.findings_by_severity[severity]
        return ordered

    @property
    def prioritized_recommendations(self) -> list[Finding]:
        return self.ordered_findings

    def evidence_for(self, finding: Finding) -> list[Evidence]:
        evidence_ids = set(finding.evidence_ids)
        return [e for e in self.scan.evidence if e.evidence_id in evidence_ids]

    @property
    def conclusion(self) -> str:
        if not self.scan.findings:
            return "No actionable findings were identified during this assessment."
        critical_and_high = len(self.scan.findings_at_or_above(Severity.HIGH))
        return (
            f"{len(self.scan.findings)} finding(s) require attention, "
            f"{critical_and_high} of which are High or Critical severity. "
            "See Detailed Findings for evidence-linked remediation guidance."
        )


def build_report_view_model(scan: Scan) -> ReportViewModel:
    """Construct the canonical view model for a completed scan."""
    edge_observation = next(
        (
            o.value
            for o in reversed(scan.observations)
            if o.module == ModuleName.EDGE and o.type == "edge_provider_indicators"
        ),
        None,
    )
    edge_summary = _summarize_edge(edge_observation)
    request_path = build_request_path(scan.target, scan.module_results, edge_summary)
    return ReportViewModel(scan=scan, request_path=request_path)


def _summarize_edge(edge_observation: dict | None) -> str | None:
    if not edge_observation or not edge_observation.get("matches"):
        return None
    top = edge_observation["matches"][0]
    return f"{top['statement']} (confidence: {top['confidence']})"
