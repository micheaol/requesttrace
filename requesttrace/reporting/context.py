"""Shared template-rendering context built from the canonical view model.

Markdown and HTML renderers both consume the exact same context so they stay
semantically equivalent — this module holds the one place that turns the
view model into simple, template-friendly data (no scan/rule logic here,
only formatting-oriented shaping).
"""

from __future__ import annotations

from typing import Any

from requesttrace.models.enums import ModuleName
from requesttrace.models.finding import Finding
from requesttrace.reporting.view_model import ReportViewModel, build_report_view_model


def build_render_context(scan) -> dict[str, Any]:
    """Build the dict passed to both the Markdown and HTML Jinja2 templates."""
    view_model: ReportViewModel = build_report_view_model(scan)

    return {
        "scan": scan,
        "target": scan.target,
        "metadata": scan.metadata,
        "assessment_label": scan.assessment_label.value,
        "executive_summary": view_model.executive_summary,
        "scope_statement": view_model.scope_statement,
        "methodology_statement": view_model.methodology_statement,
        "limitations_statement": view_model.limitations_statement,
        "request_path": view_model.request_path,
        "module_tables": _build_module_tables(scan),
        "performance_observations": view_model.performance_observations,
        "severity_summary": _severity_summary_rows(scan),
        "findings_by_severity": view_model.findings_by_severity,
        "ordered_findings": view_model.ordered_findings,
        "finding_evidence": {f.finding_id: view_model.evidence_for(f) for f in scan.findings},
        "conclusion": view_model.conclusion,
        "evidence_appendix": scan.evidence,
    }


def _severity_summary_rows(scan) -> list[tuple[str, int]]:
    return [(severity.value, count) for severity, count in scan.severity_summary.items()]


def _build_module_tables(scan) -> dict[str, dict[str, Any]]:
    """One table-friendly block per module: status, duration, key observations."""
    tables: dict[str, dict[str, Any]] = {}
    for module in ModuleName:
        result = next((m for m in scan.module_results if m.module == module), None)
        observations = {o.type: o.value for o in scan.observations if o.module == module}
        tables[module.value] = {
            "status": result.status.value if result else "not_tested",
            "duration_ms": round(result.duration_ms, 2) if result else None,
            "errors": result.errors if result else [],
            "observations": observations,
        }
    return tables


def findings_for_severity(context: dict[str, Any], severity_value: str) -> list[Finding]:
    for severity, findings in context["findings_by_severity"].items():
        if severity.value == severity_value:
            return findings
    return []
