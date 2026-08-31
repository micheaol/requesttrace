"""Assessment label engine tests (RT-028): high risk never hides as PASS."""

from __future__ import annotations

from requesttrace.models.enums import (
    AssessmentLabel,
    FindingStatus,
    ModuleName,
    ModuleStatus,
    Severity,
)
from requesttrace.models.finding import Finding
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.target import Target
from requesttrace.reporting.labels import compute_severity_summary, derive_assessment_label


def _target(scheme: str = "https") -> Target:
    return Target(
        raw_input="example.com",
        scheme=scheme,
        host="example.com",
        port=443 if scheme == "https" else 80,
        path="/",
        query="",
        normalized_url=f"{scheme}://example.com/",
        is_ip_literal=False,
    )


def _finding(severity: Severity) -> Finding:
    return Finding(
        finding_id="f",
        rule_id="RT-TEST-001",
        title="t",
        severity=severity,
        status=FindingStatus.OPEN,
        affected_asset="example.com",
        description="d",
        evidence_ids=[],
        security_impact="i",
        recommendation="r",
        how_to_fix="h",
        verification="v",
        priority="p",
    )


def _complete_modules() -> list[ModuleResult]:
    return [
        ModuleResult(module=ModuleName.DNS, status=ModuleStatus.COMPLETED, duration_ms=1),
        ModuleResult(module=ModuleName.CONNECTIVITY, status=ModuleStatus.COMPLETED, duration_ms=1),
        ModuleResult(module=ModuleName.TLS, status=ModuleStatus.COMPLETED, duration_ms=1),
        ModuleResult(module=ModuleName.HTTP, status=ModuleStatus.COMPLETED, duration_ms=1),
    ]


def test_no_findings_and_complete_modules_is_pass() -> None:
    label = derive_assessment_label([], _complete_modules(), _target())
    assert label == AssessmentLabel.PASS


def test_only_low_findings_is_pass_with_observations() -> None:
    label = derive_assessment_label([_finding(Severity.LOW)], _complete_modules(), _target())
    assert label == AssessmentLabel.PASS_WITH_OBSERVATIONS


def test_high_finding_is_remediation_required() -> None:
    label = derive_assessment_label([_finding(Severity.HIGH)], _complete_modules(), _target())
    assert label == AssessmentLabel.REMEDIATION_REQUIRED


def test_critical_finding_is_high_risk() -> None:
    label = derive_assessment_label([_finding(Severity.CRITICAL)], _complete_modules(), _target())
    assert label == AssessmentLabel.HIGH_RISK


def test_incomplete_critical_module_with_no_findings_is_assessment_incomplete() -> None:
    modules = [
        ModuleResult(module=ModuleName.DNS, status=ModuleStatus.COMPLETED, duration_ms=1),
        ModuleResult(
            module=ModuleName.CONNECTIVITY,
            status=ModuleStatus.ERROR,
            duration_ms=1,
            errors=["refused"],
        ),
        ModuleResult(
            module=ModuleName.TLS,
            status=ModuleStatus.ERROR,
            duration_ms=1,
            errors=["handshake failed"],
        ),
        ModuleResult(module=ModuleName.HTTP, status=ModuleStatus.ERROR, duration_ms=1, errors=["failed"]),
    ]
    label = derive_assessment_label([], modules, _target())
    assert label == AssessmentLabel.ASSESSMENT_INCOMPLETE


def test_incomplete_module_never_hides_an_already_found_critical_risk() -> None:
    modules = [
        ModuleResult(module=ModuleName.DNS, status=ModuleStatus.COMPLETED, duration_ms=1),
        ModuleResult(module=ModuleName.CONNECTIVITY, status=ModuleStatus.COMPLETED, duration_ms=1),
        ModuleResult(module=ModuleName.TLS, status=ModuleStatus.COMPLETED, duration_ms=1),
        ModuleResult(module=ModuleName.HTTP, status=ModuleStatus.ERROR, duration_ms=1, errors=["failed"]),
    ]
    label = derive_assessment_label([_finding(Severity.CRITICAL)], modules, _target())
    assert label == AssessmentLabel.HIGH_RISK


def test_severity_summary_counts_every_severity_level() -> None:
    summary = compute_severity_summary([_finding(Severity.HIGH), _finding(Severity.HIGH), _finding(Severity.LOW)])
    assert summary[Severity.HIGH] == 2
    assert summary[Severity.LOW] == 1
    assert summary[Severity.CRITICAL] == 0
