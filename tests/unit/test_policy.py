"""`--fail-on` policy engine tests (RT-029)."""

from __future__ import annotations

import pytest

from requesttrace.models.enums import FindingStatus, Severity
from requesttrace.models.finding import Finding
from requesttrace.policy import policy_is_breached


def _finding(severity: Severity) -> Finding:
    return Finding(
        finding_id="f-1",
        rule_id="RT-TEST-001",
        title="test",
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


@pytest.mark.parametrize(
    "fail_on,finding_severity,expected_breach",
    [
        ("critical", Severity.CRITICAL, True),
        ("critical", Severity.HIGH, False),
        ("high", Severity.HIGH, True),
        ("high", Severity.MEDIUM, False),
        ("medium", Severity.MEDIUM, True),
        ("low", Severity.LOW, True),
        ("low", Severity.INFORMATIONAL, False),
        ("never", Severity.CRITICAL, False),
    ],
)
def test_policy_threshold_matrix(fail_on: str, finding_severity: Severity, expected_breach: bool) -> None:
    assert policy_is_breached([_finding(finding_severity)], fail_on) is expected_breach


def test_no_findings_never_breaches() -> None:
    assert policy_is_breached([], "low") is False


def test_higher_severity_than_threshold_also_breaches() -> None:
    assert policy_is_breached([_finding(Severity.CRITICAL)], "medium") is True
