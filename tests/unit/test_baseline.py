"""Baseline comparison tests (RT-035): new/unchanged/resolved classification."""

from __future__ import annotations

import datetime as dt

from requesttrace.models.enums import (
    AssessmentLabel,
    ChangeType,
    FindingStatus,
    ModuleName,
    ModuleStatus,
    Severity,
)
from requesttrace.models.finding import Finding
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.scan import Scan, ScanConfigSnapshot, ScanMetadata
from requesttrace.models.target import Target
from requesttrace.reporting.baseline import compare_to_baseline


def _target() -> Target:
    return Target(
        raw_input="example.com",
        scheme="https",
        host="example.com",
        port=443,
        path="/",
        query="",
        normalized_url="https://example.com/",
        is_ip_literal=False,
    )


def _finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        finding_id="f",
        rule_id=rule_id,
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


def _scan(findings: list[Finding], module_status: ModuleStatus = ModuleStatus.COMPLETED) -> Scan:
    now = dt.datetime.now(dt.timezone.utc)
    return Scan(
        metadata=ScanMetadata(
            scan_id="s",
            scanner_version="1.0.0",
            ruleset_version="2026.08.1",
            schema_version="1.0.0",
            runtime="Python",
            container_image=None,
            started_at=now,
            completed_at=now,
            config=ScanConfigSnapshot(10.0, 10, "high", "RequestTrace/1.0", 30, 7),
        ),
        target=_target(),
        findings=findings,
        module_results=[
            ModuleResult(module=ModuleName.TLS, status=module_status, duration_ms=1),
            ModuleResult(module=ModuleName.HTTP, status=module_status, duration_ms=1),
        ],
        assessment_label=AssessmentLabel.PASS,
    )


def test_new_finding_not_in_baseline_is_classified_new() -> None:
    current = _scan([_finding("RT-TLS-001", Severity.HIGH)])
    baseline = {"findings": []}
    entries = compare_to_baseline(current, baseline)
    assert entries[0].change_type == ChangeType.NEW


def test_matching_finding_and_severity_is_unchanged() -> None:
    current = _scan([_finding("RT-TLS-001", Severity.HIGH)])
    baseline = {
        "findings": [
            {
                "rule_id": "RT-TLS-001",
                "affected_asset": "example.com",
                "severity": "high",
                "title": "t",
            }
        ]
    }
    entries = compare_to_baseline(current, baseline)
    assert entries[0].change_type == ChangeType.UNCHANGED


def test_severity_change_is_classified_changed() -> None:
    current = _scan([_finding("RT-TLS-001", Severity.CRITICAL)])
    baseline = {
        "findings": [
            {
                "rule_id": "RT-TLS-001",
                "affected_asset": "example.com",
                "severity": "high",
                "title": "t",
            }
        ]
    }
    entries = compare_to_baseline(current, baseline)
    assert entries[0].change_type == ChangeType.CHANGED


def test_finding_absent_now_is_resolved_when_module_completed() -> None:
    current = _scan([], module_status=ModuleStatus.COMPLETED)
    baseline = {
        "findings": [
            {
                "rule_id": "RT-TLS-001",
                "affected_asset": "example.com",
                "severity": "high",
                "title": "t",
            }
        ]
    }
    entries = compare_to_baseline(current, baseline)
    assert entries[0].change_type == ChangeType.RESOLVED


def test_finding_absent_now_is_not_resolved_when_module_incomplete() -> None:
    current = _scan([], module_status=ModuleStatus.ERROR)
    baseline = {
        "findings": [
            {
                "rule_id": "RT-TLS-001",
                "affected_asset": "example.com",
                "severity": "high",
                "title": "t",
            }
        ]
    }
    entries = compare_to_baseline(current, baseline)
    # A baseline must never claim remediation it could not actually verify.
    assert entries[0].change_type == ChangeType.UNCHANGED
