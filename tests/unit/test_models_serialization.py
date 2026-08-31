"""Model serialization tests (RT-002): Scan/Finding/Evidence JSON round-tripping."""

from __future__ import annotations

import datetime as dt
import json

from requesttrace.models.enums import (
    AssessmentLabel,
    Confidence,
    FindingStatus,
    ModuleName,
    ModuleStatus,
    Severity,
)
from requesttrace.models.evidence import Evidence
from requesttrace.models.finding import Finding
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.scan import Scan, ScanConfigSnapshot, ScanMetadata
from requesttrace.models.target import Target
from requesttrace.util.serialization import dump_json, to_json_safe


def _build_minimal_scan() -> Scan:
    target = Target(
        raw_input="example.com",
        scheme="https",
        host="example.com",
        port=443,
        path="/",
        query="",
        normalized_url="https://example.com/",
        is_ip_literal=False,
    )
    metadata = ScanMetadata(
        scan_id="scan-test",
        scanner_version="1.0.0",
        ruleset_version="2026.08.1",
        schema_version="1.0.0",
        runtime="Python 3.13",
        container_image=None,
        started_at=dt.datetime.now(dt.timezone.utc),
        completed_at=dt.datetime.now(dt.timezone.utc),
        config=ScanConfigSnapshot(
            timeout_seconds=10.0,
            max_redirects=10,
            fail_on="high",
            user_agent="RequestTrace/1.0",
            certificate_warning_days=30,
            certificate_critical_days=7,
        ),
    )
    finding = Finding(
        finding_id="finding-1",
        rule_id="RT-HDR-001",
        title="Missing HSTS",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        affected_asset="example.com",
        description="desc",
        evidence_ids=["ev-1"],
        security_impact="impact",
        recommendation="rec",
        how_to_fix="fix",
        verification="verify",
        priority="High",
    )
    evidence = Evidence(
        evidence_id="ev-1",
        observation_id="obs-1",
        module=ModuleName.HEADERS,
        timestamp=dt.datetime.now(dt.timezone.utc),
        normalized_value={"present": False},
        source_method="header_analyzer",
        confidence=Confidence.OBSERVED,
    )
    module_result = ModuleResult(
        module=ModuleName.HEADERS,
        status=ModuleStatus.COMPLETED,
        duration_ms=12.3,
        observation_ids=["obs-1"],
    )

    return Scan(
        metadata=metadata,
        target=target,
        observations=[],
        evidence=[evidence],
        findings=[finding],
        module_results=[module_result],
        assessment_label=AssessmentLabel.REMEDIATION_REQUIRED,
        severity_summary={Severity.HIGH: 1},
    )


def test_scan_serializes_to_valid_json() -> None:
    scan = _build_minimal_scan()
    payload = dump_json(scan)
    parsed = json.loads(payload)

    assert parsed["assessment_label"] == "REMEDIATION REQUIRED"
    assert parsed["findings"][0]["rule_id"] == "RT-HDR-001"
    assert parsed["findings"][0]["severity"] == "high"
    assert parsed["evidence"][0]["module"] == "headers"


def test_finding_references_evidence_ids() -> None:
    scan = _build_minimal_scan()
    assert scan.findings[0].evidence_ids == ["ev-1"]
    assert scan.evidence_by_id("ev-1") is not None


def test_datetimes_serialize_as_iso8601_utc() -> None:
    scan = _build_minimal_scan()
    payload = to_json_safe(scan)
    started_at = payload["metadata"]["started_at"]
    assert started_at.endswith("Z")


def test_findings_at_or_above_filters_by_severity_rank() -> None:
    scan = _build_minimal_scan()
    assert scan.findings_at_or_above(Severity.HIGH) == scan.findings
    assert scan.findings_at_or_above(Severity.CRITICAL) == []
