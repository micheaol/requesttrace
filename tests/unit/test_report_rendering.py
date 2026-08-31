"""Report renderer tests (RT-031/032/033/034): equivalence, escaping, schema validity."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import jsonschema

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
from requesttrace.reporting.html_report import render_html_report
from requesttrace.reporting.json_report import render_json_report
from requesttrace.reporting.markdown_report import render_markdown_report
from requesttrace.reporting.pdf_report import render_pdf_report

_SCHEMA_PATH = Path(__file__).parents[2] / "schemas" / "report.schema.v1.json"


def _build_scan_with_xss_attempt() -> Scan:
    now = dt.datetime.now(dt.timezone.utc)
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
        scan_id="scan-1",
        scanner_version="1.0.0",
        ruleset_version="2026.08.1",
        schema_version="1.0.0",
        runtime="Python 3.13",
        container_image=None,
        started_at=now,
        completed_at=now,
        config=ScanConfigSnapshot(10.0, 10, "high", "RequestTrace/1.0", 30, 7),
    )
    finding = Finding(
        finding_id="finding-1",
        rule_id="RT-HDR-002",
        title="<script>alert(1)</script>",
        severity=Severity.MEDIUM,
        status=FindingStatus.OPEN,
        affected_asset="example.com",
        description="Untrusted content: <img src=x onerror=alert(1)>",
        evidence_ids=["ev-1"],
        security_impact="impact",
        recommendation="rec",
        how_to_fix="fix\nwith\nnewlines",
        verification="verify",
        priority="High",
    )
    evidence = Evidence(
        evidence_id="ev-1",
        observation_id="obs-1",
        module=ModuleName.HEADERS,
        timestamp=now,
        normalized_value="<script>evil()</script>",
        source_method="header_analyzer",
        confidence=Confidence.OBSERVED,
    )
    return Scan(
        metadata=metadata,
        target=target,
        evidence=[evidence],
        findings=[finding],
        module_results=[ModuleResult(module=ModuleName.HEADERS, status=ModuleStatus.COMPLETED, duration_ms=1.0)],
        assessment_label=AssessmentLabel.REMEDIATION_REQUIRED,
        severity_summary={Severity.MEDIUM: 1},
    )


def test_json_report_validates_against_schema() -> None:
    scan = _build_scan_with_xss_attempt()
    payload = json.loads(render_json_report(scan))
    schema = json.loads(_SCHEMA_PATH.read_text())
    jsonschema.validate(payload, schema)


def test_html_report_escapes_untrusted_finding_content() -> None:
    scan = _build_scan_with_xss_attempt()
    html = render_html_report(scan)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_markdown_report_contains_all_required_sections() -> None:
    scan = _build_scan_with_xss_attempt()
    markdown = render_markdown_report(scan)
    for heading in [
        "Executive Summary",
        "Scope",
        "Methodology",
        "Limitations",
        "Request-Path Summary",
        "DNS Assessment",
        "TLS Security Assessment",
        "Findings Summary",
        "Detailed Findings",
        "Evidence Appendix",
    ]:
        assert heading in markdown


def test_pdf_report_renders_bytes_with_pdf_header() -> None:
    scan = _build_scan_with_xss_attempt()
    pdf_bytes = render_pdf_report(scan)
    assert pdf_bytes.startswith(b"%PDF-")


def test_reports_never_contain_raw_secret_placeholder_text() -> None:
    scan = _build_scan_with_xss_attempt()
    for render in (render_markdown_report, render_html_report):
        output = render(scan)
        assert "BEGIN PRIVATE KEY" not in output
