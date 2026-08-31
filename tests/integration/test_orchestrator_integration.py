"""End-to-end orchestrator test against a local HTTP fixture (no live internet)."""

from __future__ import annotations

from dataclasses import replace

from requesttrace.models.enums import AssessmentLabel, ModuleStatus
from requesttrace.orchestrator import ScanOrchestrator
from tests.fixtures.local_http_server import LocalHttpServer, RouteResponse


def test_full_scan_against_local_http_server_produces_findings(fast_scan_config) -> None:
    routes = {"/": RouteResponse(200, headers=[("Content-Type", "text/plain")], body=b"hello")}
    with LocalHttpServer(routes) as server:
        config = replace(fast_scan_config, target_input=server.base_url + "/")
        scan = ScanOrchestrator().run(config)

    assert scan.observations, "orchestrator must collect observations from a reachable local server"
    assert scan.assessment_label in (
        AssessmentLabel.PASS_WITH_OBSERVATIONS,
        AssessmentLabel.REMEDIATION_REQUIRED,
    )
    # No CSP/HSTS/etc. were sent, so header findings must fire.
    assert any(f.rule_id.startswith("RT-HDR") for f in scan.findings)

    http_result = next(m for m in scan.module_results if m.module.value == "http")
    assert http_result.status == ModuleStatus.COMPLETED


def test_unreachable_target_yields_scan_execution_signal_not_a_crash(fast_scan_config) -> None:
    config = replace(fast_scan_config, target_input="http://127.0.0.1:1/", timeout_seconds=1.0)
    scan = ScanOrchestrator().run(config)
    # Every module should fail cleanly rather than raising.
    assert all(
        m.status == ModuleStatus.ERROR for m in scan.module_results if m.module.value in ("connectivity", "http")
    )
