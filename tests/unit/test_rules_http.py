"""HTTP/redirect rule tests (RT-020 consumer)."""

from __future__ import annotations

from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName
from requesttrace.models.target import Target
from requesttrace.rules import http_rules
from requesttrace.rules.base import RuleContext


def _make_target(scheme: str = "https") -> Target:
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


def _context(store: EvidenceStore, fast_scan_config, scheme: str = "https") -> RuleContext:
    return RuleContext(target=_make_target(scheme), config=fast_scan_config, store=store)


def test_https_to_http_downgrade_triggers_critical_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.REDIRECTS, "https_to_http_downgrade_detected", True, source_method="test"
    )
    findings = http_rules._evaluate_https_downgrade(_context(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_no_downgrade_no_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.REDIRECTS, "https_to_http_downgrade_detected", False, source_method="test"
    )
    assert http_rules._evaluate_https_downgrade(_context(store, fast_scan_config)) == []


def test_missing_http_to_https_redirect_triggers_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HTTP,
        "http_to_https_redirect",
        {
            "probed_url": "http://example.com/",
            "status_code": 200,
            "location": None,
            "redirects_to_https": False,
        },
        source_method="test",
    )
    findings = http_rules._evaluate_missing_http_to_https_redirect(_context(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].rule_id == "RT-HTTP-002"


def test_present_http_to_https_redirect_has_no_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HTTP,
        "http_to_https_redirect",
        {
            "probed_url": "http://example.com/",
            "status_code": 301,
            "location": "https://example.com/",
            "redirects_to_https": True,
        },
        source_method="test",
    )
    assert http_rules._evaluate_missing_http_to_https_redirect(_context(store, fast_scan_config)) == []


def test_http_scheme_target_is_exempt_from_downgrade_redirect_check(fast_scan_config) -> None:
    store = EvidenceStore()
    assert http_rules._evaluate_missing_http_to_https_redirect(_context(store, fast_scan_config, scheme="http")) == []


def test_redirect_loop_triggers_medium_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(ModuleName.REDIRECTS, "redirect_loop_detected", True, source_method="test")
    findings = http_rules._evaluate_redirect_loop(_context(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
