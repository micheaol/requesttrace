"""Security-header rule tests (RT-021 consumer)."""

from __future__ import annotations

from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName
from requesttrace.models.target import Target
from requesttrace.rules import header_rules
from requesttrace.rules.base import RuleContext


def _context(store: EvidenceStore, fast_scan_config) -> RuleContext:
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
    return RuleContext(target=target, config=fast_scan_config, store=store)


def test_missing_hsts_triggers_high_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HEADERS,
        "hsts",
        {
            "present": False,
            "raw": None,
            "max_age": None,
            "include_subdomains": False,
            "preload": False,
        },
        source_method="test",
    )
    findings = header_rules._evaluate_missing_hsts(_context(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_hsts_with_strong_max_age_has_no_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HEADERS,
        "hsts",
        {
            "present": True,
            "raw": "max-age=63072000",
            "max_age": 63072000,
            "include_subdomains": False,
            "preload": False,
        },
        source_method="test",
    )
    assert header_rules._evaluate_missing_hsts(_context(store, fast_scan_config)) == []


def test_hsts_with_short_max_age_triggers_medium_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HEADERS,
        "hsts",
        {
            "present": True,
            "raw": "max-age=60",
            "max_age": 60,
            "include_subdomains": False,
            "preload": False,
        },
        source_method="test",
    )
    findings = header_rules._evaluate_missing_hsts(_context(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"


def test_missing_csp_triggers_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HEADERS,
        "content_security_policy",
        {"present": False, "raw": None, "high_risk_patterns": []},
        source_method="test",
    )
    findings = header_rules._evaluate_content_security_policy(_context(store, fast_scan_config))
    assert len(findings) == 1


def test_csp_with_high_risk_pattern_triggers_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HEADERS,
        "content_security_policy",
        {
            "present": True,
            "raw": "default-src 'self' 'unsafe-inline'",
            "high_risk_patterns": ["unsafe-inline"],
        },
        source_method="test",
    )
    findings = header_rules._evaluate_content_security_policy(_context(store, fast_scan_config))
    assert len(findings) == 1
    assert "unsafe-inline" in findings[0].description


def test_clean_csp_has_no_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HEADERS,
        "content_security_policy",
        {"present": True, "raw": "default-src 'self'", "high_risk_patterns": []},
        source_method="test",
    )
    assert header_rules._evaluate_content_security_policy(_context(store, fast_scan_config)) == []


def test_missing_x_content_type_options_triggers_low_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HEADERS,
        "x_content_type_options",
        {"present": False, "value": None, "valid_nosniff": False},
        source_method="test",
    )
    findings = header_rules._evaluate_x_content_type_options(_context(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "low"


def test_missing_frame_protection_triggers_medium_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HEADERS,
        "frame_protection",
        {
            "csp_frame_ancestors_present": False,
            "x_frame_options_present": False,
            "x_frame_options_value": None,
            "protected": False,
        },
        source_method="test",
    )
    findings = header_rules._evaluate_frame_protection(_context(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"


def test_x_frame_options_alone_satisfies_frame_protection(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.HEADERS,
        "frame_protection",
        {
            "csp_frame_ancestors_present": False,
            "x_frame_options_present": True,
            "x_frame_options_value": "DENY",
            "protected": True,
        },
        source_method="test",
    )
    assert header_rules._evaluate_frame_protection(_context(store, fast_scan_config)) == []


def test_permissions_policy_never_produces_a_finding() -> None:
    # Permissions-Policy is informational-only per PRD §8.6; no rule references it.
    assert not any("permissions" in rule.rule_id.lower() for rule in header_rules.RULES)
