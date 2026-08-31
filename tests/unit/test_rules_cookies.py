"""Cookie rule tests (RT-022 consumer): Secure/SameSite scored, HttpOnly never blanket-flagged."""

from __future__ import annotations

from requesttrace.analyzers.cookie_analyzer import analyze_set_cookie_headers
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.target import Target
from requesttrace.rules import cookie_rules
from requesttrace.rules.base import RuleContext


def _context(store: EvidenceStore, fast_scan_config, scheme: str = "https") -> RuleContext:
    target = Target(
        raw_input="example.com",
        scheme=scheme,
        host="example.com",
        port=443 if scheme == "https" else 80,
        path="/",
        query="",
        normalized_url=f"{scheme}://example.com/",
        is_ip_literal=False,
    )
    return RuleContext(target=target, config=fast_scan_config, store=store)


def test_cookie_missing_secure_over_https_triggers_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    analyze_set_cookie_headers(["session=abc; Path=/; HttpOnly; SameSite=Lax"], store)
    findings = cookie_rules._evaluate_missing_secure(_context(store, fast_scan_config))
    assert len(findings) == 1
    assert "session" in findings[0].description


def test_cookie_with_secure_has_no_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    analyze_set_cookie_headers(["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"], store)
    assert cookie_rules._evaluate_missing_secure(_context(store, fast_scan_config)) == []


def test_secure_not_checked_on_plain_http_target(fast_scan_config) -> None:
    store = EvidenceStore()
    analyze_set_cookie_headers(["session=abc; Path=/"], store)
    assert cookie_rules._evaluate_missing_secure(_context(store, fast_scan_config, scheme="http")) == []


def test_cookie_missing_samesite_triggers_low_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    analyze_set_cookie_headers(["session=abc; Path=/; Secure; HttpOnly"], store)
    findings = cookie_rules._evaluate_missing_samesite(_context(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "low"


def test_cookie_with_samesite_has_no_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    analyze_set_cookie_headers(["session=abc; Path=/; Secure; HttpOnly; SameSite=Strict"], store)
    assert cookie_rules._evaluate_missing_samesite(_context(store, fast_scan_config)) == []


def test_no_rule_ever_flags_missing_http_only() -> None:
    # PRD explicitly forbids a blanket HttpOnly finding — client-side access may be intentional.
    assert not any("httponly" in rule.title.lower() or "http-only" in rule.title.lower() for rule in cookie_rules.RULES)
