"""Security-header analyzer tests (RT-021): case-insensitive parsing."""

from __future__ import annotations

from requesttrace.analyzers.header_analyzer import (
    _assess_csp,
    _assess_frame_protection,
    _assess_hsts,
    _CaseInsensitiveLookup,
)


def test_hsts_parses_max_age_and_directives() -> None:
    lookup = _CaseInsensitiveLookup({"strict-transport-security": "max-age=31536000; includeSubDomains; preload"})
    result = _assess_hsts(lookup)
    assert result["present"] is True
    assert result["max_age"] == 31536000
    assert result["include_subdomains"] is True
    assert result["preload"] is True


def test_header_lookup_is_case_insensitive() -> None:
    lookup = _CaseInsensitiveLookup({"STRICT-TRANSPORT-SECURITY": "max-age=100"})
    result = _assess_hsts(lookup)
    assert result["present"] is True
    assert result["max_age"] == 100


def test_csp_flags_unsafe_inline_as_high_risk() -> None:
    lookup = _CaseInsensitiveLookup({"Content-Security-Policy": "script-src 'unsafe-inline'"})
    result = _assess_csp(lookup)
    assert "unsafe-inline" in result["high_risk_patterns"]


def test_frame_protection_recognizes_csp_frame_ancestors() -> None:
    lookup = _CaseInsensitiveLookup({"Content-Security-Policy": "frame-ancestors 'self'"})
    result = _assess_frame_protection(lookup)
    assert result["csp_frame_ancestors_present"] is True
    assert result["protected"] is True
