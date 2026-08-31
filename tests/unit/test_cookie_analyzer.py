"""Cookie parsing tests (RT-022): attributes captured, values never captured."""

from __future__ import annotations

from requesttrace.analyzers.cookie_analyzer import _parse_single_cookie_header


def test_parses_name_and_attributes() -> None:
    parsed = _parse_single_cookie_header("session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert parsed.name == "session"
    assert parsed.secure is True
    assert parsed.http_only is True
    assert parsed.same_site == "Lax"


def test_missing_attributes_default_false_or_none() -> None:
    parsed = _parse_single_cookie_header("tracking=xyz; Path=/")
    assert parsed.secure is False
    assert parsed.http_only is False
    assert parsed.same_site is None


def test_malformed_header_without_equals_returns_none() -> None:
    assert _parse_single_cookie_header("garbage-no-equals") is None


def test_parsed_attributes_object_never_stores_raw_value() -> None:
    parsed = _parse_single_cookie_header("session=super-secret-value; Secure")
    assert not hasattr(parsed, "value")
    assert "super-secret-value" not in str(parsed)
