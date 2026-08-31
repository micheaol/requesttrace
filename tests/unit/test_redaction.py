"""Redaction/sanitization tests (RT-027): secrets must never reach evidence."""

from __future__ import annotations

from requesttrace.evidence.redaction import (
    REDACTED_PLACEHOLDER,
    is_sensitive_header,
    redact_headers,
    sanitize_text,
)
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName


def test_authorization_header_is_redacted() -> None:
    headers = {"Authorization": "Bearer super-secret-token", "Content-Type": "text/html"}
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == REDACTED_PLACEHOLDER
    assert redacted["Content-Type"] == "text/html"


def test_header_redaction_is_case_insensitive() -> None:
    headers = {"authORIZATION": "Bearer xyz", "SET-COOKIE": "session=abc123"}
    redacted = redact_headers(headers)
    assert all(value == REDACTED_PLACEHOLDER for value in redacted.values())


def test_is_sensitive_header_matches_known_names() -> None:
    assert is_sensitive_header("Cookie")
    assert is_sensitive_header("Proxy-Authorization")
    assert not is_sensitive_header("Content-Type")


def test_sanitize_text_scrubs_inline_bearer_token() -> None:
    text = "Upstream failed: Authorization: Bearer abc.def.ghi was rejected"
    sanitized = sanitize_text(text)
    assert "abc.def.ghi" not in sanitized
    assert REDACTED_PLACEHOLDER in sanitized


def test_evidence_store_redacts_nested_headers_dict_defensively() -> None:
    store = EvidenceStore()
    observation = store.record_observation(ModuleName.HTTP, "response_headers", {"Set-Cookie": "session=abc"})
    evidence = store.record_evidence(
        observation,
        source_method="test",
        sanitized_raw={"headers": {"Set-Cookie": "session=abc"}},
    )
    assert evidence.sanitized_raw["headers"]["Set-Cookie"] == REDACTED_PLACEHOLDER


def test_cookie_values_never_enter_evidence_store() -> None:
    from requesttrace.analyzers.cookie_analyzer import analyze_set_cookie_headers

    store = EvidenceStore()
    analyze_set_cookie_headers(["session=top-secret-value; Path=/; Secure; HttpOnly"], store)

    for observation in store.observations:
        assert "top-secret-value" not in str(observation.value)
    for evidence in store.evidence:
        assert "top-secret-value" not in str(evidence.normalized_value)
        assert "top-secret-value" not in str(evidence.sanitized_raw)
