"""Redaction and sanitization applied before any value reaches evidence/reports.

This module is the single choke point for secret handling (RT-027). Every
scanner/analyzer that captures raw headers, cookies, or error text must
route it through here before it becomes an :class:`~requesttrace.models.evidence.Evidence`
record — including in verbose logs and JSON output, not just human reports.
"""

from __future__ import annotations

import re

REDACTED_PLACEHOLDER = "***REDACTED***"

# Header names are matched case-insensitively. Extend via `additional_headers`
# rather than editing this set, so policy overrides stay declarative.
_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}

# Matches common secret-bearing substrings inside otherwise-safe error text,
# e.g. a stack trace that echoes a connection string or bearer token.
_INLINE_SECRET_PATTERN = re.compile(
    r"(?i)(authorization:\s*bearer\s+[a-z0-9\-._~+/]+=*"
    r"|bearer\s+[a-z0-9\-._~+/]+=*"
    r"|authorization:\s*\S+"
    r"|password=\S+"
    r"|api[_-]?key=\S+)"
)


def is_sensitive_header(header_name: str, *, additional_headers: frozenset[str] = frozenset()) -> bool:
    normalized = header_name.strip().lower()
    return normalized in _SENSITIVE_HEADER_NAMES or normalized in additional_headers


def redact_sensitive_value(_header_name: str) -> str:
    """Return the fixed placeholder used for any redacted value.

    Kept as a function (rather than a bare constant reference at call
    sites) so redaction policy — e.g. partial masking — can evolve in one
    place without touching every caller.
    """
    return REDACTED_PLACEHOLDER


def redact_headers(headers: dict[str, str], *, additional_headers: frozenset[str] = frozenset()) -> dict[str, str]:
    """Return a copy of ``headers`` with sensitive values replaced.

    Header *names* are preserved (they are useful evidence, e.g. "a
    Set-Cookie header was present"); only values are redacted.
    """
    return {
        name: redact_sensitive_value(name)
        if is_sensitive_header(name, additional_headers=additional_headers)
        else value
        for name, value in headers.items()
    }


def sanitize_text(text: str) -> str:
    """Scrub inline secret-shaped substrings out of free-form text (e.g. errors)."""
    return _INLINE_SECRET_PATTERN.sub(REDACTED_PLACEHOLDER, text)


def redact_cookie_value(_raw_cookie_value: str) -> str:
    """Cookie values are never persisted in evidence — only names/attributes."""
    return REDACTED_PLACEHOLDER
