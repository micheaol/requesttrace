"""Parse and validate raw CLI target input into a trusted :class:`Target`.

This is the single point where untrusted user input is turned into
structured data. Nothing downstream re-parses ``raw_input``, and the
normalized fields here are what get passed to networking calls — never a
shell command, so target input can never reach a shell.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from requesttrace.models.target import Target

_SUPPORTED_SCHEMES = {"http", "https"}
_DEFAULT_SCHEME = "https"
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Conservative hostname validation: labels of letters/digits/hyphen, no
# leading/trailing hyphen per label, 1-63 chars per label, dots between.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


class TargetValidationError(ValueError):
    """Raised when raw target input cannot be normalized into a safe Target."""


def normalize_target(raw_input: str) -> Target:
    """Normalize hostname/domain/URL input into a validated :class:`Target`.

    Accepts bare hostnames (``example.com``), host:port pairs, and full
    HTTP(S) URLs. Defaults to HTTPS when no scheme is supplied. Raises
    :class:`TargetValidationError` on anything malformed or unsupported —
    callers should map that to CLI exit code 2.
    """
    candidate = (raw_input or "").strip()
    if not candidate:
        raise TargetValidationError("Target must not be empty.")

    candidate_with_scheme = _ensure_scheme_present(candidate)
    parts = urlsplit(candidate_with_scheme)

    scheme = _validate_scheme(parts.scheme)
    host, is_ip_literal = _validate_host(parts.hostname)
    port = _resolve_port(_extract_port(parts), scheme)
    path = _normalize_path(parts.path)
    query = parts.query or ""

    normalized_url = _build_normalized_url(scheme, host, port, path, query, is_ip_literal)

    return Target(
        raw_input=raw_input,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=query,
        normalized_url=normalized_url,
        is_ip_literal=is_ip_literal,
    )


def _ensure_scheme_present(candidate: str) -> str:
    if "://" in candidate:
        return candidate
    # Bare "host:port" must not be mistaken for a scheme by urlsplit.
    return f"{_DEFAULT_SCHEME}://{candidate}"


def _validate_scheme(scheme: str) -> str:
    scheme = (scheme or "").lower()
    if scheme not in _SUPPORTED_SCHEMES:
        raise TargetValidationError(
            f"Unsupported scheme '{scheme or '<missing>'}'. Supported schemes: {', '.join(sorted(_SUPPORTED_SCHEMES))}."
        )
    return scheme


def _extract_port(parts) -> int | None:
    """Read ``parts.port``, converting Python's own out-of-range ValueError.

    Python 3.13+ validates the port range inside ``SplitResult.port`` itself,
    raising ``ValueError`` before our own range check ever runs.
    """
    try:
        return parts.port
    except ValueError as exc:
        raise TargetValidationError(f"Invalid port in target: {exc}") from exc


def _validate_host(hostname: str | None) -> tuple[str, bool]:
    if not hostname:
        raise TargetValidationError("Target is missing a host.")

    hostname = hostname.strip(".").lower()

    ip_literal = _try_parse_ip_literal(hostname)
    if ip_literal is not None:
        return ip_literal, True

    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetValidationError(f"Invalid internationalized hostname: {hostname!r}") from exc

    if not _HOSTNAME_RE.match(ascii_host):
        raise TargetValidationError(f"Malformed hostname: {hostname!r}")

    return ascii_host, False


def _try_parse_ip_literal(hostname: str) -> str | None:
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        return None


def _resolve_port(explicit_port: int | None, scheme: str) -> int:
    if explicit_port is None:
        return _DEFAULT_PORTS[scheme]
    if not (1 <= explicit_port <= 65535):
        raise TargetValidationError(f"Port out of range: {explicit_port}")
    return explicit_port


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    return path


def _build_normalized_url(scheme: str, host: str, port: int, path: str, query: str, is_ip_literal: bool) -> str:
    host_part = f"[{host}]" if is_ip_literal and ":" in host else host
    default_port = _DEFAULT_PORTS[scheme]
    netloc = host_part if port == default_port else f"{host_part}:{port}"
    return urlunsplit((scheme, netloc, path, query, ""))
