"""Target normalizer tests (RT-003): parsing, defaults and rejection paths."""

from __future__ import annotations

import pytest

from requesttrace.target import TargetValidationError, normalize_target


def test_bare_hostname_defaults_to_https() -> None:
    target = normalize_target("example.com")
    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port == 443
    assert target.path == "/"
    assert target.normalized_url == "https://example.com/"


def test_full_https_url_preserves_path_and_query() -> None:
    target = normalize_target("https://example.com/status?check=1")
    assert target.path == "/status"
    assert target.query == "check=1"
    assert target.normalized_url == "https://example.com/status?check=1"


def test_explicit_http_scheme_defaults_port_80() -> None:
    target = normalize_target("http://example.com")
    assert target.scheme == "http"
    assert target.port == 80


def test_explicit_non_default_port_is_preserved_in_normalized_url() -> None:
    target = normalize_target("https://example.com:8443/")
    assert target.port == 8443
    assert target.normalized_url == "https://example.com:8443/"


def test_default_port_is_omitted_from_normalized_url_and_authority() -> None:
    target = normalize_target("https://example.com:443/")
    assert target.normalized_url == "https://example.com/"
    assert target.authority == "example.com"


def test_host_with_non_default_port_authority() -> None:
    target = normalize_target("example.com:8443")
    assert target.authority == "example.com:8443"


def test_ipv4_literal_is_recognized() -> None:
    target = normalize_target("https://127.0.0.1/")
    assert target.is_ip_literal is True
    assert target.host == "127.0.0.1"


def test_ipv6_literal_is_recognized() -> None:
    target = normalize_target("https://[::1]/")
    assert target.is_ip_literal is True
    assert target.host == "::1"


def test_hostname_is_lowercased() -> None:
    target = normalize_target("HTTPS://Example.COM/Path")
    assert target.host == "example.com"
    assert target.path == "/Path"


@pytest.mark.parametrize(
    "raw_input",
    [
        "",
        "   ",
        "ftp://example.com",
        "javascript://alert(1)",
        "https://",
        "https://-badhost-.com",
        "https://example..com",
    ],
)
def test_malformed_or_unsupported_targets_are_rejected(raw_input: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_target(raw_input)


def test_out_of_range_port_is_rejected() -> None:
    with pytest.raises(TargetValidationError):
        normalize_target("https://example.com:99999/")


def test_raw_input_is_preserved_verbatim() -> None:
    target = normalize_target("Example.com")
    assert target.raw_input == "Example.com"
