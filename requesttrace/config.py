"""Scan configuration: CLI-flag defaults, optional config-file overlay, validation."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from requesttrace.exit_codes import InvalidInputError

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_REDIRECTS = 10
DEFAULT_USER_AGENT = "RequestTrace/1.0 (+https://github.com/micheaol/requesttrace)"
DEFAULT_CERT_WARNING_DAYS = 30
DEFAULT_CERT_CRITICAL_DAYS = 7

_VALID_FAIL_ON = {"critical", "high", "medium", "low", "never"}
_VALID_FORMATS = {"md", "html", "pdf", "json", "all"}


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Fully resolved configuration for a single scan invocation."""

    target_input: str
    output_dir: Path
    formats: tuple[str, ...]
    fail_on: str
    baseline_path: Path | None
    timeout_seconds: float
    max_redirects: int
    verbose: bool
    quiet: bool
    user_agent: str
    certificate_warning_days: int
    certificate_critical_days: int
    write_reports: bool

    def resolved_formats(self) -> tuple[str, ...]:
        """Expand the ``all`` shorthand into the concrete format list."""
        if "all" in self.formats:
            return ("md", "html", "json", "pdf")
        return self.formats


def load_config_overlay(config_path: Path | None) -> dict[str, Any]:
    """Load a JSON config file's contents, or an empty overlay when unset."""
    if config_path is None:
        return {}
    if not config_path.is_file():
        raise InvalidInputError(f"Config file not found: {config_path}")
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidInputError(f"Config file is not valid JSON: {config_path} ({exc})") from exc


def build_scan_config(
    *,
    target_input: str,
    output_dir: str | Path = "reports",
    formats: tuple[str, ...] = ("all",),
    fail_on: str = "high",
    baseline_path: str | Path | None = None,
    timeout_seconds: float | None = None,
    max_redirects: int | None = None,
    verbose: bool = False,
    quiet: bool = False,
    config_path: str | Path | None = None,
    write_reports: bool = True,
) -> ScanConfig:
    """Merge CLI flags with an optional config-file overlay into a validated ScanConfig.

    CLI-supplied values always win over the config file; the config file
    wins over built-in defaults.
    """
    overlay = load_config_overlay(Path(config_path) if config_path else None)

    resolved_fail_on = fail_on or overlay.get("fail_on", "high")
    _validate_fail_on(resolved_fail_on)

    resolved_formats = tuple(formats) or tuple(overlay.get("formats", ["all"]))
    _validate_formats(resolved_formats)

    return ScanConfig(
        target_input=target_input,
        output_dir=Path(output_dir or overlay.get("output_dir", "reports")),
        formats=resolved_formats,
        fail_on=resolved_fail_on,
        baseline_path=Path(baseline_path) if baseline_path else None,
        timeout_seconds=float(
            timeout_seconds if timeout_seconds is not None else overlay.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        ),
        max_redirects=int(
            max_redirects if max_redirects is not None else overlay.get("max_redirects", DEFAULT_MAX_REDIRECTS)
        ),
        verbose=verbose,
        quiet=quiet,
        user_agent=str(overlay.get("user_agent", DEFAULT_USER_AGENT)),
        certificate_warning_days=int(overlay.get("certificate_warning_days", DEFAULT_CERT_WARNING_DAYS)),
        certificate_critical_days=int(overlay.get("certificate_critical_days", DEFAULT_CERT_CRITICAL_DAYS)),
        write_reports=write_reports,
    )


def with_overrides(config: ScanConfig, **overrides: Any) -> ScanConfig:
    """Return a copy of ``config`` with the given fields replaced."""
    return replace(config, **overrides)


def _validate_fail_on(value: str) -> None:
    if value not in _VALID_FAIL_ON:
        raise InvalidInputError(
            f"Invalid --fail-on value '{value}'. Must be one of: {', '.join(sorted(_VALID_FAIL_ON))}."
        )


def _validate_formats(values: tuple[str, ...]) -> None:
    unknown = set(values) - _VALID_FORMATS
    if unknown:
        raise InvalidInputError(
            f"Unknown report format(s): {', '.join(sorted(unknown))}. "
            f"Must be one of: {', '.join(sorted(_VALID_FORMATS))}."
        )
