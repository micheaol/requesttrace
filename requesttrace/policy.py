"""The `--fail-on` policy engine (RT-029): maps findings + threshold to a policy verdict."""

from __future__ import annotations

from requesttrace.models.enums import Severity
from requesttrace.models.finding import Finding

_THRESHOLD_TO_SEVERITY: dict[str, Severity | None] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "never": None,
}


def policy_is_breached(findings: list[Finding], fail_on: str) -> bool:
    """True if any finding meets or exceeds the configured `--fail-on` threshold."""
    threshold = _THRESHOLD_TO_SEVERITY[fail_on]
    if threshold is None:
        return False
    return any(finding.severity.rank >= threshold.rank for finding in findings)
