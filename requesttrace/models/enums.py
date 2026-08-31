"""Enumerations shared across the normalized data model."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Finding severity, ordered from least to most severe."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank used for threshold comparisons (higher = more severe)."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    """Confidence level attached to an observation or inferred signal."""

    OBSERVED = "observed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ModuleStatus(str, Enum):
    """Execution status of a single scanner/analyzer module."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    ERROR = "error"
    NOT_TESTED = "not_tested"
    SKIPPED = "skipped"


class ModuleName(str, Enum):
    """Stable identifiers for each scan module, used in evidence and reports."""

    DNS = "dns"
    CONNECTIVITY = "connectivity"
    TLS = "tls"
    HTTP = "http"
    REDIRECTS = "redirects"
    HEADERS = "headers"
    COOKIES = "cookies"
    EDGE = "edge"


class FindingStatus(str, Enum):
    """Lifecycle status of a finding."""

    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"


class AssessmentLabel(str, Enum):
    """Overall, human-facing assessment label for a completed scan."""

    PASS = "PASS"
    PASS_WITH_OBSERVATIONS = "PASS WITH OBSERVATIONS"
    REMEDIATION_REQUIRED = "REMEDIATION REQUIRED"
    HIGH_RISK = "HIGH RISK"
    ASSESSMENT_INCOMPLETE = "ASSESSMENT INCOMPLETE"


class ResultKind(str, Enum):
    """Distinguishes what kind of statement a report row makes."""

    PASS = "pass"
    OBSERVATION = "observation"
    FINDING = "finding"
    NOT_TESTED = "not_tested"
    ERROR = "error"


class ChangeType(str, Enum):
    """Classification used by baseline drift comparison."""

    NEW = "new"
    UNCHANGED = "unchanged"
    RESOLVED = "resolved"
    CHANGED = "changed"
