"""Assessment label and severity-summary derivation (RT-028).

A high-severity finding must never be hidden behind a "PASS" label, and a
scan that could not complete a critical module must never be reported as a
clean PASS just because no findings happened to fire.
"""

from __future__ import annotations

from collections import Counter

from requesttrace.models.enums import AssessmentLabel, ModuleName, ModuleStatus, Severity
from requesttrace.models.finding import Finding
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.target import Target

_CRITICAL_MODULES_FOR_SCHEME = {
    "https": {ModuleName.TLS, ModuleName.HTTP},
    "http": {ModuleName.HTTP},
}


def compute_severity_summary(findings: list[Finding]) -> dict[Severity, int]:
    counts = Counter(finding.severity for finding in findings)
    return {severity: counts.get(severity, 0) for severity in Severity}


def derive_assessment_label(
    findings: list[Finding], module_results: list[ModuleResult], target: Target
) -> AssessmentLabel:
    """Combine finding severity with module completeness into one overall label."""
    tentative_label = _label_from_severity(findings)

    if _critical_modules_incomplete(module_results, target):
        if tentative_label in (AssessmentLabel.PASS, AssessmentLabel.PASS_WITH_OBSERVATIONS):
            return AssessmentLabel.ASSESSMENT_INCOMPLETE
        # A real finding already fired on incomplete evidence elsewhere in the
        # scan; surface that risk rather than masking it as "incomplete".
        return tentative_label

    return tentative_label


def _label_from_severity(findings: list[Finding]) -> AssessmentLabel:
    severities = {finding.severity for finding in findings}
    if Severity.CRITICAL in severities:
        return AssessmentLabel.HIGH_RISK
    if Severity.HIGH in severities:
        return AssessmentLabel.REMEDIATION_REQUIRED
    if severities:
        return AssessmentLabel.PASS_WITH_OBSERVATIONS
    return AssessmentLabel.PASS


def _critical_modules_incomplete(module_results: list[ModuleResult], target: Target) -> bool:
    required = _CRITICAL_MODULES_FOR_SCHEME.get(target.scheme, {ModuleName.HTTP})
    results_by_module = {result.module: result for result in module_results}
    for module in required:
        result = results_by_module.get(module)
        if result is None or result.status == ModuleStatus.ERROR:
            return True
    return False
