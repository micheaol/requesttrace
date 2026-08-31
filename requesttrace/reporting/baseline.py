"""Baseline comparison / drift detection (RT-035).

Loads a previously produced JSON report and classifies each current finding
as new, unchanged, changed or (candidate) resolved relative to it. A finding
is only ever classified as resolved when the current scan's relevant
module(s) actually completed — an incomplete scan can never be used to claim
remediation, since a baseline must never suppress current risk.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from requesttrace.exit_codes import InvalidInputError
from requesttrace.models.enums import ChangeType, ModuleName, ModuleStatus
from requesttrace.models.scan import Scan

_RULE_PREFIX_TO_MODULES: dict[str, list[ModuleName]] = {
    "RT-TLS": [ModuleName.TLS],
    "RT-HTTP": [ModuleName.HTTP, ModuleName.REDIRECTS],
    "RT-HDR": [ModuleName.HEADERS],
    "RT-COOKIE": [ModuleName.COOKIES],
    "RT-DNS": [ModuleName.DNS],
}


@dataclass(frozen=True, slots=True)
class BaselineDiffEntry:
    rule_id: str
    title: str
    affected_asset: str
    change_type: ChangeType
    current_severity: str | None
    previous_severity: str | None


def load_baseline_report(baseline_path: Path) -> dict[str, Any]:
    if not baseline_path.is_file():
        raise InvalidInputError(f"Baseline file not found: {baseline_path}")
    try:
        return json.loads(baseline_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidInputError(f"Baseline file is not valid JSON: {baseline_path} ({exc})") from exc


def compare_to_baseline(current_scan: Scan, baseline_report: dict[str, Any]) -> list[BaselineDiffEntry]:
    """Classify every current and baseline finding into new/unchanged/changed/resolved."""
    current_by_key = {(f.rule_id, f.affected_asset): f for f in current_scan.findings}
    baseline_by_key = {(f["rule_id"], f["affected_asset"]): f for f in baseline_report.get("findings", [])}

    entries: list[BaselineDiffEntry] = []

    for key, finding in current_by_key.items():
        rule_id, affected_asset = key
        if key not in baseline_by_key:
            entries.append(
                BaselineDiffEntry(
                    rule_id,
                    finding.title,
                    affected_asset,
                    ChangeType.NEW,
                    finding.severity.value,
                    None,
                )
            )
            continue

        previous_severity = baseline_by_key[key]["severity"]
        change_type = ChangeType.UNCHANGED if previous_severity == finding.severity.value else ChangeType.CHANGED
        entries.append(
            BaselineDiffEntry(
                rule_id,
                finding.title,
                affected_asset,
                change_type,
                finding.severity.value,
                previous_severity,
            )
        )

    for key, baseline_finding in baseline_by_key.items():
        if key in current_by_key:
            continue
        rule_id, affected_asset = key
        if _relevant_modules_completed(current_scan, rule_id):
            change_type = ChangeType.RESOLVED
        else:
            change_type = ChangeType.UNCHANGED  # cannot verify remediation; do not overclaim
        entries.append(
            BaselineDiffEntry(
                rule_id,
                baseline_finding.get("title", rule_id),
                affected_asset,
                change_type,
                None,
                baseline_finding["severity"],
            )
        )

    return entries


def _relevant_modules_completed(scan: Scan, rule_id: str) -> bool:
    prefix = next((p for p in _RULE_PREFIX_TO_MODULES if rule_id.startswith(p)), None)
    if prefix is None:
        return True
    required_modules = _RULE_PREFIX_TO_MODULES[prefix]
    results_by_module = {r.module: r for r in scan.module_results}
    return all(
        results_by_module.get(module) is not None and results_by_module[module].status != ModuleStatus.ERROR
        for module in required_modules
    )


def summarize_baseline_diff(entries: list[BaselineDiffEntry]) -> dict[str, int]:
    summary = {change_type.value: 0 for change_type in ChangeType}
    for entry in entries:
        summary[entry.change_type.value] += 1
    return summary
