"""Security-header assessment (RT-021): HSTS, CSP, XCTO, Referrer-Policy, frame
protection and Permissions-Policy. Header lookups are case-insensitive.
"""

from __future__ import annotations

import re

from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName

MODULE = ModuleName.HEADERS

_CSP_HIGH_RISK_PATTERNS = ("unsafe-inline", "unsafe-eval", "*")


def analyze_security_headers(response_headers: dict[str, str], store: EvidenceStore) -> list[str]:
    """Assess the response header set and record one observation per control."""
    lookup = _CaseInsensitiveLookup(response_headers)

    ids: list[str] = []
    ids += _record(store, "hsts", _assess_hsts(lookup))
    ids += _record(store, "content_security_policy", _assess_csp(lookup))
    ids += _record(store, "x_content_type_options", _assess_x_content_type_options(lookup))
    ids += _record(store, "referrer_policy", _assess_referrer_policy(lookup))
    ids += _record(store, "frame_protection", _assess_frame_protection(lookup))
    ids += _record(store, "permissions_policy", _assess_permissions_policy(lookup))
    return ids


class _CaseInsensitiveLookup:
    def __init__(self, headers: dict[str, str]) -> None:
        self._headers = {name.lower(): value for name, value in headers.items()}

    def get(self, name: str) -> str | None:
        return self._headers.get(name.lower())


def _record(store: EvidenceStore, observation_type: str, value: dict) -> list[str]:
    observation, evidence = store.record_observation_with_evidence(
        MODULE,
        observation_type,
        value,
        source_method="header_analyzer.analyze_security_headers",
        sanitized_raw={"value": value},
    )
    return [observation.observation_id, evidence.evidence_id]


def _assess_hsts(lookup: _CaseInsensitiveLookup) -> dict:
    raw = lookup.get("strict-transport-security")
    if raw is None:
        return {
            "present": False,
            "raw": None,
            "max_age": None,
            "include_subdomains": False,
            "preload": False,
        }

    max_age_match = re.search(r"max-age\s*=\s*(\d+)", raw, re.IGNORECASE)
    return {
        "present": True,
        "raw": raw,
        "max_age": int(max_age_match.group(1)) if max_age_match else None,
        "include_subdomains": "includesubdomains" in raw.lower(),
        "preload": "preload" in raw.lower(),
    }


def _assess_csp(lookup: _CaseInsensitiveLookup) -> dict:
    raw = lookup.get("content-security-policy")
    if raw is None:
        return {"present": False, "raw": None, "high_risk_patterns": []}

    found_patterns = [pattern for pattern in _CSP_HIGH_RISK_PATTERNS if pattern in raw]
    return {"present": True, "raw": raw, "high_risk_patterns": found_patterns}


def _assess_x_content_type_options(lookup: _CaseInsensitiveLookup) -> dict:
    raw = lookup.get("x-content-type-options")
    return {
        "present": raw is not None,
        "value": raw,
        "valid_nosniff": raw is not None and raw.strip().lower() == "nosniff",
    }


def _assess_referrer_policy(lookup: _CaseInsensitiveLookup) -> dict:
    raw = lookup.get("referrer-policy")
    return {"present": raw is not None, "value": raw}


def _assess_frame_protection(lookup: _CaseInsensitiveLookup) -> dict:
    csp = lookup.get("content-security-policy") or ""
    frame_ancestors_present = "frame-ancestors" in csp.lower()
    x_frame_options = lookup.get("x-frame-options")
    return {
        "csp_frame_ancestors_present": frame_ancestors_present,
        "x_frame_options_present": x_frame_options is not None,
        "x_frame_options_value": x_frame_options,
        "protected": frame_ancestors_present or x_frame_options is not None,
    }


def _assess_permissions_policy(lookup: _CaseInsensitiveLookup) -> dict:
    raw = lookup.get("permissions-policy")
    return {"present": raw is not None, "value": raw}
