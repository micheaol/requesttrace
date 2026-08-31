"""Cookie attribute analysis (RT-022).

Cookie *values* are never parsed into anything that reaches the evidence
store — only the name and security-relevant attributes (Secure, HttpOnly,
SameSite) are recorded, so a session token can never leak into a report.
"""

from __future__ import annotations

from dataclasses import dataclass

from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName

MODULE = ModuleName.COOKIES


@dataclass(frozen=True, slots=True)
class CookieAttributes:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None


def analyze_set_cookie_headers(raw_set_cookie_headers: list[str], store: EvidenceStore) -> list[str]:
    """Parse each Set-Cookie header and record redacted, attribute-only evidence."""
    parsed_headers = [_parse_single_cookie_header(header) for header in raw_set_cookie_headers]
    cookies: list[CookieAttributes] = [c for c in parsed_headers if c is not None]

    if not cookies:
        observation = store.record_observation(MODULE, "cookies_present", False)
        return [observation.observation_id]

    ids: list[str] = []
    for cookie in cookies:
        value = {
            "name": cookie.name,
            "secure": cookie.secure,
            "http_only": cookie.http_only,
            "same_site": cookie.same_site,
        }
        observation, evidence = store.record_observation_with_evidence(
            MODULE,
            "cookie",
            value,
            source_method="cookie_analyzer.analyze_set_cookie_headers",
            sanitized_raw={"value": value},
        )
        ids += [observation.observation_id, evidence.evidence_id]

    return ids


def _parse_single_cookie_header(raw_header: str) -> CookieAttributes | None:
    segments = [segment.strip() for segment in raw_header.split(";") if segment.strip()]
    if not segments:
        return None

    name_value = segments[0]
    if "=" not in name_value:
        return None
    name = name_value.split("=", 1)[0].strip()

    attributes: dict[str, str | bool] = {}
    for segment in segments[1:]:
        if "=" in segment:
            key, value = segment.split("=", 1)
            attributes[key.strip().lower()] = value.strip()
        else:
            attributes[segment.strip().lower()] = True

    same_site_raw = attributes.get("samesite")
    return CookieAttributes(
        name=name,
        secure=bool(attributes.get("secure")),
        http_only=bool(attributes.get("httponly")),
        same_site=same_site_raw if isinstance(same_site_raw, str) else None,
    )
