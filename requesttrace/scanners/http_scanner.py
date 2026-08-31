"""Safe, bounded HTTP/HTTPS request collector (RT-019).

Issues one safe GET per hop (never following redirects automatically, so
every hop becomes its own piece of evidence), and separately probes plain-HTTP
behavior so an HTTP->HTTPS redirect posture check never depends on how the
user happened to specify the target's scheme.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import requests
from requests.exceptions import RequestException

from requesttrace.analyzers.cookie_analyzer import analyze_set_cookie_headers
from requesttrace.analyzers.header_analyzer import analyze_security_headers
from requesttrace.analyzers.redirect_analyzer import analyze_redirect_chain
from requesttrace.config import ScanConfig
from requesttrace.evidence.redaction import redact_headers
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName, ModuleStatus
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.target import Target
from requesttrace.util.timing import Stopwatch

MAX_RESPONSE_BYTES_SAMPLED = 4096


@dataclass
class HttpHop:
    """One request/response pair in a redirect chain."""

    url: str
    status_code: int
    headers: dict[str, str]
    location: str | None
    ttfb_ms: float
    total_ms: float
    http_version: str
    content_type: str | None
    raw_set_cookie_headers: list[str]


class HttpAssessmentScanner:
    """Collects the primary request chain and a separate HTTP->HTTPS probe."""

    module = ModuleName.HTTP

    def run(self, target: Target, config: ScanConfig, store: EvidenceStore) -> ModuleResult:
        stopwatch = Stopwatch()
        observation_ids: list[str] = []
        errors: list[str] = []

        with stopwatch:
            hops, chain_error, loop_detected = self._follow_redirect_chain(target, config)
            if chain_error:
                errors.append(chain_error)

            if hops:
                observation_ids += analyze_redirect_chain(hops, target, store, loop_detected=loop_detected)
                observation_ids += self._record_final_response(hops[-1], store)
                observation_ids += analyze_security_headers(redact_headers(hops[-1].headers), store)
                observation_ids += analyze_set_cookie_headers(hops[-1].raw_set_cookie_headers, store)

            if target.scheme == "https":
                observation_ids += self._probe_http_to_https_redirect(target, config, store, errors)

        status = _derive_status(hops, errors)
        return ModuleResult(
            module=self.module,
            status=status,
            duration_ms=stopwatch.elapsed_ms,
            observation_ids=observation_ids,
            errors=errors,
        )

    def _follow_redirect_chain(self, target: Target, config: ScanConfig) -> tuple[list[HttpHop], str | None, bool]:
        hops: list[HttpHop] = []
        visited: set[str] = set()
        current_url = target.normalized_url
        headers = {"User-Agent": config.user_agent}

        for _ in range(config.max_redirects + 1):
            if current_url in visited:
                return hops, f"Redirect loop detected at {current_url}.", True
            visited.add(current_url)

            try:
                hop, next_url = _perform_single_request(current_url, headers, config.timeout_seconds)
            except RequestException as exc:
                return hops, f"HTTP request to {current_url} failed: {exc}", False

            hops.append(hop)
            if next_url is None:
                return hops, None, False
            current_url = next_url

        return hops, f"Exceeded max-redirects ({config.max_redirects}).", False

    def _record_final_response(self, final_hop: HttpHop, store: EvidenceStore) -> list[str]:
        ids: list[str] = []
        redacted_headers = redact_headers(final_hop.headers)
        for observation_type, value in (
            ("final_url", final_hop.url),
            ("status_code", final_hop.status_code),
            ("http_version", final_hop.http_version),
            ("content_type", final_hop.content_type),
            ("ttfb_ms", round(final_hop.ttfb_ms, 2)),
            ("total_duration_ms", round(final_hop.total_ms, 2)),
            ("response_headers", redacted_headers),
        ):
            observation, evidence = store.record_observation_with_evidence(
                self.module,
                observation_type,
                value,
                source_method="requests.Session.get",
                sanitized_raw={"value": value},
            )
            ids += [observation.observation_id, evidence.evidence_id]
        return ids

    def _probe_http_to_https_redirect(
        self,
        target: Target,
        config: ScanConfig,
        store: EvidenceStore,
        errors: list[str],
    ) -> list[str]:
        plain_http_url = f"http://{target.host}{target.path}"
        if target.query:
            plain_http_url += f"?{target.query}"
        headers = {"User-Agent": config.user_agent}

        try:
            hop, next_url = _perform_single_request(plain_http_url, headers, config.timeout_seconds)
        except RequestException as exc:
            errors.append(f"HTTP->HTTPS probe to {plain_http_url} failed: {exc}")
            return []

        redirects_to_https = bool(next_url and urlsplit(next_url).scheme == "https")
        observation, evidence = store.record_observation_with_evidence(
            self.module,
            "http_to_https_redirect",
            {
                "probed_url": plain_http_url,
                "status_code": hop.status_code,
                "location": hop.location,
                "redirects_to_https": redirects_to_https,
            },
            source_method="requests (plain-HTTP probe, allow_redirects=False)",
            sanitized_raw={"probed_url": plain_http_url, "location": hop.location},
        )
        return [observation.observation_id, evidence.evidence_id]


def _perform_single_request(url: str, headers: dict[str, str], timeout_seconds: float) -> tuple[HttpHop, str | None]:
    stopwatch = Stopwatch()
    with stopwatch:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout_seconds,
            allow_redirects=False,
            stream=True,
        )
        ttfb_ms = response.elapsed.total_seconds() * 1000
        # Bound body reads; RequestTrace never persists full response bodies.
        next(response.iter_content(MAX_RESPONSE_BYTES_SAMPLED), b"")
        response.close()

    http_version = {11: "HTTP/1.1", 10: "HTTP/1.0"}.get(getattr(response.raw, "version", 11), "HTTP/1.1")
    raw_set_cookie_headers = list(response.raw.headers.getlist("Set-Cookie")) if response.raw else []
    hop = HttpHop(
        url=url,
        status_code=response.status_code,
        headers=dict(response.headers),
        location=response.headers.get("Location"),
        ttfb_ms=ttfb_ms,
        total_ms=stopwatch.elapsed_ms,
        http_version=http_version,
        content_type=response.headers.get("Content-Type"),
        raw_set_cookie_headers=raw_set_cookie_headers,
    )

    next_url = None
    if response.is_redirect and hop.location:
        next_url = requests.compat.urljoin(url, hop.location)

    return hop, next_url


def _derive_status(hops: list[HttpHop], errors: list[str]) -> ModuleStatus:
    if hops and not errors:
        return ModuleStatus.COMPLETED
    if hops and errors:
        return ModuleStatus.PARTIAL
    return ModuleStatus.ERROR
