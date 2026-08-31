"""CDN / reverse-proxy / edge indicator engine (RT-023).

Fingerprints are independently maintainable: each entry in ``FINGERPRINTS``
is a self-contained matcher over already-collected DNS/header/TLS evidence.
Matches are always phrased as "indicators are consistent with" — this module
must never assert a provider as observed fact, and an unmatched target is a
perfectly valid ("unknown") result, not an error.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import Confidence, ModuleName

MODULE = ModuleName.EDGE


@dataclass(frozen=True, slots=True)
class EdgeEvidenceBundle:
    """The cross-module signals available to edge fingerprinting."""

    cname_chain: list[str]
    response_headers: dict[str, str]
    certificate_issuer: str | None


EdgeMatcher = Callable[["EdgeEvidenceBundle"], list[str]]


@dataclass(frozen=True, slots=True)
class EdgeFingerprint:
    provider: str
    confidence: Confidence
    matcher: EdgeMatcher


def _cname_contains(*substrings: str):
    def matcher(bundle: EdgeEvidenceBundle) -> list[str]:
        indicators = []
        for entry in bundle.cname_chain:
            lowered = entry.lower()
            for substring in substrings:
                if substring in lowered:
                    indicators.append(f"CNAME chain includes '{entry}' (matches '{substring}')")
        return indicators

    return matcher


def _header_contains(header_name: str, *substrings: str):
    def matcher(bundle: EdgeEvidenceBundle) -> list[str]:
        value = _get_header(bundle.response_headers, header_name)
        if value is None:
            return []
        lowered = value.lower()
        if not substrings or any(s in lowered for s in substrings):
            return [f"Response header '{header_name}: {value}'"]
        return []

    return matcher


def _header_present(header_name: str):
    def matcher(bundle: EdgeEvidenceBundle) -> list[str]:
        value = _get_header(bundle.response_headers, header_name)
        return [f"Response header '{header_name}' present"] if value is not None else []

    return matcher


def _issuer_contains(*substrings: str):
    def matcher(bundle: EdgeEvidenceBundle) -> list[str]:
        if not bundle.certificate_issuer:
            return []
        lowered = bundle.certificate_issuer.lower()
        return [f"Certificate issuer '{bundle.certificate_issuer}'"] if any(s in lowered for s in substrings) else []

    return matcher


def _any_of(*matchers):
    def combined(bundle: EdgeEvidenceBundle) -> list[str]:
        indicators: list[str] = []
        for matcher in matchers:
            indicators += matcher(bundle)
        return indicators

    return combined


def _get_header(headers: dict[str, str], name: str) -> str | None:
    lowered_name = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered_name:
            return value
    return None


# Header-based matches carry HIGH confidence (direct server signal); CNAME-only
# matches carry MEDIUM confidence (DNS delegation is a strong but indirect signal).
FINGERPRINTS: list[EdgeFingerprint] = [
    EdgeFingerprint(
        "Cloudflare",
        Confidence.HIGH,
        _any_of(_header_present("CF-RAY"), _header_contains("Server", "cloudflare")),
    ),
    EdgeFingerprint("Cloudflare", Confidence.MEDIUM, _cname_contains("cloudflare.com", "cdn.cloudflare.net")),
    EdgeFingerprint(
        "Akamai",
        Confidence.HIGH,
        _any_of(_header_contains("Server", "akamaighost"), _header_present("X-Akamai-Transformed")),
    ),
    EdgeFingerprint(
        "Akamai",
        Confidence.MEDIUM,
        _cname_contains("akamai", "akamaiedge.net", "akamaitechnologies.com"),
    ),
    EdgeFingerprint("Fastly", Confidence.HIGH, _header_present("X-Fastly-Request-ID")),
    EdgeFingerprint("Fastly", Confidence.MEDIUM, _cname_contains("fastly.net", "fastlylb.net")),
    EdgeFingerprint(
        "Amazon CloudFront",
        Confidence.HIGH,
        _any_of(_header_present("X-Amz-Cf-Id"), _header_contains("Via", "cloudfront")),
    ),
    EdgeFingerprint("Amazon CloudFront", Confidence.MEDIUM, _cname_contains("cloudfront.net")),
    EdgeFingerprint(
        "Google Front End / Cloud CDN",
        Confidence.HIGH,
        _any_of(_header_contains("Server", "gws"), _header_contains("Via", "google")),
    ),
    EdgeFingerprint(
        "Google Cloud CDN",
        Confidence.MEDIUM,
        _cname_contains("googleusercontent.com", "ghs.google.com"),
    ),
    EdgeFingerprint("Microsoft Azure Front Door / CDN", Confidence.HIGH, _header_present("X-Azure-Ref")),
    EdgeFingerprint(
        "Microsoft Azure Front Door / CDN",
        Confidence.MEDIUM,
        _cname_contains("azureedge.net", "azurefd.net", "trafficmanager.net"),
    ),
    EdgeFingerprint("Vercel", Confidence.HIGH, _header_present("x-vercel-id")),
    EdgeFingerprint("Vercel", Confidence.MEDIUM, _cname_contains("vercel-dns.com")),
    EdgeFingerprint(
        "Netlify",
        Confidence.HIGH,
        _any_of(_header_present("x-nf-request-id"), _header_contains("Server", "netlify")),
    ),
    EdgeFingerprint("Netlify", Confidence.MEDIUM, _cname_contains("netlify.app", "netlifyglobalcdn.com")),
    EdgeFingerprint("Cloudflare", Confidence.MEDIUM, _issuer_contains("cloudflare")),
]


def analyze_edge_indicators(bundle: EdgeEvidenceBundle, store: EvidenceStore) -> list[str]:
    """Match collected evidence against known fingerprints and record a confidence-scored result."""
    matches: dict[str, dict] = {}
    for fingerprint in FINGERPRINTS:
        indicators = fingerprint.matcher(bundle)
        if not indicators:
            continue
        matches.setdefault(
            fingerprint.provider,
            {
                "provider": fingerprint.provider,
                "confidence": fingerprint.confidence,
                "indicators": [],
            },
        )
        record = matches[fingerprint.provider]
        record["indicators"] += indicators
        if _confidence_rank(fingerprint.confidence) > _confidence_rank(record["confidence"]):
            record["confidence"] = fingerprint.confidence

    ranked = sorted(matches.values(), key=lambda m: _confidence_rank(m["confidence"]), reverse=True)

    result: dict[str, Any] = {
        "matches": [
            {
                "provider": m["provider"],
                "confidence": m["confidence"].value,
                "indicators": m["indicators"],
                "statement": f"Indicators are consistent with {m['provider']}.",
            }
            for m in ranked
        ],
        "unknown": len(ranked) == 0,
    }

    observation, evidence = store.record_observation_with_evidence(
        MODULE,
        "edge_provider_indicators",
        result,
        source_method="edge_fingerprint.analyze_edge_indicators",
        confidence=Confidence.HIGH if any(m["confidence"] == "high" for m in result["matches"]) else Confidence.MEDIUM,
        sanitized_raw={"result": result},
    )
    return [observation.observation_id, evidence.evidence_id]


def _confidence_rank(confidence: Confidence) -> int:
    return {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1, Confidence.UNKNOWN: 0}.get(confidence, 0)
