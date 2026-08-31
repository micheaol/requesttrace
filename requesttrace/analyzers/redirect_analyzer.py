"""Redirect-chain analysis: hop capture, loop detection, HTTPS->HTTP downgrade (RT-020)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName
from requesttrace.models.target import Target

if TYPE_CHECKING:
    from requesttrace.scanners.http_scanner import HttpHop

MODULE = ModuleName.REDIRECTS


def analyze_redirect_chain(
    hops: list[HttpHop], target: Target, store: EvidenceStore, *, loop_detected: bool = False
) -> list[str]:
    """Summarize every hop and flag loops / HTTPS->HTTP downgrades as evidence.

    ``loop_detected`` is supplied by the caller (the scanner that actually
    followed the chain) because a loop is only visible at the moment the
    *next* hop would revisit an already-seen URL — by the time hops are
    collected here, that revisited URL was never appended, so it can't be
    reliably re-derived from duplicates within ``hops`` alone.
    """
    chain_summary = [
        {
            "url": hop.url,
            "status_code": hop.status_code,
            "location": hop.location,
            "scheme": urlsplit(hop.url).scheme,
        }
        for hop in hops
    ]

    loop_detected = loop_detected or len({entry["url"] for entry in chain_summary}) < len(chain_summary)
    downgrade_detected = _detect_https_to_http_downgrade(chain_summary)

    ids: list[str] = []
    observation, evidence = store.record_observation_with_evidence(
        MODULE,
        "redirect_chain",
        chain_summary,
        source_method="redirect_analyzer.analyze_redirect_chain",
        metadata={"hop_count": len(hops)},
        sanitized_raw={"chain": chain_summary},
    )
    ids += [observation.observation_id, evidence.evidence_id]

    for observation_type, value in (
        ("redirect_loop_detected", loop_detected),
        ("https_to_http_downgrade_detected", downgrade_detected),
    ):
        observation, evidence = store.record_observation_with_evidence(
            MODULE,
            observation_type,
            value,
            source_method="redirect_analyzer.analyze_redirect_chain",
            sanitized_raw={"value": value},
        )
        ids += [observation.observation_id, evidence.evidence_id]

    return ids


def _detect_https_to_http_downgrade(chain_summary: list[dict]) -> bool:
    """True if any hop uses http after an earlier hop used https."""
    seen_https = False
    for entry in chain_summary:
        if entry["scheme"] == "https":
            seen_https = True
        elif entry["scheme"] == "http" and seen_https:
            return True
    return False
