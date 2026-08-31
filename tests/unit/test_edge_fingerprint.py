"""Edge/CDN fingerprint tests (RT-023): confidence-scored, never asserted as fact."""

from __future__ import annotations

from requesttrace.analyzers.edge_fingerprint import EdgeEvidenceBundle, analyze_edge_indicators
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName


def test_cloudflare_header_yields_high_confidence_match() -> None:
    store = EvidenceStore()
    bundle = EdgeEvidenceBundle(cname_chain=[], response_headers={"CF-RAY": "abc123-AMS"}, certificate_issuer=None)
    analyze_edge_indicators(bundle, store)

    result = store.observations_of_type(ModuleName.EDGE, "edge_provider_indicators")[-1].value
    assert result["unknown"] is False
    assert result["matches"][0]["provider"] == "Cloudflare"
    assert result["matches"][0]["confidence"] == "high"
    assert "consistent with" in result["matches"][0]["statement"]


def test_unmatched_target_is_a_valid_unknown_result() -> None:
    store = EvidenceStore()
    bundle = EdgeEvidenceBundle(cname_chain=[], response_headers={}, certificate_issuer=None)
    analyze_edge_indicators(bundle, store)

    result = store.observations_of_type(ModuleName.EDGE, "edge_provider_indicators")[-1].value
    assert result["unknown"] is True
    assert result["matches"] == []


def test_cname_only_match_is_medium_confidence_not_high() -> None:
    store = EvidenceStore()
    bundle = EdgeEvidenceBundle(cname_chain=["app.cloudfront.net"], response_headers={}, certificate_issuer=None)
    analyze_edge_indicators(bundle, store)

    result = store.observations_of_type(ModuleName.EDGE, "edge_provider_indicators")[-1].value
    assert result["matches"][0]["provider"] == "Amazon CloudFront"
    assert result["matches"][0]["confidence"] == "medium"


def test_never_invents_a_private_service_name() -> None:
    store = EvidenceStore()
    bundle = EdgeEvidenceBundle(
        cname_chain=["internal-db.corp.local"],
        response_headers={"Server": "MyCustomApp/1.0"},
        certificate_issuer=None,
    )
    analyze_edge_indicators(bundle, store)
    result = store.observations_of_type(ModuleName.EDGE, "edge_provider_indicators")[-1].value
    assert result["unknown"] is True
