"""TLS rule tests (RT-014/016/017): triggering condition and the negative case."""

from __future__ import annotations

import datetime as dt

from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName
from requesttrace.models.target import Target
from requesttrace.rules import tls_rules
from requesttrace.rules.base import RuleContext


def _make_target() -> Target:
    return Target(
        raw_input="example.com",
        scheme="https",
        host="example.com",
        port=443,
        path="/",
        query="",
        normalized_url="https://example.com/",
        is_ip_literal=False,
    )


def _certificate_value(**overrides) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    base = {
        "subject": "CN=example.com",
        "issuer": "CN=Example CA",
        "subject_alternative_names": ["example.com"],
        "not_valid_before": (now - dt.timedelta(days=30)).isoformat(),
        "not_valid_after": (now + dt.timedelta(days=90)).isoformat(),
        "days_remaining": 90,
        "fingerprint_sha256": "a" * 64,
        "signature_algorithm": "sha256WithRSAEncryption",
        "public_key_algorithm": "RSA",
        "public_key_size_bits": 2048,
    }
    base.update(overrides)
    return base


def _context_with(store: EvidenceStore, fast_scan_config) -> RuleContext:
    return RuleContext(target=_make_target(), config=fast_scan_config, store=store)


def test_deprecated_protocol_enabled_triggers_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "protocol_support",
        {
            "TLS 1.0": {"tested": True, "supported": True, "reason": None},
            "TLS 1.1": {"tested": True, "supported": False, "reason": None},
            "TLS 1.2": {"tested": True, "supported": True, "reason": None},
            "TLS 1.3": {"tested": True, "supported": True, "reason": None},
        },
        source_method="test",
    )

    findings = tls_rules._evaluate_deprecated_protocols(_context_with(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].rule_id == "RT-TLS-001"
    assert "TLS 1.0" in findings[0].description


def test_no_deprecated_protocol_when_disabled(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "protocol_support",
        {
            "TLS 1.0": {"tested": True, "supported": False, "reason": None},
            "TLS 1.1": {"tested": True, "supported": False, "reason": None},
        },
        source_method="test",
    )
    findings = tls_rules._evaluate_deprecated_protocols(_context_with(store, fast_scan_config))
    assert findings == []


def test_hostname_mismatch_triggers_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "hostname_match",
        {"matches": False, "matched_name": None},
        source_method="test",
    )
    findings = tls_rules._evaluate_hostname_mismatch(_context_with(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].rule_id == "RT-TLS-002"
    assert findings[0].severity.value == "high"


def test_hostname_match_does_not_trigger_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "hostname_match",
        {"matches": True, "matched_name": "example.com"},
        source_method="test",
    )
    assert tls_rules._evaluate_hostname_mismatch(_context_with(store, fast_scan_config)) == []


def test_self_signed_trust_failure_is_high_severity(fast_scan_config) -> None:
    store = EvidenceStore()
    observation = store.record_observation(
        ModuleName.TLS, "trust_chain_valid", False, metadata={"failure_category": "self_signed"}
    )
    store.record_evidence(observation, source_method="test")
    findings = tls_rules._evaluate_trust_chain(_context_with(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert "self-signed" in findings[0].title


def test_trusted_chain_does_not_trigger_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(ModuleName.TLS, "trust_chain_valid", True, source_method="test")
    assert tls_rules._evaluate_trust_chain(_context_with(store, fast_scan_config)) == []


def test_expired_certificate_is_critical(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "certificate",
        _certificate_value(
            days_remaining=-5,
            not_valid_after=(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=5)).isoformat(),
        ),
        source_method="test",
    )
    findings = tls_rules._evaluate_certificate_expiry(_context_with(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert "expired" in findings[0].title


def test_certificate_expiring_within_critical_threshold(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS, "certificate", _certificate_value(days_remaining=3), source_method="test"
    )
    findings = tls_rules._evaluate_certificate_expiry(_context_with(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_certificate_expiring_within_warning_threshold_is_medium(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS, "certificate", _certificate_value(days_remaining=20), source_method="test"
    )
    findings = tls_rules._evaluate_certificate_expiry(_context_with(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"


def test_certificate_with_healthy_expiry_has_no_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS, "certificate", _certificate_value(days_remaining=180), source_method="test"
    )
    assert tls_rules._evaluate_certificate_expiry(_context_with(store, fast_scan_config)) == []


def test_weak_cipher_triggers_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "negotiated_cipher",
        {"name": "TLS_RSA_WITH_RC4_128_SHA", "protocol": "TLSv1.2", "bits": 128},
        source_method="test",
    )
    findings = tls_rules._evaluate_negotiated_cipher(_context_with(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].rule_id == "RT-TLS-006"


def test_strong_cipher_does_not_trigger_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "negotiated_cipher",
        {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256},
        source_method="test",
    )
    assert tls_rules._evaluate_negotiated_cipher(_context_with(store, fast_scan_config)) == []


def test_weak_rsa_key_size_triggers_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "certificate",
        _certificate_value(public_key_algorithm="RSA", public_key_size_bits=1024),
        source_method="test",
    )
    findings = tls_rules._evaluate_public_key_strength(_context_with(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_adequate_rsa_key_size_has_no_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "certificate",
        _certificate_value(public_key_algorithm="RSA", public_key_size_bits=2048),
        source_method="test",
    )
    assert tls_rules._evaluate_public_key_strength(_context_with(store, fast_scan_config)) == []


def test_sha1_signature_algorithm_is_medium(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "certificate",
        _certificate_value(signature_algorithm="sha1WithRSAEncryption"),
        source_method="test",
    )
    findings = tls_rules._evaluate_signature_algorithm(_context_with(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"


def test_missing_forward_secrecy_on_tls12_triggers_finding(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation(ModuleName.TLS, "negotiated_protocol", "TLSv1.2")
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "negotiated_cipher",
        {"name": "TLS_RSA_WITH_AES_256_GCM_SHA384", "protocol": "TLSv1.2", "bits": 256},
        source_method="test",
    )
    findings = tls_rules._evaluate_forward_secrecy(_context_with(store, fast_scan_config))
    assert len(findings) == 1
    assert findings[0].rule_id == "RT-TLS-009"


def test_tls13_is_exempt_from_forward_secrecy_check(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation(ModuleName.TLS, "negotiated_protocol", "TLSv1.3")
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "negotiated_cipher",
        {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256},
        source_method="test",
    )
    assert tls_rules._evaluate_forward_secrecy(_context_with(store, fast_scan_config)) == []


def test_ecdhe_cipher_provides_forward_secrecy(fast_scan_config) -> None:
    store = EvidenceStore()
    store.record_observation(ModuleName.TLS, "negotiated_protocol", "TLSv1.2")
    store.record_observation_with_evidence(
        ModuleName.TLS,
        "negotiated_cipher",
        {"name": "ECDHE-RSA-AES256-GCM-SHA384", "protocol": "TLSv1.2", "bits": 256},
        source_method="test",
    )
    assert tls_rules._evaluate_forward_secrecy(_context_with(store, fast_scan_config)) == []
