"""TLS scanner integration tests against a local, controlled TLS fixture server.

Covers valid, expired, and hostname-mismatch certificate scenarios plus
protocol-support probing — all without any live internet dependency
(PRD §19 / RT-011 / RT-036).
"""

from __future__ import annotations

import datetime as dt
import ssl
from dataclasses import replace

from requesttrace.config import ScanConfig
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName, ModuleStatus
from requesttrace.scanners.tls_scanner import TlsSecurityScanner
from requesttrace.target import normalize_target
from tests.fixtures.local_tls_server import LocalTlsHttpServer, generate_self_signed_certificate


def _scan_local_server(server: LocalTlsHttpServer, config: ScanConfig):
    target = normalize_target(f"https://{server.host}:{server.port}/")
    store = EvidenceStore()
    result = TlsSecurityScanner().run(target, config, store)
    return result, store


def test_valid_certificate_reports_hostname_match_and_self_signed_chain(
    fast_scan_config: ScanConfig,
) -> None:
    certificate = generate_self_signed_certificate(common_name="127.0.0.1", subject_alternative_names=["127.0.0.1"])
    with LocalTlsHttpServer(certificate) as server:
        result, store = _scan_local_server(server, fast_scan_config)

    assert result.status in (ModuleStatus.COMPLETED, ModuleStatus.PARTIAL)

    hostname_match = store.observations_of_type(ModuleName.TLS, "hostname_match")[-1].value
    assert hostname_match["matches"] is True

    # Self-signed fixture certs are never in a trust store, so this must fail closed.
    trust_valid = store.observations_of_type(ModuleName.TLS, "trust_chain_valid")[-1]
    assert trust_valid.value is False
    assert trust_valid.metadata["failure_category"] == "self_signed"


def test_hostname_mismatch_is_detected_independently_of_trust(fast_scan_config: ScanConfig) -> None:
    certificate = generate_self_signed_certificate(
        common_name="not-the-right-host.example",
        subject_alternative_names=["not-the-right-host.example"],
    )
    with LocalTlsHttpServer(certificate) as server:
        result, store = _scan_local_server(server, fast_scan_config)

    assert result.status in (ModuleStatus.COMPLETED, ModuleStatus.PARTIAL)
    hostname_match = store.observations_of_type(ModuleName.TLS, "hostname_match")[-1].value
    assert hostname_match["matches"] is False
    assert hostname_match["matched_name"] is None


def test_expired_certificate_is_detected_from_certificate_dates(
    fast_scan_config: ScanConfig,
) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    certificate = generate_self_signed_certificate(
        common_name="127.0.0.1",
        subject_alternative_names=["127.0.0.1"],
        not_valid_before=now - dt.timedelta(days=30),
        not_valid_after=now - dt.timedelta(days=1),
    )
    with LocalTlsHttpServer(certificate) as server:
        _result, store = _scan_local_server(server, fast_scan_config)

    cert_observation = store.observations_of_type(ModuleName.TLS, "certificate")[-1].value
    assert cert_observation["days_remaining"] < 0


def test_not_yet_valid_certificate_is_detected(fast_scan_config: ScanConfig) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    certificate = generate_self_signed_certificate(
        common_name="127.0.0.1",
        subject_alternative_names=["127.0.0.1"],
        not_valid_before=now + dt.timedelta(days=10),
        not_valid_after=now + dt.timedelta(days=400),
    )
    with LocalTlsHttpServer(certificate) as server:
        _result, store = _scan_local_server(server, fast_scan_config)

    cert_observation = store.observations_of_type(ModuleName.TLS, "certificate")[-1].value
    not_valid_before = dt.datetime.fromisoformat(cert_observation["not_valid_before"])
    assert not_valid_before > now


def test_protocol_probing_reflects_server_restricted_to_tls12(fast_scan_config: ScanConfig) -> None:
    certificate = generate_self_signed_certificate(common_name="127.0.0.1", subject_alternative_names=["127.0.0.1"])
    with LocalTlsHttpServer(
        certificate,
        minimum_version=ssl.TLSVersion.TLSv1_2,
        maximum_version=ssl.TLSVersion.TLSv1_2,
    ) as server:
        _result, store = _scan_local_server(server, fast_scan_config)

    protocol_support = store.observations_of_type(ModuleName.TLS, "protocol_support")[-1].value
    assert protocol_support["TLS 1.2"]["supported"] is True
    assert protocol_support["TLS 1.3"]["tested"] is True
    assert protocol_support["TLS 1.3"]["supported"] is False


def test_http_scheme_target_skips_tls_module(fast_scan_config: ScanConfig) -> None:
    target = normalize_target("http://127.0.0.1:9/")
    store = EvidenceStore()
    result = TlsSecurityScanner().run(target, fast_scan_config, store)
    assert result.status == ModuleStatus.SKIPPED


def test_unreachable_host_produces_error_status_not_a_crash(fast_scan_config: ScanConfig) -> None:
    target = normalize_target("https://127.0.0.1:1/")
    config = replace(fast_scan_config, timeout_seconds=1.0)
    store = EvidenceStore()
    result = TlsSecurityScanner().run(target, config, store)
    assert result.status == ModuleStatus.ERROR
    assert result.errors
