"""DNS scanner tests (RT-007/008) using mocked dnspython responses.

Mocked rather than hitting live DNS so CI stays deterministic and does not
depend on uncontrolled public domains (PRD §19 / RT-011).
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import patch

import dns.exception
import dns.resolver

from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName, ModuleStatus
from requesttrace.scanners.dns_scanner import DnsResolutionScanner
from requesttrace.target import normalize_target


@dataclass
class _FakeAddressRecord:
    address: str


@dataclass
class _FakeTargetRecord:
    target: object  # anything whose str() gives the hostname, e.g. plain str


def _run_scanner(fast_scan_config, resolve_side_effect) -> tuple:
    target = normalize_target("https://example.com/")
    store = EvidenceStore()
    with patch.object(dns.resolver.Resolver, "resolve", side_effect=resolve_side_effect):
        result = DnsResolutionScanner().run(target, fast_scan_config, store)
    return result, store


def test_successful_resolution_emits_evidence(fast_scan_config) -> None:
    def side_effect(host, record_type, lifetime=None):
        if record_type == "A":
            return [_FakeAddressRecord("93.184.216.34")]
        if record_type == "AAAA":
            return [_FakeAddressRecord("2606:2800:220:1:248:1893:25c8:1946")]
        if record_type == "CNAME":
            raise dns.resolver.NoAnswer()
        if record_type == "NS":
            return [_FakeTargetRecord("a.iana-servers.net"), _FakeTargetRecord("b.iana-servers.net")]
        raise AssertionError(f"unexpected record type {record_type}")

    result, store = _run_scanner(fast_scan_config, side_effect)

    assert result.status == ModuleStatus.COMPLETED
    a_records = store.observations_of_type(ModuleName.DNS, "a_records")[-1].value
    assert a_records == ["93.184.216.34"]
    aaaa_records = store.observations_of_type(ModuleName.DNS, "aaaa_records")[-1].value
    assert aaaa_records == ["2606:2800:220:1:248:1893:25c8:1946"]
    ns_records = store.observations_of_type(ModuleName.DNS, "ns_records")[-1].value
    assert ns_records == ["a.iana-servers.net", "b.iana-servers.net"]

    for evidence in store.evidence:
        assert evidence.module == ModuleName.DNS


def test_nxdomain_produces_error_status_without_fabricated_findings(fast_scan_config) -> None:
    def side_effect(host, record_type, lifetime=None):
        raise dns.resolver.NXDOMAIN()

    result, store = _run_scanner(fast_scan_config, side_effect)

    assert result.status == ModuleStatus.ERROR
    assert any("NXDOMAIN" in e for e in result.errors)
    assert store.observations_of_type(ModuleName.DNS, "a_records") == []


def test_no_answer_is_recorded_as_empty_list_not_an_error(fast_scan_config) -> None:
    def side_effect(host, record_type, lifetime=None):
        if record_type in ("A", "AAAA"):
            raise dns.resolver.NoAnswer()
        if record_type == "CNAME":
            raise dns.resolver.NoAnswer()
        if record_type == "NS":
            raise dns.resolver.NoAnswer()
        raise AssertionError

    result, store = _run_scanner(fast_scan_config, side_effect)

    a_records = store.observations_of_type(ModuleName.DNS, "a_records")[-1]
    assert a_records.value == []
    assert a_records.metadata["reason"] == "no_answer"
    assert result.status == ModuleStatus.COMPLETED


def test_timeout_is_categorized_as_error(fast_scan_config) -> None:
    def side_effect(host, record_type, lifetime=None):
        raise dns.exception.Timeout()

    result, _store = _run_scanner(fast_scan_config, side_effect)

    assert result.status == ModuleStatus.ERROR
    assert any("timed out" in e for e in result.errors)


def test_cname_chain_is_followed_and_bounded(fast_scan_config) -> None:
    chain = ["cdn.example.net", "edge.cdnprovider.net"]

    def side_effect(host, record_type, lifetime=None):
        if record_type in ("A", "AAAA"):
            raise dns.resolver.NoAnswer()
        if record_type == "CNAME":
            if host == "example.com":
                return [_FakeTargetRecord(chain[0])]
            if host == chain[0]:
                return [_FakeTargetRecord(chain[1])]
            raise dns.resolver.NoAnswer()
        if record_type == "NS":
            raise dns.resolver.NoAnswer()
        raise AssertionError

    result, store = _run_scanner(fast_scan_config, side_effect)

    cname_chain = store.observations_of_type(ModuleName.DNS, "cname_chain")[-1].value
    assert cname_chain == chain
    assert result.status == ModuleStatus.COMPLETED


def test_cname_loop_is_detected_and_does_not_hang(fast_scan_config) -> None:
    def side_effect(host, record_type, lifetime=None):
        if record_type in ("A", "AAAA"):
            raise dns.resolver.NoAnswer()
        if record_type == "CNAME":
            # Always points back to itself -> guaranteed loop.
            return [_FakeTargetRecord("example.com")]
        if record_type == "NS":
            raise dns.resolver.NoAnswer()
        raise AssertionError

    result, store = _run_scanner(fast_scan_config, side_effect)

    assert any("loop" in e.lower() for e in result.errors)
    assert result.status == ModuleStatus.PARTIAL


def test_ip_literal_target_skips_dns_entirely(fast_scan_config) -> None:
    target = normalize_target("https://127.0.0.1/")
    store = EvidenceStore()
    result = DnsResolutionScanner().run(target, fast_scan_config, store)

    assert result.status == ModuleStatus.SKIPPED
    assert store.observations_of_type(ModuleName.DNS, "skipped_ip_literal_target")
