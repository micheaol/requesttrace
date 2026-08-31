"""Wires scanners, analyzers, the evidence store and the rule engine into one scan.

This is the only place that knows the full module execution order. Every
scanner failure is isolated here too (belt-and-suspenders on top of each
scanner's own internal handling) so one module's unexpected exception can
never erase evidence already collected by another.
"""

from __future__ import annotations

import os
import platform
import sys

from requesttrace import __version__
from requesttrace.analyzers.edge_fingerprint import EdgeEvidenceBundle, analyze_edge_indicators
from requesttrace.config import ScanConfig
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName, ModuleStatus
from requesttrace.models.identifiers import generate_scan_id
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.scan import Scan, ScanConfigSnapshot, ScanMetadata
from requesttrace.models.target import Target
from requesttrace.reporting.labels import compute_severity_summary, derive_assessment_label
from requesttrace.rules.base import RuleContext
from requesttrace.rules.engine import RULESET_VERSION, RuleEngine
from requesttrace.scanners.base import Scanner
from requesttrace.scanners.connectivity_scanner import TcpConnectivityScanner
from requesttrace.scanners.dns_scanner import DnsResolutionScanner
from requesttrace.scanners.http_scanner import HttpAssessmentScanner
from requesttrace.scanners.tls_scanner import TlsSecurityScanner
from requesttrace.target import normalize_target
from requesttrace.util.serialization import utc_now

SCHEMA_VERSION = "1.0.0"


def _default_scanner_pipeline() -> list[Scanner]:
    return [
        DnsResolutionScanner(),
        TcpConnectivityScanner(),
        TlsSecurityScanner(),
        HttpAssessmentScanner(),
    ]


class ScanOrchestrator:
    """Runs the full RequestTrace assessment pipeline for one target."""

    def __init__(self, scanners: list[Scanner] | None = None, rule_engine: RuleEngine | None = None) -> None:
        self._scanners = scanners if scanners is not None else _default_scanner_pipeline()
        self._rule_engine = rule_engine if rule_engine is not None else RuleEngine()

    def run(self, config: ScanConfig) -> Scan:
        started_at = utc_now()
        target = normalize_target(config.target_input)
        store = EvidenceStore()

        module_results = [self._run_scanner_safely(scanner, target, config, store) for scanner in self._scanners]
        module_results.append(self._run_edge_fingerprinting(target, store))

        findings = self._rule_engine.evaluate(RuleContext(target=target, config=config, store=store))

        severity_summary = compute_severity_summary(findings)
        assessment_label = derive_assessment_label(findings, module_results, target)

        metadata = ScanMetadata(
            scan_id=generate_scan_id(),
            scanner_version=__version__,
            ruleset_version=RULESET_VERSION,
            schema_version=SCHEMA_VERSION,
            runtime=f"Python {platform.python_version()} ({sys.platform})",
            container_image=os.environ.get("REQUESTTRACE_IMAGE_REF"),
            started_at=started_at,
            completed_at=utc_now(),
            config=ScanConfigSnapshot(
                timeout_seconds=config.timeout_seconds,
                max_redirects=config.max_redirects,
                fail_on=config.fail_on,
                user_agent=config.user_agent,
                certificate_warning_days=config.certificate_warning_days,
                certificate_critical_days=config.certificate_critical_days,
            ),
        )

        return Scan(
            metadata=metadata,
            target=target,
            observations=store.observations,
            evidence=store.evidence,
            findings=findings,
            module_results=module_results,
            assessment_label=assessment_label,
            severity_summary=severity_summary,
        )

    def _run_scanner_safely(
        self, scanner: Scanner, target: Target, config: ScanConfig, store: EvidenceStore
    ) -> ModuleResult:
        try:
            return scanner.run(target, config, store)
        except Exception as exc:  # noqa: BLE001 — isolate unexpected scanner bugs from the rest of the scan
            module = getattr(scanner, "module", ModuleName.HTTP)
            return ModuleResult(
                module=module,
                status=ModuleStatus.ERROR,
                duration_ms=0.0,
                errors=[f"Unexpected error in {scanner.__class__.__name__}: {exc}"],
            )

    def _run_edge_fingerprinting(self, target: Target, store: EvidenceStore) -> ModuleResult:
        try:
            bundle = EdgeEvidenceBundle(
                cname_chain=_latest(store, ModuleName.DNS, "cname_chain") or [],
                response_headers=_latest(store, ModuleName.HTTP, "response_headers") or {},
                certificate_issuer=(_latest(store, ModuleName.TLS, "certificate") or {}).get("issuer"),
            )
            observation_ids = analyze_edge_indicators(bundle, store)
            return ModuleResult(
                module=ModuleName.EDGE,
                status=ModuleStatus.COMPLETED,
                duration_ms=0.0,
                observation_ids=observation_ids,
            )
        except Exception as exc:  # noqa: BLE001
            return ModuleResult(
                module=ModuleName.EDGE,
                status=ModuleStatus.ERROR,
                duration_ms=0.0,
                errors=[f"Edge fingerprinting failed: {exc}"],
            )


def _latest(store: EvidenceStore, module: ModuleName, observation_type: str):
    matches = store.observations_of_type(module, observation_type)
    return matches[-1].value if matches else None
