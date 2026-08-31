"""DNS assessment engine: A/AAAA resolution, CNAME chain, NS collection (RT-007/008)."""

from __future__ import annotations

import dns.exception
import dns.rdatatype
import dns.resolver

from requesttrace.config import ScanConfig
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName, ModuleStatus
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.target import Target
from requesttrace.util.timing import Stopwatch

MAX_CNAME_HOPS = 10


class DnsResolutionScanner:
    """Resolves A/AAAA records, the CNAME chain, and authoritative NS records."""

    module = ModuleName.DNS

    def run(self, target: Target, config: ScanConfig, store: EvidenceStore) -> ModuleResult:
        stopwatch = Stopwatch()
        observation_ids: list[str] = []
        errors: list[str] = []

        if target.is_ip_literal:
            observation = store.record_observation(
                self.module,
                "skipped_ip_literal_target",
                target.host,
                metadata={"reason": "Target is an IP literal; DNS resolution is not applicable."},
            )
            observation_ids.append(observation.observation_id)
            return ModuleResult(
                module=self.module,
                status=ModuleStatus.SKIPPED,
                duration_ms=0.0,
                observation_ids=observation_ids,
            )

        resolver = _build_resolver(config.timeout_seconds)

        with stopwatch:
            observation_ids += self._resolve_address_family(resolver, target.host, "A", store, errors)
            observation_ids += self._resolve_address_family(resolver, target.host, "AAAA", store, errors)
            observation_ids += self._resolve_cname_chain(resolver, target.host, store, errors)
            observation_ids += self._resolve_nameservers(resolver, target.host, store, errors)

        status = _derive_module_status(observation_ids, errors)
        return ModuleResult(
            module=self.module,
            status=status,
            duration_ms=stopwatch.elapsed_ms,
            observation_ids=observation_ids,
            errors=errors,
        )

    def _resolve_address_family(
        self,
        resolver: dns.resolver.Resolver,
        host: str,
        record_type: str,
        store: EvidenceStore,
        errors: list[str],
    ) -> list[str]:
        lookup = Stopwatch()
        try:
            with lookup:
                answer = resolver.resolve(host, record_type, lifetime=resolver.lifetime)
            addresses = sorted({record.address for record in answer})
            observation, evidence = store.record_observation_with_evidence(
                self.module,
                f"{record_type.lower()}_records",
                addresses,
                source_method=f"dns.resolver.resolve({record_type})",
                metadata={"duration_ms": lookup.elapsed_ms, "record_type": record_type},
                sanitized_raw={"addresses": addresses, "duration_ms": lookup.elapsed_ms},
            )
            return [observation.observation_id, evidence.evidence_id]
        except dns.resolver.NXDOMAIN:
            errors.append(f"{record_type}: NXDOMAIN — domain does not exist.")
        except dns.resolver.NoAnswer:
            observation = store.record_observation(
                self.module,
                f"{record_type.lower()}_records",
                [],
                metadata={"reason": "no_answer", "record_type": record_type},
            )
            return [observation.observation_id]
        except dns.resolver.NoNameservers as exc:
            errors.append(f"{record_type}: no nameservers could answer ({exc}).")
        except dns.exception.Timeout:
            errors.append(f"{record_type}: DNS lookup timed out.")
        return []

    def _resolve_cname_chain(
        self,
        resolver: dns.resolver.Resolver,
        host: str,
        store: EvidenceStore,
        errors: list[str],
    ) -> list[str]:
        chain: list[str] = []
        seen: set[str] = set()
        current = host

        for _ in range(MAX_CNAME_HOPS):
            if current in seen:
                errors.append(f"CNAME loop detected at {current!r}; chain truncated.")
                break
            seen.add(current)
            try:
                answer = resolver.resolve(current, "CNAME", lifetime=resolver.lifetime)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                break
            except dns.exception.Timeout:
                errors.append("CNAME chain resolution timed out.")
                break
            except dns.resolver.NoNameservers as exc:
                errors.append(f"CNAME: no nameservers could answer ({exc}).")
                break

            target_name = str(answer[0].target).rstrip(".")
            chain.append(target_name)
            current = target_name

        if not chain:
            return []

        observation = store.record_observation(self.module, "cname_chain", chain, metadata={"hop_count": len(chain)})
        evidence = store.record_evidence(
            observation, source_method="dns.resolver.resolve(CNAME)", sanitized_raw={"chain": chain}
        )
        return [observation.observation_id, evidence.evidence_id]

    def _resolve_nameservers(
        self,
        resolver: dns.resolver.Resolver,
        host: str,
        store: EvidenceStore,
        errors: list[str],
    ) -> list[str]:
        try:
            answer = resolver.resolve(host, "NS", lifetime=resolver.lifetime)
        except dns.resolver.NoAnswer:
            observation = store.record_observation(
                self.module,
                "ns_records",
                [],
                metadata={"reason": "no_answer_not_zone_apex"},
            )
            return [observation.observation_id]
        except dns.resolver.NXDOMAIN:
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            errors.append(f"NS: lookup failed ({exc}).")
            return []

        nameservers = sorted({str(record.target).rstrip(".") for record in answer})
        observation, evidence = store.record_observation_with_evidence(
            self.module,
            "ns_records",
            nameservers,
            source_method="dns.resolver.resolve(NS)",
            sanitized_raw={"nameservers": nameservers},
        )
        return [observation.observation_id, evidence.evidence_id]


def _build_resolver(timeout_seconds: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout_seconds
    resolver.timeout = timeout_seconds
    return resolver


def _derive_module_status(observation_ids: list[str], errors: list[str]) -> ModuleStatus:
    if observation_ids and not errors:
        return ModuleStatus.COMPLETED
    if observation_ids and errors:
        return ModuleStatus.PARTIAL
    return ModuleStatus.ERROR
