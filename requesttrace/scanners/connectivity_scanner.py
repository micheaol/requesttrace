"""TCP connectivity engine: bounded connect-only checks (RT-009).

Deliberately connects to exactly the normalized service port — never a
range — so this module can never become a port scanner.
"""

from __future__ import annotations

import errno
import socket

from requesttrace.config import ScanConfig
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import ModuleName, ModuleStatus
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.target import Target
from requesttrace.util.timing import Stopwatch


class TcpConnectivityScanner:
    """Attempts a single bounded TCP connection to the target's service port."""

    module = ModuleName.CONNECTIVITY

    def run(self, target: Target, config: ScanConfig, store: EvidenceStore) -> ModuleResult:
        stopwatch = Stopwatch()
        try:
            with stopwatch:
                connection = socket.create_connection((target.host, target.port), timeout=config.timeout_seconds)
        except TimeoutError:
            return self._record_failure(store, "timeout", "Connection attempt timed out.", stopwatch)
        except ConnectionRefusedError:
            return self._record_failure(store, "refused", "Connection actively refused by the target.", stopwatch)
        except OSError as exc:
            return self._record_failure(store, *_categorize_os_error(exc), stopwatch=stopwatch)

        try:
            peer_ip, peer_port = connection.getpeername()[:2]
            address_family = "IPv6" if connection.family == socket.AF_INET6 else "IPv4"
        finally:
            connection.close()

        observation, evidence = store.record_observation_with_evidence(
            self.module,
            "tcp_connection",
            {"selected_ip": peer_ip, "port": peer_port, "address_family": address_family},
            source_method="socket.create_connection",
            sanitized_raw={
                "selected_ip": peer_ip,
                "port": peer_port,
                "address_family": address_family,
                "duration_ms": stopwatch.elapsed_ms,
            },
        )
        return ModuleResult(
            module=self.module,
            status=ModuleStatus.COMPLETED,
            duration_ms=stopwatch.elapsed_ms,
            observation_ids=[observation.observation_id, evidence.evidence_id],
        )

    def _record_failure(self, store: EvidenceStore, category: str, message: str, stopwatch: Stopwatch) -> ModuleResult:
        observation = store.record_observation(
            self.module, "tcp_connection_failure", category, metadata={"message": message}
        )
        return ModuleResult(
            module=self.module,
            status=ModuleStatus.ERROR,
            duration_ms=stopwatch.elapsed_ms,
            observation_ids=[observation.observation_id],
            errors=[message],
        )


def _categorize_os_error(exc: OSError) -> tuple[str, str]:
    if exc.errno == errno.EHOSTUNREACH:
        return "unreachable", "Destination host is unreachable."
    if exc.errno == errno.ENETUNREACH:
        return "unreachable", "Destination network is unreachable."
    if exc.errno == errno.ECONNREFUSED:
        return "refused", "Connection actively refused by the target."
    if exc.errno == socket.EAI_NONAME:
        return "resolution_failed", "Host could not be resolved for connection."
    return "error", f"Connection failed: {exc}"
