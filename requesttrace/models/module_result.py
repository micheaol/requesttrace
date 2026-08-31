"""Per-module execution outcome (status, timing, errors, produced observations)."""

from __future__ import annotations

from dataclasses import dataclass, field

from requesttrace.models.enums import ModuleName, ModuleStatus


@dataclass(frozen=True, slots=True)
class ModuleResult:
    """Records whether a scanner/analyzer module succeeded, and how.

    One module's failure (e.g. TLS handshake refused) must never erase
    evidence already produced by other modules — each module gets its own
    result object, aggregated by the orchestrator into the final Scan.
    """

    module: ModuleName
    status: ModuleStatus
    duration_ms: float
    observation_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
