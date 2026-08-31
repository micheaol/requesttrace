"""The scanner contract every collector module implements.

A scanner's only job is to turn network interaction into normalized
:class:`~requesttrace.models.observation.Observation` records via the shared
:class:`~requesttrace.evidence.store.EvidenceStore`. A scanner must never
raise on an *expected* network failure (timeout, refused, NXDOMAIN, TLS
handshake failure) — it must catch that and return an errored
:class:`~requesttrace.models.module_result.ModuleResult` instead, so one
module's failure never erases evidence already collected by another.
"""

from __future__ import annotations

from typing import Protocol

from requesttrace.config import ScanConfig
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.target import Target


class Scanner(Protocol):
    """Structural interface implemented by every scanner module."""

    def run(self, target: Target, config: ScanConfig, store: EvidenceStore) -> ModuleResult:
        """Execute the module's checks and return its aggregate result."""
        ...
