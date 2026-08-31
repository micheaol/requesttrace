"""Stable, collision-resistant ID generation for scan model objects.

IDs are content-independent (random) rather than content-hashed, because two
identical observations collected at different times must remain
distinguishable. Stability of *rule* IDs (e.g. ``RT-TLS-014``) is handled
separately in :mod:`requesttrace.rules`, not here.
"""

from __future__ import annotations

import uuid


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def generate_scan_id() -> str:
    return _new_id("scan")


def generate_observation_id() -> str:
    return _new_id("obs")


def generate_evidence_id() -> str:
    return _new_id("ev")


def generate_finding_id() -> str:
    return _new_id("finding")
