"""Schema-versioned JSON report renderer (RT-034)."""

from __future__ import annotations

from requesttrace.models.scan import Scan
from requesttrace.util.serialization import dump_json


def render_json_report(scan: Scan, *, indent: int | None = 2) -> str:
    """Serialize a scan into the versioned JSON report format for CI/CD consumption."""
    return dump_json(scan, indent=indent)
