"""Filesystem path helpers that guard against path traversal in generated filenames."""

from __future__ import annotations

import re
from pathlib import Path

from requesttrace.exit_codes import InvalidInputError

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename_component(value: str) -> str:
    """Strip any character that is not alphanumeric, dot, underscore or hyphen."""
    sanitized = _SAFE_COMPONENT_RE.sub("_", value).strip("._") or "target"
    return sanitized[:120]


def resolve_output_path(output_dir: Path, filename: str) -> Path:
    """Join ``filename`` under ``output_dir`` and refuse to escape it.

    Defense in depth on top of :func:`safe_filename_component` — even if a
    caller passes an unsanitized filename, this guarantees the final path
    still resolves inside ``output_dir``.
    """
    output_dir_resolved = output_dir.resolve()
    candidate = (output_dir_resolved / filename).resolve()
    if output_dir_resolved not in candidate.parents and candidate != output_dir_resolved:
        raise InvalidInputError(f"Refusing to write outside the output directory: {filename}")
    return candidate
