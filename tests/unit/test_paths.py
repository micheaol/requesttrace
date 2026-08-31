"""Path-traversal safety tests for report output filenames (PRD §15)."""

from __future__ import annotations

import pytest

from requesttrace.exit_codes import InvalidInputError
from requesttrace.util.paths import resolve_output_path, safe_filename_component


def test_safe_filename_component_strips_traversal_sequences() -> None:
    assert ".." not in safe_filename_component("../../etc/passwd")
    assert "/" not in safe_filename_component("../../etc/passwd")


def test_safe_filename_component_preserves_ordinary_hostnames() -> None:
    assert safe_filename_component("example.com") == "example.com"


def test_resolve_output_path_stays_within_output_dir(tmp_path) -> None:
    resolved = resolve_output_path(tmp_path, "report.json")
    assert resolved.parent == tmp_path.resolve()


def test_resolve_output_path_rejects_traversal(tmp_path) -> None:
    with pytest.raises(InvalidInputError):
        resolve_output_path(tmp_path, "../escape.json")


def test_resolve_output_path_rejects_absolute_escape(tmp_path) -> None:
    with pytest.raises(InvalidInputError):
        resolve_output_path(tmp_path, "/etc/passwd")
