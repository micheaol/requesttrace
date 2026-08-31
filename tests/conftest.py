"""Shared pytest fixtures: a fast default ScanConfig for unit/integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from requesttrace.config import ScanConfig


@pytest.fixture
def fast_scan_config(tmp_path: Path) -> ScanConfig:
    """A ScanConfig with short timeouts, suitable for local-only test fixtures."""
    return ScanConfig(
        target_input="https://127.0.0.1/",
        output_dir=tmp_path,
        formats=("json",),
        fail_on="high",
        baseline_path=None,
        timeout_seconds=3.0,
        max_redirects=5,
        verbose=False,
        quiet=True,
        user_agent="RequestTrace/1.0 (tests)",
        certificate_warning_days=30,
        certificate_critical_days=7,
        write_reports=False,
    )
