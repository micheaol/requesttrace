"""ScanConfig construction/validation tests (RT-004/RT-029)."""

from __future__ import annotations

import json

import pytest

from requesttrace.config import build_scan_config
from requesttrace.exit_codes import InvalidInputError


def test_defaults_are_applied() -> None:
    config = build_scan_config(target_input="example.com")
    assert config.fail_on == "high"
    assert config.timeout_seconds > 0
    assert config.max_redirects > 0


def test_invalid_fail_on_is_rejected() -> None:
    with pytest.raises(InvalidInputError):
        build_scan_config(target_input="example.com", fail_on="extreme")


def test_invalid_format_is_rejected() -> None:
    with pytest.raises(InvalidInputError):
        build_scan_config(target_input="example.com", formats=("xml",))


def test_all_format_expands_to_full_set() -> None:
    config = build_scan_config(target_input="example.com", formats=("all",))
    assert set(config.resolved_formats()) == {"md", "html", "json", "pdf"}


def test_config_file_overlay_is_applied(tmp_path) -> None:
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"timeout_seconds": 42, "certificate_warning_days": 60}))
    config = build_scan_config(target_input="example.com", config_path=str(config_file))
    assert config.timeout_seconds == 42
    assert config.certificate_warning_days == 60


def test_cli_value_overrides_config_file(tmp_path) -> None:
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"timeout_seconds": 42}))
    config = build_scan_config(target_input="example.com", config_path=str(config_file), timeout_seconds=5)
    assert config.timeout_seconds == 5


def test_missing_config_file_is_rejected() -> None:
    with pytest.raises(InvalidInputError):
        build_scan_config(target_input="example.com", config_path="/nonexistent/config.json")


def test_malformed_config_file_is_rejected(tmp_path) -> None:
    config_file = tmp_path / "config.json"
    config_file.write_text("{not valid json")
    with pytest.raises(InvalidInputError):
        build_scan_config(target_input="example.com", config_path=str(config_file))
