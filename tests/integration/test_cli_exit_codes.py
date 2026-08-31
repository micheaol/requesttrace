"""CLI exit-code contract tests (PRD §11 / RT-029), against local fixtures only."""

from __future__ import annotations

from click.testing import CliRunner

from requesttrace.cli import main
from tests.fixtures.local_http_server import LocalHttpServer, RouteResponse


def test_invalid_target_exits_2() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "not a valid target!!", "--quiet"])
    assert result.exit_code == 2


def test_unreachable_target_exits_3() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "https://127.0.0.1:1/", "--timeout", "1", "--quiet"])
    assert result.exit_code == 3


def test_clean_scan_with_fail_on_never_exits_0() -> None:
    routes = {"/": RouteResponse(200, headers=[("Content-Type", "text/plain")], body=b"ok")}
    with LocalHttpServer(routes) as server:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", server.base_url + "/", "--fail-on", "never", "--quiet"])
    assert result.exit_code == 0


def test_findings_above_threshold_exit_1() -> None:
    # No security headers at all on a plain HTTP target -> header findings fire.
    routes = {"/": RouteResponse(200, headers=[("Content-Type", "text/plain")], body=b"ok")}
    with LocalHttpServer(routes) as server:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", server.base_url + "/", "--fail-on", "low", "--quiet"])
    assert result.exit_code == 1


def test_json_stdout_mode_prints_only_json() -> None:
    routes = {"/": RouteResponse(200, headers=[("Content-Type", "text/plain")], body=b"ok")}
    with LocalHttpServer(routes) as server:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", server.base_url + "/", "--json", "--fail-on", "never"])
    assert result.output.strip().startswith("{")
    assert result.output.strip().endswith("}")


def test_report_flag_writes_files(tmp_path) -> None:
    routes = {"/": RouteResponse(200, headers=[("Content-Type", "text/plain")], body=b"ok")}
    with LocalHttpServer(routes) as server:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                server.base_url + "/",
                "--report",
                "--format",
                "json",
                "--output",
                str(tmp_path),
                "--fail-on",
                "never",
                "--quiet",
            ],
        )
    assert result.exit_code == 0
    assert any(tmp_path.glob("*.json"))
