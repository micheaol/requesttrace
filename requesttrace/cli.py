"""The `requesttrace` command-line entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from requesttrace import __version__
from requesttrace.config import build_scan_config
from requesttrace.exit_codes import ExitCode, RequestTraceError
from requesttrace.models.enums import AssessmentLabel
from requesttrace.orchestrator import ScanOrchestrator
from requesttrace.policy import policy_is_breached
from requesttrace.reporting.baseline import (
    compare_to_baseline,
    load_baseline_report,
    summarize_baseline_diff,
)
from requesttrace.reporting.json_report import render_json_report
from requesttrace.reporting.writer import write_reports
from requesttrace.target import TargetValidationError


def emit(message: str, *, quiet: bool = False, err: bool = False) -> None:
    """Print a status line, honoring `--quiet`. Errors always print, even when quiet."""
    if quiet and not err:
        return
    click.echo(message, err=err)


@click.group()
@click.version_option(version=__version__, prog_name="requesttrace")
def main() -> None:
    """RequestTrace — production request-path, TLS and HTTP security assessment CLI."""


@main.command("scan")
@click.argument("target")
@click.option("--report", "write_report_files", is_flag=True, help="Write report file(s) to --output.")
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["md", "html", "pdf", "json", "all"]),
    default="md",
    show_default=True,
    help="Report format(s) to write when --report is set.",
)
@click.option(
    "--output",
    "output_dir",
    default="reports",
    show_default=True,
    help="Directory for written reports.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "never"]),
    default="high",
    show_default=True,
    help="Minimum finding severity that causes a non-zero (policy breach) exit code.",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=False),
    default=None,
    help="Previous JSON report to diff against.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=False),
    default=None,
    help="JSON config file overlay.",
)
@click.option(
    "--timeout",
    "timeout_seconds",
    type=float,
    default=None,
    help="Per-operation timeout in seconds.",
)
@click.option("--max-redirects", type=int, default=None, help="Maximum HTTP redirect hops to follow.")
@click.option(
    "--json",
    "json_stdout",
    is_flag=True,
    help="Print only the JSON scan result to stdout (CI/CD mode).",
)
@click.option("--verbose", is_flag=True, help="Print module-level diagnostics.")
@click.option("--quiet", is_flag=True, help="Suppress non-essential terminal output.")
def scan(
    target: str,
    write_report_files: bool,
    report_format: str,
    output_dir: str,
    fail_on: str,
    baseline_path: str | None,
    config_path: str | None,
    timeout_seconds: float | None,
    max_redirects: int | None,
    json_stdout: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    """Trace and assess the request path for TARGET (hostname, domain or full URL)."""
    exit_code = _run_scan(
        target=target,
        write_report_files=write_report_files,
        report_format=report_format,
        output_dir=output_dir,
        fail_on=fail_on,
        baseline_path=baseline_path,
        config_path=config_path,
        timeout_seconds=timeout_seconds,
        max_redirects=max_redirects,
        json_stdout=json_stdout,
        verbose=verbose,
        quiet=quiet,
    )
    sys.exit(exit_code)


def _run_scan(
    *,
    target: str,
    write_report_files: bool,
    report_format: str,
    output_dir: str,
    fail_on: str,
    baseline_path: str | None,
    config_path: str | None,
    timeout_seconds: float | None,
    max_redirects: int | None,
    json_stdout: bool,
    verbose: bool,
    quiet: bool,
) -> int:
    try:
        scan_config = build_scan_config(
            target_input=target,
            output_dir=output_dir,
            formats=(report_format,),
            fail_on=fail_on,
            baseline_path=baseline_path,
            timeout_seconds=timeout_seconds,
            max_redirects=max_redirects,
            verbose=verbose,
            quiet=quiet,
            config_path=config_path,
            write_reports=write_report_files,
        )
    except RequestTraceError as exc:
        emit(f"Error: {exc}", err=True)
        return exc.exit_code

    try:
        emit(f"Scanning {target} ...", quiet=quiet or json_stdout)
        result_scan = ScanOrchestrator().run(scan_config)
    except TargetValidationError as exc:
        emit(f"Invalid target: {exc}", err=True)
        return ExitCode.INVALID_INPUT
    except Exception as exc:  # noqa: BLE001 — surface as a scan execution failure, not a crash
        emit(f"Scan execution failed: {exc}", err=True)
        return ExitCode.SCAN_EXECUTION_FAILED

    if verbose and not (quiet or json_stdout):
        _emit_module_diagnostics(result_scan)

    if baseline_path:
        try:
            baseline_report = load_baseline_report(Path(baseline_path))
            diff_entries = compare_to_baseline(result_scan, baseline_report)
            if not (quiet or json_stdout):
                _emit_baseline_summary(diff_entries)
        except RequestTraceError as exc:
            emit(f"Error: {exc}", err=True)
            return exc.exit_code

    if json_stdout:
        click.echo(render_json_report(result_scan))
    elif not quiet:
        _emit_terminal_summary(result_scan)

    if write_report_files:
        try:
            written = write_reports(result_scan, scan_config.resolved_formats(), scan_config.output_dir)
            for fmt, path in written.items():
                emit(f"Wrote {fmt.upper()} report: {path}", quiet=quiet or json_stdout)
        except RequestTraceError as exc:
            emit(f"Error: {exc}", err=True)
            return exc.exit_code

    # A scan that could never produce a valid assessment (every critical
    # module failed, or nothing was observed at all) is a runtime/scanner
    # failure, not a policy outcome — it must not be conflated with exit 0/1.
    if result_scan.assessment_label == AssessmentLabel.ASSESSMENT_INCOMPLETE or not result_scan.observations:
        emit("Scan could not produce a valid assessment for this target.", err=True)
        return ExitCode.SCAN_EXECUTION_FAILED

    if policy_is_breached(result_scan.findings, scan_config.fail_on):
        return ExitCode.POLICY_BREACH
    return ExitCode.SUCCESS


def _emit_terminal_summary(scan_obj) -> None:
    click.echo("")
    click.echo(f"Overall Assessment: {scan_obj.assessment_label.value}")
    click.echo(f"Findings: {len(scan_obj.findings)}")
    for severity, count in scan_obj.severity_summary.items():
        if count:
            click.echo(f"  {severity.value}: {count}")
    for finding in scan_obj.findings:
        click.echo(f"  [{finding.severity.value.upper()}] {finding.rule_id} — {finding.title}")


def _emit_module_diagnostics(scan_obj) -> None:
    click.echo("Module diagnostics:")
    for result in scan_obj.module_results:
        click.echo(f"  {result.module.value}: {result.status.value} ({result.duration_ms:.1f} ms)")
        for error in result.errors:
            click.echo(f"    ⚠ {error}")


def _emit_baseline_summary(diff_entries) -> None:
    summary = summarize_baseline_diff(diff_entries)
    click.echo("Baseline comparison:")
    for change_type, count in summary.items():
        if count:
            click.echo(f"  {change_type}: {count}")


if __name__ == "__main__":
    main()
