"""Writes rendered reports to disk under the configured, path-traversal-safe output dir."""

from __future__ import annotations

from pathlib import Path

from requesttrace.models.scan import Scan
from requesttrace.reporting.html_report import render_html_report
from requesttrace.reporting.json_report import render_json_report
from requesttrace.reporting.markdown_report import render_markdown_report
from requesttrace.reporting.pdf_report import PdfRendererUnavailableError, render_pdf_report
from requesttrace.util.paths import resolve_output_path, safe_filename_component

_RENDERERS = {
    "json": ("json", render_json_report, "w", "utf-8"),
    "md": ("md", render_markdown_report, "w", "utf-8"),
    "html": ("html", render_html_report, "w", "utf-8"),
}


def write_reports(scan: Scan, formats: tuple[str, ...], output_dir: Path) -> dict[str, Path]:
    """Render and write each requested format; returns format -> written path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = _base_report_name(scan)

    written: dict[str, Path] = {}
    for fmt in formats:
        if fmt == "pdf":
            written_path = _write_pdf(scan, base_name, output_dir)
            if written_path:
                written["pdf"] = written_path
            continue

        extension, render_fn, mode, encoding = _RENDERERS[fmt]
        destination = resolve_output_path(output_dir, f"{base_name}.{extension}")
        destination.write_text(render_fn(scan), encoding=encoding)
        written[fmt] = destination

    return written


def _write_pdf(scan: Scan, base_name: str, output_dir: Path) -> Path | None:
    try:
        content = render_pdf_report(scan)
    except PdfRendererUnavailableError:
        return None
    destination = resolve_output_path(output_dir, f"{base_name}.pdf")
    destination.write_bytes(content)
    return destination


def _base_report_name(scan: Scan) -> str:
    host_component = safe_filename_component(scan.target.host)
    timestamp_component = scan.metadata.started_at.strftime("%Y%m%dT%H%M%SZ")
    return f"requesttrace_{host_component}_{timestamp_component}"
