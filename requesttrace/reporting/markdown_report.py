"""Production Markdown report renderer (RT-031)."""

from __future__ import annotations

from requesttrace.models.scan import Scan
from requesttrace.reporting.context import build_render_context
from requesttrace.reporting.template_env import build_template_environment


def render_markdown_report(scan: Scan) -> str:
    """Render the canonical view model as a GitHub-readable Markdown report."""
    environment = build_template_environment(autoescape=False)
    template = environment.get_template("report.md.j2")
    return template.render(**build_render_context(scan))
