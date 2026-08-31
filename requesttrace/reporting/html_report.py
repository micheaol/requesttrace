"""Production HTML report renderer (RT-032): offline, no external JS, escaped by default."""

from __future__ import annotations

from requesttrace.models.scan import Scan
from requesttrace.reporting.context import build_render_context
from requesttrace.reporting.template_env import build_template_environment


def render_html_report(scan: Scan) -> str:
    """Render the canonical view model as a self-contained, printable HTML report."""
    environment = build_template_environment(autoescape=True)
    template = environment.get_template("report.html.j2")
    return template.render(**build_render_context(scan))
