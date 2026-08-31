"""Shared Jinja2 environment for the Markdown and HTML report renderers."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def build_template_environment(*, autoescape: bool) -> Environment:
    # Templates are named `*.html.j2` / `*.md.j2`, so `select_autoescape`'s
    # filename-extension heuristic (which looks for a literal `.html` suffix)
    # would never fire — the caller's explicit `autoescape` flag is authoritative.
    # Only two call sites exist: html_report.py always passes True (untrusted
    # finding text is HTML-escaped), markdown_report.py always passes False
    # (plain-text output, where HTML-entity escaping would corrupt content
    # rather than protect it). Static analysis can't see that, hence nosec.
    return Environment(  # nosec B701
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=autoescape,
        trim_blocks=True,
        lstrip_blocks=True,
    )
