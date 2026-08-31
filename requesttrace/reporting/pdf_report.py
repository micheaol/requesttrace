"""PDF report renderer (RT-033).

Built from the same canonical render context as Markdown/HTML so content
stays equivalent across formats. Uses ``fpdf2`` (a pure-Python renderer with
no system font/graphics dependencies) so PDF generation degrades gracefully
— missing the optional dependency raises a clear, catchable error instead of
crashing the whole report pipeline.
"""

from __future__ import annotations

from requesttrace.models.scan import Scan
from requesttrace.reporting.context import build_render_context

PDF_TITLE_FONT_SIZE = 16
PDF_HEADING_FONT_SIZE = 12
PDF_BODY_FONT_SIZE = 9


class PdfRendererUnavailableError(RuntimeError):
    """Raised when the optional PDF dependency is not installed."""


def render_pdf_report(scan: Scan) -> bytes:
    """Render the canonical view model as a paginated PDF document."""
    try:
        from fpdf import FPDF
    except ImportError as exc:
        raise PdfRendererUnavailableError(
            "PDF rendering requires the optional 'pdf' extra: pip install 'requesttrace[pdf]'"
        ) from exc

    context = build_render_context(scan)
    document = _build_document_class(FPDF)()
    document.set_auto_page_break(auto=True, margin=15)
    document.add_page()

    _render_cover(document, context)
    _render_executive_summary(document, context)
    _render_module_status(document, context)
    _render_findings(document, context)
    _render_evidence_appendix(document, context)

    return bytes(document.output())


def _build_document_class(fpdf_base_class):
    """Attach the report's header/footer to fpdf2's FPDF, imported lazily by the caller."""

    class RequestTracePdf(fpdf_base_class):
        def header(self) -> None:
            self.set_font("Helvetica", "B", 10)
            self.cell(0, 8, "RequestTrace Security Assessment Report", new_x="LMARGIN", new_y="NEXT")
            self.set_draw_color(200, 200, 200)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(2)

        def footer(self) -> None:
            self.set_y(-15)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(120, 120, 120)
            self.cell(0, 10, f"Page {self.page_no()}", align="C")

    return RequestTracePdf


def _render_cover(document, context: dict) -> None:
    document.set_font("Helvetica", "B", PDF_TITLE_FONT_SIZE)
    _paragraph(document, 10, f"Target: {context['target'].normalized_url}")
    document.set_font("Helvetica", "", PDF_BODY_FONT_SIZE)
    _paragraph(
        document,
        6,
        f"Scan ID: {context['metadata'].scan_id}\n"
        f"Started: {context['metadata'].started_at}  Completed: {context['metadata'].completed_at}\n"
        f"Scanner: {context['metadata'].scanner_version}  Ruleset: {context['metadata'].ruleset_version}\n"
        f"Overall Assessment: {context['assessment_label']}",
    )
    document.ln(4)


def _render_executive_summary(document, context: dict) -> None:
    _section_heading(document, "Executive Summary")
    _body_text(document, context["executive_summary"])
    _section_heading(document, "Scope")
    _body_text(document, context["scope_statement"])
    _section_heading(document, "Limitations")
    _body_text(document, context["limitations_statement"])


def _render_module_status(document, context: dict) -> None:
    _section_heading(document, "Module Status")
    for module_name, table in context["module_tables"].items():
        _body_text(document, f"{module_name}: {table['status']} ({table['duration_ms']} ms)")


def _render_findings(document, context: dict) -> None:
    _section_heading(document, "Detailed Findings")
    findings = context["ordered_findings"]
    if not findings:
        _body_text(document, "No actionable findings were identified.")
        return

    for finding in findings:
        document.set_font("Helvetica", "B", PDF_BODY_FONT_SIZE + 1)
        _paragraph(document, 6, f"{finding.finding_id} [{finding.severity.value.upper()}] {finding.title}")
        document.set_font("Helvetica", "", PDF_BODY_FONT_SIZE)
        _paragraph(
            document,
            5,
            f"Rule: {finding.rule_id}\n"
            f"Affected asset: {finding.affected_asset}\n"
            f"Description: {finding.description}\n"
            f"Security impact: {finding.security_impact}\n"
            f"Recommendation: {finding.recommendation}\n"
            f"Verification: {finding.verification}\n"
            f"Priority: {finding.priority}",
        )
        document.ln(3)


def _render_evidence_appendix(document, context: dict) -> None:
    _section_heading(document, "Evidence Appendix")
    for evidence in context["evidence_appendix"]:
        _body_text(
            document,
            f"{evidence.evidence_id} [{evidence.module.value}] {evidence.source_method}: {evidence.normalized_value}",
        )


def _section_heading(document, title: str) -> None:
    document.ln(2)
    document.set_font("Helvetica", "B", PDF_HEADING_FONT_SIZE)
    document.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
    document.set_font("Helvetica", "", PDF_BODY_FONT_SIZE)


def _body_text(document, text: str) -> None:
    _paragraph(document, 5, str(text))


_PDF_CHARACTER_REPLACEMENTS = {
    "—": "-",  # em dash
    "–": "-",  # en dash
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',
    "…": "...",
    "•": "-",
}


def _paragraph(document, height: float, text: str) -> None:
    """multi_cell wrapper that resets the cursor to the left margin and is font-safe.

    fpdf2 leaves the x cursor at the right edge after a plain multi_cell call
    unless told otherwise, which starves the next call of horizontal space.
    The core Helvetica font only supports Latin-1, so text is normalized to
    avoid crashing on characters like an em dash pulled from finding text.
    """
    document.multi_cell(0, height, _pdf_safe_text(text), new_x="LMARGIN", new_y="NEXT")


def _pdf_safe_text(text: str) -> str:
    for source, target in _PDF_CHARACTER_REPLACEMENTS.items():
        text = text.replace(source, target)
    return text.encode("latin-1", errors="replace").decode("latin-1")
