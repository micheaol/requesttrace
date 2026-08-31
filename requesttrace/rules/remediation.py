"""Remediation knowledge model (RT-026): consistent, technology-labeled fix guidance.

Examples are always explicitly labeled by the technology they illustrate
(e.g. "Example (NGINX)"). RequestTrace never fingerprints origin server
software, so guidance must never claim the target actually runs the
illustrated technology — only that the example demonstrates the fix on a
commonly used stack.
"""

from __future__ import annotations


def format_how_to_fix(
    general_guidance: str,
    *,
    nginx_example: str | None = None,
    application_example: str | None = None,
    managed_edge_note: str | None = None,
) -> str:
    """Assemble technology-neutral guidance plus clearly labeled illustrative examples."""
    sections = [general_guidance.strip()]

    if nginx_example:
        sections.append(
            f"Example (NGINX config — illustrative, verify against your actual origin):\n{nginx_example.strip()}"
        )
    if application_example:
        sections.append(
            f"Example (application middleware — illustrative, verify against your actual stack):\n{application_example.strip()}"
        )
    if managed_edge_note:
        sections.append(f"If using a managed CDN/edge/WAF: {managed_edge_note.strip()}")

    return "\n\n".join(sections)
