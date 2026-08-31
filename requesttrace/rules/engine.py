"""The versioned rule engine (RT-025): observations in, evidence-linked findings out."""

from __future__ import annotations

from requesttrace.models.finding import Finding
from requesttrace.rules import cookie_rules, dns_rules, header_rules, http_rules, tls_rules
from requesttrace.rules.base import RuleContext, RuleDefinition

# Bump whenever a rule's triggering condition, severity mapping or finding
# text changes in a way that could alter previously reported results —
# baseline comparison and reports both surface this value.
RULESET_VERSION = "2026.08.1"


def build_default_ruleset() -> list[RuleDefinition]:
    """Return every built-in rule, aggregated from each area-specific module."""
    return [
        *dns_rules.RULES,
        *tls_rules.RULES,
        *http_rules.RULES,
        *header_rules.RULES,
        *cookie_rules.RULES,
    ]


class RuleEngine:
    """Evaluates a ruleset against a scan's collected observations.

    Deterministic by construction: rules only read from the
    :class:`~requesttrace.evidence.store.EvidenceStore` via
    :class:`~requesttrace.rules.base.RuleContext`, never from rendered
    report text, so the same evidence always yields the same findings.
    """

    def __init__(self, rules: list[RuleDefinition] | None = None) -> None:
        self.rules: list[RuleDefinition] = rules if rules is not None else build_default_ruleset()

    def evaluate(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.evaluate(context))
        return findings
