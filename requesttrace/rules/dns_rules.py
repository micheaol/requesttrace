"""DNS-derived rules.

The DNS module currently contributes observations/evidence only — resolution
failures (NXDOMAIN, timeout, empty answers) surface as a
:class:`~requesttrace.models.module_result.ModuleResult` error rather than a
fabricated security finding, since a DNS failure alone is not itself an
externally verifiable security weakness. This module exists so the ruleset
registry has one place to add DNS-specific findings later (e.g. dangling
CNAME / subdomain takeover indicators) without changing the engine wiring.
"""

from __future__ import annotations

from requesttrace.rules.base import RuleDefinition

RULES: list[RuleDefinition] = []
