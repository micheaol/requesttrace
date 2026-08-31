"""Cookie attribute rules (RT-022 consumer).

Deliberately does **not** flag every cookie lacking HttpOnly: some cookies
are intentionally readable by client-side JavaScript, so a blanket rule
would produce false claims. Only Secure (on HTTPS targets) and SameSite are
scored here.
"""

from __future__ import annotations

from requesttrace.models.enums import ModuleName, Severity
from requesttrace.models.finding import Finding
from requesttrace.rules.base import RuleContext, RuleDefinition, build_finding
from requesttrace.rules.remediation import format_how_to_fix

_MODULE = ModuleName.COOKIES


def _all_cookie_observations(context: RuleContext) -> list[dict]:
    return [o.value for o in context.store.observations_of_type(_MODULE, "cookie")]


def _all_cookie_evidence_ids(context: RuleContext) -> list[str]:
    observations = context.store.observations_of_type(_MODULE, "cookie")
    observation_ids = {o.observation_id for o in observations}
    return [e.evidence_id for e in context.store.evidence if e.observation_id in observation_ids]


def _evaluate_missing_secure(context: RuleContext) -> list[Finding]:
    if context.target.scheme != "https":
        return []
    cookies = _all_cookie_observations(context)
    offending = [c["name"] for c in cookies if not c.get("secure")]
    if not offending:
        return []

    return [
        build_finding(
            rule_id="RT-COOKIE-001",
            title="Cookie set without the Secure attribute over HTTPS",
            severity=Severity.MEDIUM,
            affected_asset=context.target.authority,
            description=f"Cookie(s) missing the Secure attribute on an HTTPS response: {', '.join(offending)}.",
            evidence_ids=_all_cookie_evidence_ids(context),
            security_impact="Without Secure, the cookie can be sent over a future plain-HTTP connection to the same host, exposing it to network interception.",
            recommendation="Add the Secure attribute to every cookie set on an HTTPS response.",
            how_to_fix=format_how_to_fix(
                "Set the Secure flag when issuing the cookie.",
                application_example='res.cookie("session", value, { secure: true, httpOnly: true, sameSite: "lax" });',
            ),
            verification="Re-run the scan and confirm every reported cookie has secure=true.",
            priority="Medium — remediate as part of the next release cycle.",
        )
    ]


def _evaluate_missing_samesite(context: RuleContext) -> list[Finding]:
    cookies = _all_cookie_observations(context)
    offending = [c["name"] for c in cookies if not c.get("same_site")]
    if not offending:
        return []

    return [
        build_finding(
            rule_id="RT-COOKIE-002",
            title="Cookie set without an explicit SameSite attribute",
            severity=Severity.LOW,
            affected_asset=context.target.authority,
            description=f"Cookie(s) did not declare an explicit SameSite attribute: {', '.join(offending)}.",
            evidence_ids=_all_cookie_evidence_ids(context),
            security_impact="Relying on browser-default SameSite behavior is inconsistent across clients and versions, weakening CSRF defense-in-depth.",
            recommendation="Explicitly set SameSite=Lax (or Strict, where compatible with the flow) on all cookies.",
            how_to_fix=format_how_to_fix(
                "Set SameSite explicitly when issuing the cookie.",
                application_example='res.cookie("session", value, { sameSite: "lax", secure: true, httpOnly: true });',
            ),
            verification="Re-run the scan and confirm every reported cookie has an explicit same_site value.",
            priority="Low — remediate opportunistically.",
        )
    ]


RULES: list[RuleDefinition] = [
    RuleDefinition(
        "RT-COOKIE-001",
        "Cookie missing Secure over HTTPS",
        Severity.MEDIUM,
        _evaluate_missing_secure,
    ),
    RuleDefinition(
        "RT-COOKIE-002",
        "Cookie missing explicit SameSite",
        Severity.LOW,
        _evaluate_missing_samesite,
    ),
]
