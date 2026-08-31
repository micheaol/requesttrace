"""Security-header rules (RT-021 consumer).

Permissions-Policy is intentionally not scored here — the PRD requires it be
assessed only informationally, so its observation is surfaced in reports
without ever becoming a finding.
"""

from __future__ import annotations

from requesttrace.models.enums import ModuleName, Severity
from requesttrace.models.finding import Finding
from requesttrace.rules.base import RuleContext, RuleDefinition, build_finding
from requesttrace.rules.remediation import format_how_to_fix

_MODULE = ModuleName.HEADERS
_MIN_RECOMMENDED_HSTS_MAX_AGE_SECONDS = 15552000  # 180 days


def _evaluate_missing_hsts(context: RuleContext) -> list[Finding]:
    if context.target.scheme != "https":
        return []
    value, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "hsts")
    if value is None or value.get("present") is True:
        return _evaluate_weak_hsts(context, value, evidence_ids) if value else []

    return [
        build_finding(
            rule_id="RT-HDR-001",
            title="Missing Strict-Transport-Security (HSTS) header",
            severity=Severity.HIGH,
            affected_asset=context.target.authority,
            description="No Strict-Transport-Security header was present on the HTTPS response.",
            evidence_ids=evidence_ids,
            security_impact="Without HSTS, browsers may still attempt plain-HTTP connections first, leaving an opening for SSL-stripping style downgrade attacks.",
            recommendation="Send a Strict-Transport-Security header with a long max-age on every HTTPS response.",
            how_to_fix=format_how_to_fix(
                "Add the HSTS header at the edge or application layer for all HTTPS responses.",
                nginx_example='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
                application_example='res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");',
                managed_edge_note="enable the HSTS header injection feature if your CDN/WAF offers one.",
            ),
            verification="Re-run the scan and confirm `hsts.present` is true with an adequate max-age.",
            priority="High — remediate within the next release cycle.",
        )
    ]


def _evaluate_weak_hsts(context: RuleContext, value: dict, evidence_ids: list[str]) -> list[Finding]:
    max_age = value.get("max_age")
    if max_age is not None and max_age >= _MIN_RECOMMENDED_HSTS_MAX_AGE_SECONDS:
        return []

    return [
        build_finding(
            rule_id="RT-HDR-001",
            title="Strict-Transport-Security max-age is too low",
            severity=Severity.MEDIUM,
            affected_asset=context.target.authority,
            description=f"HSTS is present but max-age is {max_age if max_age is not None else 'missing/unparseable'} seconds, below the recommended {_MIN_RECOMMENDED_HSTS_MAX_AGE_SECONDS}.",
            evidence_ids=evidence_ids,
            security_impact="A short max-age shortens the window during which returning clients are protected from downgrade attempts.",
            recommendation=f"Set HSTS max-age to at least {_MIN_RECOMMENDED_HSTS_MAX_AGE_SECONDS} seconds (180 days).",
            how_to_fix=format_how_to_fix(
                "Increase the HSTS max-age directive.",
                nginx_example='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            ),
            verification="Re-run the scan and confirm `hsts.max_age` meets the recommended minimum.",
            priority="Medium — remediate at next release.",
        )
    ]


def _evaluate_content_security_policy(context: RuleContext) -> list[Finding]:
    value, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "content_security_policy")
    if value is None:
        return []

    if not value.get("present"):
        return [
            build_finding(
                rule_id="RT-HDR-002",
                title="Missing Content-Security-Policy header",
                severity=Severity.MEDIUM,
                affected_asset=context.target.authority,
                description="No Content-Security-Policy header was present on the response.",
                evidence_ids=evidence_ids,
                security_impact="Without CSP, the browser has no defense-in-depth restriction on script/resource sources, increasing the impact of any XSS.",
                recommendation="Deploy a Content-Security-Policy appropriate to the application's actual resource needs.",
                how_to_fix=format_how_to_fix(
                    "Start with a restrictive default-src and iteratively allow only the "
                    "origins the application legitimately needs, ideally via report-only "
                    "mode first.",
                    nginx_example="add_header Content-Security-Policy \"default-src 'self'\" always;",
                ),
                verification="Re-run the scan and confirm `content_security_policy.present` is true.",
                priority="Medium — remediate as part of the next security hardening pass.",
            )
        ]

    high_risk = value.get("high_risk_patterns") or []
    if not high_risk:
        return []

    return [
        build_finding(
            rule_id="RT-HDR-002",
            title="Content-Security-Policy contains high-risk directives",
            severity=Severity.MEDIUM,
            affected_asset=context.target.authority,
            description=f"The CSP contains high-risk pattern(s): {', '.join(high_risk)}.",
            evidence_ids=evidence_ids,
            security_impact="'unsafe-inline'/'unsafe-eval' and wildcard sources significantly weaken CSP's ability to mitigate XSS.",
            recommendation="Remove unsafe-inline/unsafe-eval and wildcard sources; use nonces/hashes for required inline scripts.",
            how_to_fix=format_how_to_fix(
                "Replace 'unsafe-inline' with per-request nonces or hashes, and replace "
                "wildcard sources with an explicit allow-list of required origins."
            ),
            verification="Re-run the scan and confirm `content_security_policy.high_risk_patterns` is empty.",
            priority="Medium — remediate as part of the next security hardening pass.",
        )
    ]


def _evaluate_x_content_type_options(context: RuleContext) -> list[Finding]:
    value, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "x_content_type_options")
    if value is None or value.get("valid_nosniff") is True:
        return []

    return [
        build_finding(
            rule_id="RT-HDR-003",
            title="Missing or invalid X-Content-Type-Options header",
            severity=Severity.LOW,
            affected_asset=context.target.authority,
            description="X-Content-Type-Options: nosniff was not present (or had an unexpected value).",
            evidence_ids=evidence_ids,
            security_impact="Without nosniff, some browsers may MIME-sniff responses, which can enable content-type confusion attacks.",
            recommendation="Send X-Content-Type-Options: nosniff on all responses.",
            how_to_fix=format_how_to_fix(
                "Add the header at the edge or application layer.",
                nginx_example='add_header X-Content-Type-Options "nosniff" always;',
                application_example='res.setHeader("X-Content-Type-Options", "nosniff");',
            ),
            verification="Re-run the scan and confirm `x_content_type_options.valid_nosniff` is true.",
            priority="Low — remediate opportunistically.",
        )
    ]


def _evaluate_referrer_policy(context: RuleContext) -> list[Finding]:
    value, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "referrer_policy")
    if value is None or value.get("present") is True:
        return []

    return [
        build_finding(
            rule_id="RT-HDR-004",
            title="Missing Referrer-Policy header",
            severity=Severity.LOW,
            affected_asset=context.target.authority,
            description="No Referrer-Policy header was present on the response.",
            evidence_ids=evidence_ids,
            security_impact="Without an explicit policy, full referrer URLs (potentially including sensitive query parameters) may leak to third-party destinations.",
            recommendation="Set an explicit, minimal Referrer-Policy such as strict-origin-when-cross-origin.",
            how_to_fix=format_how_to_fix(
                "Add the header at the edge or application layer.",
                nginx_example='add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
                application_example='res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");',
            ),
            verification="Re-run the scan and confirm `referrer_policy.present` is true.",
            priority="Low — remediate opportunistically.",
        )
    ]


def _evaluate_frame_protection(context: RuleContext) -> list[Finding]:
    value, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "frame_protection")
    if value is None or value.get("protected") is True:
        return []

    return [
        build_finding(
            rule_id="RT-HDR-005",
            title="Missing clickjacking / frame protection",
            severity=Severity.MEDIUM,
            affected_asset=context.target.authority,
            description="Neither a CSP frame-ancestors directive nor an X-Frame-Options header was present.",
            evidence_ids=evidence_ids,
            security_impact="The page can be embedded in an attacker-controlled iframe, enabling clickjacking-style UI redress attacks.",
            recommendation="Set CSP frame-ancestors (preferred) or X-Frame-Options to restrict framing.",
            how_to_fix=format_how_to_fix(
                "Add frame-ancestors to the CSP, or fall back to X-Frame-Options for legacy clients.",
                nginx_example="add_header Content-Security-Policy \"frame-ancestors 'self'\" always;",
            ),
            verification="Re-run the scan and confirm `frame_protection.protected` is true.",
            priority="Medium — remediate as part of the next security hardening pass.",
        )
    ]


RULES: list[RuleDefinition] = [
    RuleDefinition("RT-HDR-001", "Missing or weak HSTS", Severity.HIGH, _evaluate_missing_hsts),
    RuleDefinition("RT-HDR-002", "Missing or weak CSP", Severity.MEDIUM, _evaluate_content_security_policy),
    RuleDefinition(
        "RT-HDR-003",
        "Missing X-Content-Type-Options",
        Severity.LOW,
        _evaluate_x_content_type_options,
    ),
    RuleDefinition("RT-HDR-004", "Missing Referrer-Policy", Severity.LOW, _evaluate_referrer_policy),
    RuleDefinition("RT-HDR-005", "Missing frame protection", Severity.MEDIUM, _evaluate_frame_protection),
]
