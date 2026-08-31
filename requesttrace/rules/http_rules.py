"""HTTP/HTTPS redirect posture rules (RT-020 downgrade/loop detection consumers)."""

from __future__ import annotations

from requesttrace.models.enums import ModuleName, Severity
from requesttrace.models.finding import Finding
from requesttrace.rules.base import RuleContext, RuleDefinition, build_finding
from requesttrace.rules.remediation import format_how_to_fix

_HTTP_MODULE = ModuleName.HTTP
_REDIRECTS_MODULE = ModuleName.REDIRECTS


def _evaluate_https_downgrade(context: RuleContext) -> list[Finding]:
    value, evidence_ids = context.latest_observation_and_evidence_ids(
        _REDIRECTS_MODULE, "https_to_http_downgrade_detected"
    )
    if value is not True:
        return []

    return [
        build_finding(
            rule_id="RT-HTTP-001",
            title="Redirect chain downgrades from HTTPS to plaintext HTTP",
            severity=Severity.CRITICAL,
            affected_asset=context.target.authority,
            description="One or more hops in the observed redirect chain moved from an https:// URL to an http:// URL.",
            evidence_ids=evidence_ids,
            security_impact="Traffic transits in plaintext for at least one hop, exposing requests/responses to network-level interception and tampering.",
            recommendation="Ensure every redirect hop in the chain stays on HTTPS end to end.",
            how_to_fix=format_how_to_fix(
                "Remove any redirect rule that sends clients from an https:// URL to an "
                "http:// URL; all internal redirects should target https:// destinations.",
                nginx_example="return 301 https://$host$request_uri;  # never redirect an https vhost to http://",
                managed_edge_note="check CDN/load-balancer redirect rules for any HTTPS listener that forwards to an HTTP origin or destination.",
            ),
            verification="Re-run the scan and confirm `https_to_http_downgrade_detected` is false.",
            priority="Critical — remediate immediately.",
        )
    ]


def _evaluate_missing_http_to_https_redirect(context: RuleContext) -> list[Finding]:
    if context.target.scheme != "https":
        return []
    value, evidence_ids = context.latest_observation_and_evidence_ids(_HTTP_MODULE, "http_to_https_redirect")
    if value is None or value.get("redirects_to_https") is True:
        return []

    return [
        build_finding(
            rule_id="RT-HTTP-002",
            title="Plain HTTP requests are not redirected to HTTPS",
            severity=Severity.HIGH,
            affected_asset=context.target.authority,
            description=(
                f"A request to {value.get('probed_url')} returned status "
                f"{value.get('status_code')} without redirecting to HTTPS."
            ),
            evidence_ids=evidence_ids,
            security_impact="Clients that reach the site over plain HTTP (bookmarks, typed URLs, old links) will transmit requests in plaintext instead of being upgraded to a secure channel.",
            recommendation="Redirect all plain-HTTP requests to the HTTPS equivalent (301/308).",
            how_to_fix=format_how_to_fix(
                "Add an unconditional redirect from the HTTP listener to the equivalent HTTPS URL.",
                nginx_example=(
                    "server {\n"
                    "    listen 80;\n"
                    "    server_name example.com;\n"
                    "    return 301 https://$host$request_uri;\n"
                    "}"
                ),
                managed_edge_note="enable the 'redirect HTTP to HTTPS' / 'force HTTPS' option in your CDN or load balancer.",
            ),
            verification="Re-run the scan and confirm `http_to_https_redirect.redirects_to_https` is true.",
            priority="High — remediate within the next release cycle.",
        )
    ]


def _evaluate_redirect_loop(context: RuleContext) -> list[Finding]:
    value, evidence_ids = context.latest_observation_and_evidence_ids(_REDIRECTS_MODULE, "redirect_loop_detected")
    if value is not True:
        return []

    return [
        build_finding(
            rule_id="RT-HTTP-003",
            title="Redirect loop detected",
            severity=Severity.MEDIUM,
            affected_asset=context.target.authority,
            description="The observed redirect chain revisited a previously seen URL before reaching a final response.",
            evidence_ids=evidence_ids,
            security_impact="A redirect loop breaks availability for affected clients and paths, and may indicate a misconfiguration in routing/proxy rules.",
            recommendation="Fix the redirect rule(s) so the chain terminates in a final response.",
            how_to_fix=format_how_to_fix(
                "Review each redirect rule in the chain (proxy, application, CDN) for a "
                "condition that redirects back to an earlier URL in the chain."
            ),
            verification="Re-run the scan and confirm `redirect_loop_detected` is false and a final status code is reached.",
            priority="Medium — remediate promptly; affects availability.",
        )
    ]


RULES: list[RuleDefinition] = [
    RuleDefinition("RT-HTTP-001", "HTTPS to HTTP downgrade", Severity.CRITICAL, _evaluate_https_downgrade),
    RuleDefinition(
        "RT-HTTP-002",
        "Missing HTTP to HTTPS redirect",
        Severity.HIGH,
        _evaluate_missing_http_to_https_redirect,
    ),
    RuleDefinition("RT-HTTP-003", "Redirect loop", Severity.MEDIUM, _evaluate_redirect_loop),
]
