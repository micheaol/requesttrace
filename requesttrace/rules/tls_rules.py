"""TLS cryptography, trust, hostname and certificate-expiry rules (RT-014/016/017)."""

from __future__ import annotations

import datetime as dt

from requesttrace.models.enums import ModuleName, Severity
from requesttrace.models.finding import Finding
from requesttrace.rules.base import RuleContext, RuleDefinition, build_finding
from requesttrace.rules.remediation import format_how_to_fix

_MODULE = ModuleName.TLS
_LEGACY_PROTOCOL_DISPLAY_NAMES = ("TLS 1.0", "TLS 1.1")
_WEAK_CIPHER_SUBSTRINGS = ("rc4", "3des", "des-cbc", "export", "null", "_md5", "anon")


def _evaluate_deprecated_protocols(context: RuleContext) -> list[Finding]:
    value, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "protocol_support")
    if not value:
        return []

    enabled_legacy = [name for name in _LEGACY_PROTOCOL_DISPLAY_NAMES if value.get(name, {}).get("supported") is True]
    if not enabled_legacy:
        return []

    return [
        build_finding(
            rule_id="RT-TLS-001",
            title="Deprecated TLS protocol version enabled",
            severity=Severity.HIGH,
            affected_asset=context.target.authority,
            description=(
                f"The server negotiated a successful handshake using deprecated protocol "
                f"version(s): {', '.join(enabled_legacy)}. These protocols have known "
                "cryptographic weaknesses and are deprecated by all major browsers."
            ),
            evidence_ids=evidence_ids,
            security_impact=(
                "Deprecated TLS versions lack modern cipher suites and mitigations, "
                "increasing exposure to downgrade and protocol-level attacks against "
                "clients that still permit negotiation to this version."
            ),
            recommendation="Disable TLS 1.0 and TLS 1.1; support only TLS 1.2 and TLS 1.3.",
            how_to_fix=format_how_to_fix(
                "Restrict the TLS listener to TLS 1.2 and TLS 1.3 only.",
                nginx_example="ssl_protocols TLSv1.2 TLSv1.3;",
                managed_edge_note="set the minimum TLS version policy to 1.2 in your CDN/load balancer configuration.",
            ),
            verification=(
                "Re-run `requesttrace scan` and confirm TLS 1.0/1.1 report supported=false, "
                "or verify with `openssl s_client -tls1_1 -connect <host>:<port>` (expect a handshake failure)."
            ),
            priority="High — remediate within the next release cycle.",
        )
    ]


def _evaluate_hostname_mismatch(context: RuleContext) -> list[Finding]:
    value, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "hostname_match")
    if value is None or value.get("matches") is True:
        return []

    return [
        build_finding(
            rule_id="RT-TLS-002",
            title="TLS certificate does not match the requested hostname",
            severity=Severity.HIGH,
            affected_asset=context.target.authority,
            description=(
                f"The presented certificate's Subject Alternative Names did not include '{context.target.host}'."
            ),
            evidence_ids=evidence_ids,
            security_impact=(
                "Clients performing standard hostname validation will reject this "
                "certificate, breaking trust indicators and training users to click "
                "through security warnings — which also enables real MITM attacks."
            ),
            recommendation="Issue and deploy a certificate whose SAN list includes the exact hostname served.",
            how_to_fix=format_how_to_fix(
                "Reissue the TLS certificate with the correct Subject Alternative Name(s), "
                "or correct the routing/SNI configuration serving this hostname.",
                managed_edge_note="confirm the custom-domain / hostname mapping is attached to the correct certificate.",
            ),
            verification="Re-run the scan and confirm `hostname_match.matches` is true.",
            priority="Critical — fix before this hostname serves production traffic.",
        )
    ]


def _evaluate_trust_chain(context: RuleContext) -> list[Finding]:
    value, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "trust_chain_valid")
    if value is not False:
        return []

    failure_category = _latest_trust_failure_category(context)
    severity, label = {
        "self_signed": (Severity.HIGH, "self-signed"),
        "incomplete_chain": (Severity.HIGH, "incomplete (missing intermediate certificate)"),
        "not_yet_valid": (Severity.HIGH, "not yet valid"),
        "expired": (Severity.CRITICAL, "expired"),
    }.get(failure_category or "", (Severity.MEDIUM, "not verifiable against a trusted root store"))

    return [
        build_finding(
            rule_id="RT-TLS-003",
            title=f"TLS certificate chain is {label}",
            severity=severity,
            affected_asset=context.target.authority,
            description=(f"Standard trust-chain validation against the system trust store failed: {label}."),
            evidence_ids=evidence_ids,
            security_impact=(
                "Clients cannot cryptographically verify the server's identity, which "
                "either breaks connectivity for strict clients or trains users/automation "
                "to bypass certificate validation entirely."
            ),
            recommendation="Deploy a certificate issued by a publicly trusted CA with a complete chain.",
            how_to_fix=format_how_to_fix(
                "Install the full certificate chain (leaf + intermediate(s)) in the correct "
                "order, issued by a CA trusted by public root stores.",
                nginx_example="ssl_certificate /etc/ssl/fullchain.pem;  # leaf + intermediates, in order",
                managed_edge_note="verify the managed certificate/ACM/CDN certificate status is 'issued' and attached to this hostname.",
            ),
            verification="Re-run the scan, or `openssl s_client -connect <host>:<port> -showcerts` and confirm `Verify return code: 0 (ok)`.",
            priority="High — remediate promptly; may already be breaking clients.",
        )
    ]


def _latest_trust_failure_category(context: RuleContext) -> str | None:
    matches = context.store.observations_of_type(_MODULE, "trust_chain_valid")
    if not matches:
        return None
    return matches[-1].metadata.get("failure_category")


def _evaluate_certificate_expiry(context: RuleContext) -> list[Finding]:
    certificate, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "certificate")
    if not certificate:
        return []

    days_remaining = certificate.get("days_remaining")
    if days_remaining is None:
        return []

    not_valid_before = dt.datetime.fromisoformat(certificate["not_valid_before"])
    now = dt.datetime.now(not_valid_before.tzinfo)

    if now < not_valid_before:
        return [_certificate_temporal_finding(context, evidence_ids, "not yet valid", Severity.HIGH, certificate)]

    if days_remaining < 0:
        return [
            _certificate_temporal_finding(
                context,
                evidence_ids,
                f"expired {abs(days_remaining)} day(s) ago",
                Severity.CRITICAL,
                certificate,
            )
        ]

    if days_remaining <= context.config.certificate_critical_days:
        return [_certificate_expiring_finding(context, evidence_ids, days_remaining, Severity.CRITICAL, certificate)]

    if days_remaining <= context.config.certificate_warning_days:
        return [_certificate_expiring_finding(context, evidence_ids, days_remaining, Severity.MEDIUM, certificate)]

    return []


def _certificate_temporal_finding(
    context: RuleContext,
    evidence_ids: list[str],
    condition: str,
    severity: Severity,
    certificate: dict,
) -> Finding:
    return build_finding(
        rule_id="RT-TLS-004",
        title=f"TLS certificate is {condition}",
        severity=severity,
        affected_asset=context.target.authority,
        description=(
            f"The certificate for '{certificate.get('subject')}' is {condition} "
            f"(valid until {certificate.get('not_valid_after')})."
        ),
        evidence_ids=evidence_ids,
        security_impact="Clients will refuse or warn on connection, and any trust guarantees the certificate provided are void.",
        recommendation="Renew and redeploy the certificate immediately.",
        how_to_fix=format_how_to_fix(
            "Issue a new certificate and deploy it before the current one's validity window fails, "
            "then automate renewal (e.g. ACME/Let's Encrypt with a renewal cron/systemd timer).",
            managed_edge_note="check the managed certificate's auto-renewal status.",
        ),
        verification="Re-run the scan and confirm `certificate.days_remaining` is positive and above your warning threshold.",
        priority="Critical — remediate immediately.",
    )


def _certificate_expiring_finding(
    context: RuleContext,
    evidence_ids: list[str],
    days_remaining: int,
    severity: Severity,
    certificate: dict,
) -> Finding:
    return build_finding(
        rule_id="RT-TLS-005",
        title="TLS certificate is approaching expiry",
        severity=severity,
        affected_asset=context.target.authority,
        description=(
            f"The certificate for '{certificate.get('subject')}' expires in {days_remaining} day(s) "
            f"(on {certificate.get('not_valid_after')})."
        ),
        evidence_ids=evidence_ids,
        security_impact="An expired certificate will break TLS connectivity for all clients until renewed.",
        recommendation=f"Renew the certificate well before its {days_remaining}-day expiry window closes.",
        how_to_fix=format_how_to_fix(
            "Renew the certificate now and verify automated renewal is configured so this does "
            "not recur (e.g. certbot renew timer, or your CDN/cloud provider's managed renewal).",
        ),
        verification="Re-run the scan after renewal and confirm `certificate.days_remaining` has increased.",
        priority="High — schedule renewal before the warning window closes.",
    )


def _evaluate_negotiated_cipher(context: RuleContext) -> list[Finding]:
    cipher, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "negotiated_cipher")
    if not cipher or not cipher.get("name"):
        return []

    cipher_name_lower = cipher["name"].lower()
    if not any(pattern in cipher_name_lower for pattern in _WEAK_CIPHER_SUBSTRINGS):
        return []

    return [
        build_finding(
            rule_id="RT-TLS-006",
            title="Weak or deprecated TLS cipher suite negotiated",
            severity=Severity.HIGH,
            affected_asset=context.target.authority,
            description=f"The server negotiated cipher suite '{cipher['name']}', which is considered weak or deprecated.",
            evidence_ids=evidence_ids,
            security_impact="Weak ciphers may be vulnerable to cryptanalytic or downgrade attacks, potentially exposing session confidentiality/integrity.",
            recommendation="Restrict the server's cipher suite list to modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
            how_to_fix=format_how_to_fix(
                "Configure the TLS stack to offer only modern, forward-secret AEAD cipher suites.",
                nginx_example="ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305';\nssl_prefer_server_ciphers off;",
                managed_edge_note="select a modern TLS security policy (e.g. an 'AEAD-only' or TLS 1.2+ policy) in your load balancer/CDN settings.",
            ),
            verification="Re-run the scan and confirm the negotiated cipher is AEAD-based (GCM or ChaCha20-Poly1305).",
            priority="High — remediate within the next release cycle.",
        )
    ]


def _evaluate_public_key_strength(context: RuleContext) -> list[Finding]:
    certificate, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "certificate")
    if not certificate:
        return []

    algorithm = certificate.get("public_key_algorithm", "")
    key_size = certificate.get("public_key_size_bits")
    if key_size is None:
        return []

    is_weak_rsa = algorithm == "RSA" and key_size < 2048
    is_weak_dsa = algorithm == "DSA" and key_size < 2048
    if not (is_weak_rsa or is_weak_dsa):
        return []

    severity = Severity.CRITICAL if key_size <= 1024 else Severity.HIGH
    return [
        build_finding(
            rule_id="RT-TLS-007",
            title=f"TLS certificate public key size is too small ({algorithm} {key_size}-bit)",
            severity=severity,
            affected_asset=context.target.authority,
            description=f"The certificate's {algorithm} public key is {key_size} bits, below the modern minimum of 2048 bits.",
            evidence_ids=evidence_ids,
            security_impact="Small key sizes reduce the computational cost of factoring/discrete-log attacks, weakening the certificate's cryptographic guarantees.",
            recommendation="Reissue the certificate with an RSA key of at least 2048 bits (or migrate to ECDSA P-256).",
            how_to_fix=format_how_to_fix(
                "Generate a new key pair meeting current minimums and request a new certificate for it.",
                nginx_example="openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr",
            ),
            verification="Re-run the scan and confirm `certificate.public_key_size_bits` is >= 2048 (RSA) or an approved EC curve.",
            priority="High — reissue at the next opportunity.",
        )
    ]


def _evaluate_signature_algorithm(context: RuleContext) -> list[Finding]:
    certificate, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "certificate")
    if not certificate:
        return []

    signature_algorithm = str(certificate.get("signature_algorithm", "")).lower()
    if "md5" in signature_algorithm:
        severity = Severity.HIGH
    elif "sha1" in signature_algorithm:
        severity = Severity.MEDIUM
    else:
        return []

    return [
        build_finding(
            rule_id="RT-TLS-008",
            title=f"TLS certificate uses a deprecated signature algorithm ({certificate.get('signature_algorithm')})",
            severity=severity,
            affected_asset=context.target.authority,
            description=f"The certificate is signed using {certificate.get('signature_algorithm')}, which is deprecated due to known collision weaknesses.",
            evidence_ids=evidence_ids,
            security_impact="Weak signature algorithms may allow certificate forgery in targeted scenarios, undermining the chain of trust.",
            recommendation="Reissue the certificate using SHA-256 (or stronger) signatures.",
            how_to_fix=format_how_to_fix(
                "Request a new certificate signed with SHA-256 or better from your issuing CA."
            ),
            verification="Re-run the scan and confirm `certificate.signature_algorithm` uses SHA-256 or stronger.",
            priority="Medium — remediate at next renewal.",
        )
    ]


def _evaluate_forward_secrecy(context: RuleContext) -> list[Finding]:
    protocol = context.latest_observation_value(_MODULE, "negotiated_protocol")
    cipher, evidence_ids = context.latest_observation_and_evidence_ids(_MODULE, "negotiated_cipher")
    if not cipher or not cipher.get("name") or protocol == "TLSv1.3":
        return []

    cipher_name = cipher["name"]
    if "ECDHE" in cipher_name or "DHE" in cipher_name:
        return []

    return [
        build_finding(
            rule_id="RT-TLS-009",
            title="Negotiated cipher suite does not provide forward secrecy",
            severity=Severity.MEDIUM,
            affected_asset=context.target.authority,
            description=f"Cipher suite '{cipher_name}' does not use an ephemeral (EC)DHE key exchange.",
            evidence_ids=evidence_ids,
            security_impact="Without forward secrecy, compromise of the server's private key in the future would allow decryption of previously captured traffic.",
            recommendation="Prefer ECDHE-based cipher suites for all supported TLS versions.",
            how_to_fix=format_how_to_fix(
                "Reorder or restrict the cipher suite list to ephemeral key-exchange suites only.",
                nginx_example="ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';",
            ),
            verification="Re-run the scan and confirm the negotiated cipher name contains 'ECDHE' or 'DHE', or that TLS 1.3 is negotiated.",
            priority="Medium — remediate within the next release cycle.",
        )
    ]


RULES: list[RuleDefinition] = [
    RuleDefinition(
        "RT-TLS-001",
        "Deprecated TLS protocol version enabled",
        Severity.HIGH,
        _evaluate_deprecated_protocols,
    ),
    RuleDefinition("RT-TLS-002", "TLS hostname mismatch", Severity.HIGH, _evaluate_hostname_mismatch),
    RuleDefinition("RT-TLS-003", "TLS trust chain invalid", Severity.HIGH, _evaluate_trust_chain),
    RuleDefinition("RT-TLS-004", "TLS certificate expiry", Severity.CRITICAL, _evaluate_certificate_expiry),
    RuleDefinition("RT-TLS-006", "Weak negotiated cipher", Severity.HIGH, _evaluate_negotiated_cipher),
    RuleDefinition("RT-TLS-007", "Weak certificate public key", Severity.HIGH, _evaluate_public_key_strength),
    RuleDefinition(
        "RT-TLS-008",
        "Deprecated certificate signature algorithm",
        Severity.MEDIUM,
        _evaluate_signature_algorithm,
    ),
    RuleDefinition("RT-TLS-009", "Missing forward secrecy", Severity.MEDIUM, _evaluate_forward_secrecy),
]
