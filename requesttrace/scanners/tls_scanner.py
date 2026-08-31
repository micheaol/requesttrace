"""TLS security assessment engine: handshake, certificate, trust, protocol probing.

Covers RT-012 (handshake), RT-013 (certificate parser), RT-014 (trust/hostname/
validity), and RT-015 (protocol support probing). Cryptography *rules* and
expiry *thresholds* (RT-016/RT-017) deliberately live in
:mod:`requesttrace.rules.tls_rules` — this module only records observations.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from requesttrace.config import ScanConfig
from requesttrace.evidence.store import EvidenceStore
from requesttrace.models.enums import Confidence, ModuleName, ModuleStatus
from requesttrace.models.module_result import ModuleResult
from requesttrace.models.target import Target
from requesttrace.util.timing import Stopwatch

ALPN_PREFERENCE = ["h2", "http/1.1"]

_PROBED_PROTOCOLS: list[tuple[str, str]] = [
    ("TLSv1", "TLS 1.0"),
    ("TLSv1_1", "TLS 1.1"),
    ("TLSv1_2", "TLS 1.2"),
    ("TLSv1_3", "TLS 1.3"),
]

_LEGACY_PROTOCOLS = {"TLSv1", "TLSv1_1"}


@dataclass
class _CertificateFields:
    subject: str
    issuer: str
    subject_alternative_names: list[str]
    not_valid_before: datetime
    not_valid_after: datetime
    days_remaining: int
    fingerprint_sha256: str
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size_bits: int | None


class TlsSecurityScanner:
    """Collects the primary TLS handshake, certificate detail and protocol support."""

    module = ModuleName.TLS

    def run(self, target: Target, config: ScanConfig, store: EvidenceStore) -> ModuleResult:
        if target.scheme != "https":
            observation = store.record_observation(
                self.module,
                "tls_not_applicable",
                False,
                metadata={"reason": "Target scheme is http; TLS assessment does not apply."},
            )
            return ModuleResult(
                module=self.module,
                status=ModuleStatus.SKIPPED,
                duration_ms=0.0,
                observation_ids=[observation.observation_id],
            )

        stopwatch = Stopwatch()
        observation_ids: list[str] = []
        errors: list[str] = []

        with stopwatch:
            handshake_ids, der_certificate, handshake_ok = self._collect_primary_handshake(
                target, config, store, errors
            )
            observation_ids += handshake_ids

            if der_certificate is not None:
                observation_ids += self._collect_certificate_fields(der_certificate, target, store)
                observation_ids += self._collect_hostname_match(der_certificate, target, store)

            observation_ids += self._collect_trust_chain_validation(target, config, store, errors)
            observation_ids += self._collect_protocol_support(target, config, store)

        status = ModuleStatus.COMPLETED if handshake_ok else ModuleStatus.ERROR
        if handshake_ok and errors:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            module=self.module,
            status=status,
            duration_ms=stopwatch.elapsed_ms,
            observation_ids=observation_ids,
            errors=errors,
        )

    # -- Primary handshake (RT-012) ------------------------------------------------

    def _collect_primary_handshake(
        self,
        target: Target,
        config: ScanConfig,
        store: EvidenceStore,
        errors: list[str],
    ) -> tuple[list[str], bytes | None, bool]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(ALPN_PREFERENCE)

        handshake_timer = Stopwatch()
        try:
            with handshake_timer:
                raw_socket = socket.create_connection((target.host, target.port), timeout=config.timeout_seconds)
                with context.wrap_socket(raw_socket, server_hostname=target.host) as tls_socket:
                    negotiated_protocol = tls_socket.version()
                    cipher_name, cipher_protocol, cipher_bits = tls_socket.cipher() or (
                        None,
                        None,
                        None,
                    )
                    alpn_protocol = tls_socket.selected_alpn_protocol()
                    der_certificate = tls_socket.getpeercert(binary_form=True)
        except TimeoutError:
            errors.append("TLS handshake timed out.")
            return [], None, False
        except ssl.SSLError as exc:
            errors.append(f"TLS handshake failed: {exc}")
            return [], None, False
        except OSError as exc:
            errors.append(f"TLS connection failed: {exc}")
            return [], None, False

        ids: list[str] = []
        for observation_type, value in (
            ("sni", target.host),
            ("negotiated_protocol", negotiated_protocol),
            (
                "negotiated_cipher",
                {"name": cipher_name, "protocol": cipher_protocol, "bits": cipher_bits},
            ),
            ("alpn_protocol", alpn_protocol),
            ("handshake_duration_ms", round(handshake_timer.elapsed_ms, 2)),
        ):
            observation, evidence = store.record_observation_with_evidence(
                self.module,
                observation_type,
                value,
                source_method="ssl.SSLContext.wrap_socket",
                sanitized_raw={"value": value},
            )
            ids += [observation.observation_id, evidence.evidence_id]

        return ids, der_certificate, True

    # -- Certificate parsing (RT-013) ------------------------------------------------

    def _collect_certificate_fields(self, der_certificate: bytes, target: Target, store: EvidenceStore) -> list[str]:
        fields = _parse_certificate(der_certificate)
        observation, evidence = store.record_observation_with_evidence(
            self.module,
            "certificate",
            {
                "subject": fields.subject,
                "issuer": fields.issuer,
                "subject_alternative_names": fields.subject_alternative_names,
                "not_valid_before": fields.not_valid_before.isoformat(),
                "not_valid_after": fields.not_valid_after.isoformat(),
                "days_remaining": fields.days_remaining,
                "fingerprint_sha256": fields.fingerprint_sha256,
                "signature_algorithm": fields.signature_algorithm,
                "public_key_algorithm": fields.public_key_algorithm,
                "public_key_size_bits": fields.public_key_size_bits,
            },
            source_method="cryptography.x509.load_der_x509_certificate",
            sanitized_raw={
                "fingerprint_sha256": fields.fingerprint_sha256,
                "subject": fields.subject,
            },
        )
        return [observation.observation_id, evidence.evidence_id]

    def _collect_hostname_match(self, der_certificate: bytes, target: Target, store: EvidenceStore) -> list[str]:
        fields = _parse_certificate(der_certificate)
        matched_name = _match_hostname(target.host, fields.subject_alternative_names)
        observation, evidence = store.record_observation_with_evidence(
            self.module,
            "hostname_match",
            {"matches": matched_name is not None, "matched_name": matched_name},
            source_method="manual SAN comparison (independent of trust-chain validation)",
            sanitized_raw={"host": target.host, "matched_name": matched_name},
        )
        return [observation.observation_id, evidence.evidence_id]

    # -- Trust chain validation (RT-014) ------------------------------------------------

    def _collect_trust_chain_validation(
        self,
        target: Target,
        config: ScanConfig,
        store: EvidenceStore,
        errors: list[str],
    ) -> list[str]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            raw_socket = socket.create_connection((target.host, target.port), timeout=config.timeout_seconds)
            with context.wrap_socket(raw_socket, server_hostname=target.host):
                pass
            trust_valid = True
            failure_category = None
            failure_message = None
        except ssl.SSLCertVerificationError as exc:
            trust_valid = False
            failure_category = _categorize_trust_failure(str(exc))
            failure_message = str(exc)
        except (TimeoutError, ssl.SSLError, OSError) as exc:
            observation = store.record_observation(
                self.module,
                "trust_chain_valid",
                None,
                confidence=Confidence.UNKNOWN,
                metadata={"reason": f"Trust-chain check could not complete: {exc}"},
            )
            errors.append(f"Trust-chain validation could not complete: {exc}")
            return [observation.observation_id]

        observation, evidence = store.record_observation_with_evidence(
            self.module,
            "trust_chain_valid",
            trust_valid,
            source_method="ssl.create_default_context (system trust store)",
            metadata={"failure_category": failure_category},
            sanitized_raw={
                "failure_category": failure_category,
                "failure_message": failure_message,
            },
        )
        return [observation.observation_id, evidence.evidence_id]

    # -- Protocol support probing (RT-015) ------------------------------------------------

    def _collect_protocol_support(self, target: Target, config: ScanConfig, store: EvidenceStore) -> list[str]:
        results: dict[str, dict[str, Any]] = {}
        for attribute_name, display_name in _PROBED_PROTOCOLS:
            results[display_name] = self._probe_single_protocol(target, config, attribute_name, display_name)

        observation, evidence = store.record_observation_with_evidence(
            self.module,
            "protocol_support",
            results,
            source_method="ssl.SSLContext(minimum_version=maximum_version=<probed>)",
            confidence=Confidence.OBSERVED,
            sanitized_raw={"protocol_support": results},
        )
        return [observation.observation_id, evidence.evidence_id]

    def _probe_single_protocol(
        self, target: Target, config: ScanConfig, attribute_name: str, display_name: str
    ) -> dict[str, Any]:
        try:
            protocol_version = getattr(ssl.TLSVersion, attribute_name)
        except AttributeError:
            return {
                "tested": False,
                "supported": None,
                "reason": "runtime does not define this protocol",
            }

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = protocol_version
            context.maximum_version = protocol_version
        except (ValueError, OSError):
            return {
                "tested": False,
                "supported": None,
                "reason": "local TLS runtime refuses to negotiate this protocol version",
            }

        try:
            raw_socket = socket.create_connection((target.host, target.port), timeout=config.timeout_seconds)
            with context.wrap_socket(raw_socket, server_hostname=target.host):
                pass
            return {"tested": True, "supported": True, "reason": None}
        except ssl.SSLError as exc:
            reason = str(exc)
            note = None
            if attribute_name in _LEGACY_PROTOCOLS:
                note = (
                    "Local OpenSSL security policy may also reject this legacy protocol independent of server support."
                )
            return {"tested": True, "supported": False, "reason": reason, "note": note}
        except TimeoutError:
            return {"tested": False, "supported": None, "reason": "probe timed out"}
        except OSError as exc:
            return {"tested": False, "supported": None, "reason": f"connection failed: {exc}"}


def _parse_certificate(der_certificate: bytes) -> _CertificateFields:
    certificate = x509.load_der_x509_certificate(der_certificate)

    not_valid_before = _as_utc(getattr(certificate, "not_valid_before_utc", None) or certificate.not_valid_before)
    not_valid_after = _as_utc(getattr(certificate, "not_valid_after_utc", None) or certificate.not_valid_after)
    days_remaining = (not_valid_after - datetime.now(timezone.utc)).days

    try:
        san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    fingerprint_sha256 = hashlib.sha256(der_certificate).hexdigest()
    public_key = certificate.public_key()
    algorithm_name, key_size = _describe_public_key(public_key)

    return _CertificateFields(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        subject_alternative_names=sans,
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        days_remaining=days_remaining,
        fingerprint_sha256=fingerprint_sha256,
        signature_algorithm=certificate.signature_algorithm_oid._name,
        public_key_algorithm=algorithm_name,
        public_key_size_bits=key_size,
    )


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _describe_public_key(public_key: Any) -> tuple[str, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC ({public_key.curve.name})", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    return public_key.__class__.__name__, None


def _match_hostname(hostname: str, candidate_names: list[str]) -> str | None:
    hostname = hostname.lower()
    for candidate in candidate_names:
        pattern = candidate.lower()
        if fnmatch(hostname, pattern):
            return candidate
    return None


def _categorize_trust_failure(verify_message: str) -> str:
    message = verify_message.lower()
    if "self signed" in message or "self-signed" in message:
        return "self_signed"
    if "unable to get local issuer certificate" in message or "unable to get issuer certificate" in message:
        return "incomplete_chain"
    if "certificate has expired" in message:
        return "expired"
    if "certificate is not yet valid" in message:
        return "not_yet_valid"
    if "hostname mismatch" in message:
        return "hostname_mismatch"
    return "other"
