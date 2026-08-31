"""A minimal, self-contained local TLS/HTTP fixture server for controlled tests.

Generates certificates on the fly (valid, expired, not-yet-valid, hostname
mismatch) so TLS scanner tests never depend on live internet access or
uncontrolled third-party domains (PRD §19, RT-011).
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_CANNED_HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
)


@dataclass(frozen=True, slots=True)
class GeneratedCertificate:
    certificate_pem: bytes
    private_key_pem: bytes


def generate_self_signed_certificate(
    *,
    common_name: str,
    subject_alternative_names: list[str],
    not_valid_before: dt.datetime | None = None,
    not_valid_after: dt.datetime | None = None,
) -> GeneratedCertificate:
    """Build a throwaway self-signed certificate for a local TLS test fixture."""
    now = dt.datetime.now(dt.timezone.utc)
    not_valid_before = not_valid_before or (now - dt.timedelta(days=1))
    not_valid_after = not_valid_after or (now + dt.timedelta(days=365))

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )
    if subject_alternative_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in subject_alternative_names]),
            critical=False,
        )

    certificate = builder.sign(private_key, hashes.SHA256())

    return GeneratedCertificate(
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
        private_key_pem=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


class LocalTlsHttpServer:
    """Serves one canned HTTP/1.1 response per TLS connection on 127.0.0.1."""

    def __init__(
        self,
        certificate: GeneratedCertificate,
        *,
        minimum_version: ssl.TLSVersion | None = None,
        maximum_version: ssl.TLSVersion | None = None,
    ) -> None:
        self._certificate = certificate
        self._minimum_version = minimum_version
        self._maximum_version = maximum_version
        self._server_socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.port: int = 0

    def __enter__(self) -> LocalTlsHttpServer:
        context = self._build_server_context()
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_socket.bind(("127.0.0.1", 0))
        raw_socket.listen(5)
        raw_socket.settimeout(0.5)
        self.port = raw_socket.getsockname()[1]
        self._server_socket = context.wrap_socket(raw_socket, server_side=True)

        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._server_socket:
            self._server_socket.close()

    @property
    def host(self) -> str:
        return "127.0.0.1"

    def _build_server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp_dir:
            cert_path = Path(tmp_dir) / "cert.pem"
            key_path = Path(tmp_dir) / "key.pem"
            cert_path.write_bytes(self._certificate.certificate_pem)
            key_path.write_bytes(self._certificate.private_key_pem)
            context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        if self._minimum_version is not None:
            context.minimum_version = self._minimum_version
        if self._maximum_version is not None:
            context.maximum_version = self._maximum_version
        return context

    def _serve_forever(self) -> None:
        assert self._server_socket is not None
        while not self._stop_event.is_set():
            try:
                connection, _addr = self._server_socket.accept()
            except (TimeoutError, ssl.SSLError, OSError):
                continue
            try:
                connection.settimeout(2)
                connection.recv(4096)
                connection.sendall(_CANNED_HTTP_RESPONSE)
            except OSError:
                pass
            finally:
                connection.close()
