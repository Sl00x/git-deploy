"""Internal PKI used for agent <-> control plane mutual TLS.

The control plane owns a private CA. Agents generate their key locally and
only ever send a CSR; the CA signs the public key with a subject chosen by the
control plane (never by the CSR). Agent identity = SHA-256 fingerprint of the
presented client certificate, looked up in the database (revocation = removal).
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

AGENT_URI_PREFIX = "urn:udeploy:host:"


class PKIError(Exception):
    pass


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def key_to_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def load_key(pem: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise PKIError("expected an EC private key")
    return key


def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def load_cert(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)


def fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def fingerprint(cert: x509.Certificate) -> str:
    return fingerprint_der(cert.public_bytes(serialization.Encoding.DER))


def create_ca(common_name: str = "udeploy internal CA", days: int = 3650) -> tuple[bytes, bytes]:
    key = _key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key_to_pem(key), cert_to_pem(cert)


def _leaf(
    ca_key_pem: bytes,
    ca_cert_pem: bytes,
    public_key: ec.EllipticCurvePublicKey,
    common_name: str,
    san: list[x509.GeneralName],
    usage: x509.ObjectIdentifier,
    days: int,
) -> bytes:
    ca_key = load_key(ca_key_pem)
    ca_cert = load_cert(ca_cert_pem)
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert_to_pem(cert)


def sign_agent_csr(
    ca_key_pem: bytes, ca_cert_pem: bytes, csr_pem: bytes, host_id: str, days: int = 90
) -> bytes:
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except ValueError as exc:
        raise PKIError("invalid CSR") from exc
    if not csr.is_signature_valid:
        raise PKIError("CSR signature invalid")
    public_key = csr.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or public_key.curve.key_size < 256:
        raise PKIError("agent keys must be EC P-256 or stronger")
    return _leaf(
        ca_key_pem,
        ca_cert_pem,
        public_key,
        f"udeploy-agent-{host_id}",
        [x509.UniformResourceIdentifier(AGENT_URI_PREFIX + host_id)],
        ExtendedKeyUsageOID.CLIENT_AUTH,
        days,
    )


def issue_server_cert(
    ca_key_pem: bytes, ca_cert_pem: bytes, dns_names: list[str], ips: list[str] | None = None, days: int = 365
) -> tuple[bytes, bytes]:
    key = _key()
    san: list[x509.GeneralName] = [x509.DNSName(n) for n in dns_names]
    san += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips or []]
    cert = _leaf(
        ca_key_pem, ca_cert_pem, key.public_key(), dns_names[0], san, ExtendedKeyUsageOID.SERVER_AUTH, days
    )
    return key_to_pem(key), cert


def make_csr(key_pem: bytes, common_name: str) -> bytes:
    key = load_key(key_pem)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def new_private_key_pem() -> bytes:
    return key_to_pem(_key())


def host_id_from_cert(cert: x509.Certificate) -> str | None:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith(AGENT_URI_PREFIX):
            return uri[len(AGENT_URI_PREFIX) :]
    return None


def not_after(cert: x509.Certificate) -> datetime:
    return cert.not_valid_after_utc
