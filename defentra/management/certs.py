"""Server certificate bootstrap for TLS fleet deployments.

Generates a self-signed server certificate suitable for small fleets: the
same file acts as both the server cert/key AND the CA anchor clients pin
(`defentra agent pair --ca-cert server.crt`). For larger deployments,
replace with certs from your internal PKI — clients accept any chain that
validates against the pinned --ca-cert.
"""

from __future__ import annotations

import datetime
import os
import socket


def generate_server_cert(
    out_dir: str,
    hostname: str = socket.gethostname(),
    days: int = 825,
    key_size: int = 3072,
) -> tuple:
    """Write server.crt / server.key into out_dir; returns (cert, key) paths."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    from cryptography.x509.oid import NameOID

    os.makedirs(out_dir, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Defentra Fleet"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    san = x509.SubjectAlternativeName(
        [x509.DNSName(hostname), x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed: cert doubles as the trust anchor
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(san, critical=False)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = os.path.join(out_dir, "server.crt")
    key_path = os.path.join(out_dir, "server.key")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(Encoding.PEM))
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return cert_path, key_path


def ip_address(text: str):
    import ipaddress

    return ipaddress.ip_address(text)
