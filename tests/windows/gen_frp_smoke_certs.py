#!/usr/bin/env python3
"""Generate ephemeral CA + leaf (IP SAN 127.0.0.1) for Windows FRP smoke.

Writes:
  ca.crt  (DER)
  leaf.pfx (PKCS#12)
  leaf.pass (ascii password)
  status.txt (paths)

Uses the cryptography package (provisioned by the Windows smoke workflow step).
No OpenSSL CLI required.
"""
from __future__ import annotations

import argparse
import datetime as dt
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DRLink FRP Smoke CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(hours=6))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
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
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        # Use the issued CA subject bytes exactly (Name object identity matters for chain).
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(hours=6))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    ca_der = out / "ca.crt"
    ca_der.write_bytes(ca_cert.public_bytes(serialization.Encoding.DER))
    ca_pem = out / "ca.pem"
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    leaf_der = out / "leaf.crt"
    leaf_der.write_bytes(leaf_cert.public_bytes(serialization.Encoding.DER))
    leaf_pem = out / "leaf.pem"
    leaf_pem.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    leaf_key_pem = out / "leaf.key"
    leaf_key_pem.write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    password = secrets.token_hex(16)
    pfx = pkcs12.serialize_key_and_certificates(
        name=b"drlink-frp-smoke",
        key=leaf_key,
        cert=leaf_cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("ascii")),
    )
    leaf_pfx = out / "leaf.pfx"
    leaf_pfx.write_bytes(pfx)
    pass_path = out / "leaf.pass"
    pass_path.write_text(password + "\n", encoding="ascii")

    status = out / "status.txt"
    status.write_text(
        "\n".join(
            [
                "CA_DER=%s" % ca_der,
                "LEAF_DER=%s" % leaf_der,
                "LEAF_PEM=%s" % leaf_pem,
                "LEAF_KEY=%s" % leaf_key_pem,
                "LEAF_PFX=%s" % leaf_pfx,
                "LEAF_PASS=%s" % pass_path,
                "",
            ]
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
