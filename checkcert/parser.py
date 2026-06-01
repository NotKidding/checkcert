"""X.509 certificate field extraction.

Converts a raw pyOpenSSL X509 object into a typed CertInfo dataclass.
Uses the `cryptography` library (via .to_cryptography()) for richer parsing
of SANs, key types, and subject/issuer DN attributes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import OpenSSL.crypto
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from .constants import OID_SHORT
from .models import CertInfo, KeyInfo


def parse_cert(openssl_cert: OpenSSL.crypto.X509) -> CertInfo:
    """Extract all certificate fields into a CertInfo dataclass."""
    crypto_cert = openssl_cert.to_cryptography()

    not_before = _parse_asn1_date(openssl_cert.get_notBefore())
    not_after = _parse_asn1_date(openssl_cert.get_notAfter())
    days_left = (not_after - datetime.now(timezone.utc)).days

    return CertInfo(
        subject=_name_to_dict(crypto_cert.subject),
        issuer=_name_to_dict(crypto_cert.issuer),
        serial=_serial_to_hex(openssl_cert.get_serial_number()),
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        days_left=days_left,
        sans=_get_sans(crypto_cert),
        key=_get_key_info(crypto_cert),
        sig_alg=openssl_cert.get_signature_algorithm().decode(),
        is_self_signed=(crypto_cert.subject == crypto_cert.issuer),
    )


# ── Private helpers ──────────────────────────────────────────────────────────

def _parse_asn1_date(raw: Optional[bytes]) -> datetime:
    if raw is None:
        raise ValueError("Certificate is missing a validity date field")
    return datetime.strptime(raw.decode(), "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)


def _name_to_dict(name: Any) -> dict[str, str]:
    return {OID_SHORT.get(attr.oid._name, attr.oid._name): attr.value for attr in name}


def _get_sans(crypto_cert: x509.Certificate) -> list[str]:
    try:
        ext = crypto_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        entries: list[str] = []
        for dns in ext.value.get_values_for_type(x509.DNSName):
            entries.append(f"DNS:{dns}")
        for ip in ext.value.get_values_for_type(x509.IPAddress):
            entries.append(f"IP:{ip}")
        return entries
    except x509.ExtensionNotFound:
        return []


def _get_key_info(crypto_cert: x509.Certificate) -> KeyInfo:
    pub = crypto_cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return KeyInfo(type="RSA", bits=pub.key_size)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return KeyInfo(type="EC", bits=pub.key_size, curve=pub.curve.name)
    if isinstance(pub, dsa.DSAPublicKey):
        return KeyInfo(type="DSA", bits=pub.key_size)
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return KeyInfo(type="Ed25519", bits=256)
    if isinstance(pub, ed448.Ed448PublicKey):
        return KeyInfo(type="Ed448", bits=448)
    return KeyInfo(type="Unknown", bits=None)


def _serial_to_hex(n: int) -> str:
    h = format(n, "x").upper()
    if len(h) % 2:
        h = "0" + h
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))
