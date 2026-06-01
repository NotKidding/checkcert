"""Shared data types passed between all modules.

Adding a new field to CertInfo or TLSInfo only requires changing this file
and updating the parser — the output and check layers consume these types.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

# ── Flag severity constants ──────────────────────────────────────────────────
LEVEL_CRITICAL = "critical"
LEVEL_WARN = "warn"
LEVEL_INFO = "info"


@dataclass
class KeyInfo:
    """Public key metadata extracted from a certificate."""

    type: str            # RSA | EC | DSA | Ed25519 | Ed448 | Unknown
    bits: Optional[int]  # None for algorithms with fixed key size (Ed25519 etc.)
    curve: Optional[str] = None  # EC curve name, e.g. secp256r1

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.type, "bits": self.bits}
        if self.curve:
            d["curve"] = self.curve
        return d


@dataclass
class CertInfo:
    """All parsed fields from a single X.509 certificate."""

    subject: dict[str, str]   # short-name keys: CN, O, OU, C, …
    issuer: dict[str, str]
    serial: str               # colon-separated uppercase hex
    not_before: str           # ISO 8601
    not_after: str            # ISO 8601
    days_left: int            # negative means already expired
    sans: list[str]           # ["DNS:example.com", "IP:1.2.3.4", …]
    key: KeyInfo
    sig_alg: str
    is_self_signed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_left": self.days_left,
            "sans": self.sans,
            "key": self.key.to_dict(),
            "sig_alg": self.sig_alg,
            "is_self_signed": self.is_self_signed,
        }


@dataclass
class TLSInfo:
    """Negotiated TLS session details."""

    version: str        # e.g. TLSv1.3
    cipher: str         # e.g. TLS_AES_256_GCM_SHA384
    bits: Optional[int] # effective cipher key bits

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "cipher": self.cipher, "bits": self.bits}


@dataclass
class Flag:
    """A single security check result."""

    level: str  # LEVEL_CRITICAL | LEVEL_WARN | LEVEL_INFO
    msg: str

    def to_dict(self) -> dict[str, str]:
        return {"level": self.level, "msg": self.msg}
