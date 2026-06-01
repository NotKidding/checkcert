"""Security checks — each check is a small private function that returns a list of Flags.

To add a new check:
  1. Write a _check_<name>(…) -> list[Flag] function below.
  2. Call it inside run_checks() and extend the flags list.
"""

from __future__ import annotations

from .constants import (
    CRITICAL_DAYS,
    DEPRECATED_TLS,
    EXIT_CRITICAL,
    EXIT_OK,
    EXIT_WARN,
    MIN_EC_BITS,
    MIN_RSA_BITS,
    WARN_DAYS,
    WEAK_SIG_ALGOS,
)
from .models import LEVEL_CRITICAL, LEVEL_INFO, LEVEL_WARN, CertInfo, Flag, TLSInfo


def run_checks(
    cert: CertInfo,
    tls: TLSInfo,
    host: str,
    chain_len: int,
) -> list[Flag]:
    """Run all checks and return a combined list of Flag objects."""
    flags: list[Flag] = []
    flags.extend(_check_expiry(cert.days_left))
    flags.extend(_check_self_signed(cert))
    flags.extend(_check_hostname(host, cert))
    flags.extend(_check_key_strength(cert))
    flags.extend(_check_sig_algorithm(cert))
    flags.extend(_check_tls_version(tls))
    flags.extend(_check_chain_completeness(chain_len, cert))
    flags.extend(_check_wildcard(cert))
    return flags


def exit_code(flags: list[Flag]) -> int:
    """Map the worst flag level to a Unix exit code."""
    levels = {f.level for f in flags}
    if LEVEL_CRITICAL in levels:
        return EXIT_CRITICAL
    if LEVEL_WARN in levels:
        return EXIT_WARN
    return EXIT_OK


def cert_covers_host(host: str, sans: list[str], cn: str) -> bool:
    """Return True if host is covered by SANs (RFC 6125), with CN as fallback."""
    candidates = sans if sans else [f"DNS:{cn}"]
    for entry in candidates:
        if entry.startswith("DNS:") and _matches_pattern(host, entry[4:]):
            return True
        if entry.startswith("IP:") and host.lower() == entry[3:].lower():
            return True
    return False


# ── Individual checks (one concern each) ────────────────────────────────────

def _check_expiry(days: int) -> list[Flag]:
    if days < 0:
        return [Flag(LEVEL_CRITICAL, f"Certificate EXPIRED {abs(days)} days ago")]
    if days < CRITICAL_DAYS:
        label = "day" if days == 1 else "days"
        return [Flag(LEVEL_CRITICAL, f"Expires in {days} {label} — CRITICAL")]
    if days < WARN_DAYS:
        return [Flag(LEVEL_WARN, f"Expires in {days} days")]
    return []


def _check_self_signed(cert: CertInfo) -> list[Flag]:
    if cert.is_self_signed:
        return [Flag(LEVEL_CRITICAL, "Self-signed certificate")]
    return []


def _check_hostname(host: str, cert: CertInfo) -> list[Flag]:
    cn = cert.subject.get("CN", "")
    if not cert_covers_host(host, cert.sans, cn):
        return [Flag(LEVEL_CRITICAL, f"Hostname mismatch — cert does not cover {host!r}")]
    return []


def _check_key_strength(cert: CertInfo) -> list[Flag]:
    key = cert.key
    bits = key.bits
    if key.type == "RSA" and bits and bits < MIN_RSA_BITS:
        return [Flag(LEVEL_WARN, f"Weak RSA key: {bits} bits (minimum {MIN_RSA_BITS})")]
    if key.type == "EC" and bits and bits < MIN_EC_BITS:
        return [Flag(LEVEL_WARN, f"Weak EC key: {bits} bits (minimum {MIN_EC_BITS})")]
    return []


def _check_sig_algorithm(cert: CertInfo) -> list[Flag]:
    if cert.sig_alg in WEAK_SIG_ALGOS:
        return [Flag(LEVEL_WARN, f"Weak/deprecated signature algorithm: {cert.sig_alg}")]
    return []


def _check_tls_version(tls: TLSInfo) -> list[Flag]:
    if tls.version in DEPRECATED_TLS:
        return [Flag(LEVEL_WARN, f"Deprecated TLS version: {tls.version}")]
    return []


def _check_chain_completeness(chain_len: int, cert: CertInfo) -> list[Flag]:
    if chain_len == 1 and not cert.is_self_signed:
        return [Flag(LEVEL_WARN, "Incomplete chain — no intermediate certificates sent by server")]
    return []


def _check_wildcard(cert: CertInfo) -> list[Flag]:
    is_wildcard = (
        any(s.startswith("DNS:*.") for s in cert.sans)
        or cert.subject.get("CN", "").startswith("*.")
    )
    if is_wildcard:
        return [Flag(LEVEL_INFO, "Wildcard certificate")]
    return []


# ── Hostname matching ────────────────────────────────────────────────────────

def _matches_pattern(host: str, pattern: str) -> bool:
    """RFC 6125 wildcard match — wildcard must not span DNS labels."""
    host, pattern = host.lower(), pattern.lower()
    if not pattern.startswith("*."):
        return host == pattern
    suffix = pattern[1:]  # ".example.com"
    if not host.endswith(suffix):
        return False
    prefix = host[: len(host) - len(suffix)]
    return "." not in prefix  # wildcard covers exactly one label
