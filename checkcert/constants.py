"""All tunable thresholds and static look-up tables.

Adjust the values here to change tool behaviour without touching any logic.
"""

__version__ = "1.0.0"

# ── Exit codes ───────────────────────────────────────────────────────────────
EXIT_OK = 0
EXIT_WARN = 1
EXIT_CRITICAL = 2

# ── Expiry thresholds (days) ─────────────────────────────────────────────────
WARN_DAYS = 30
CRITICAL_DAYS = 7

# ── Minimum acceptable public key sizes ─────────────────────────────────────
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256

# ── Deprecated / weak signature algorithms ──────────────────────────────────
WEAK_SIG_ALGOS: frozenset[str] = frozenset({
    "md2WithRSAEncryption",
    "md5WithRSAEncryption",
    "sha1WithRSAEncryption",
    "sha1WithRSASignature",
    "ecdsa-with-SHA1",
})

# ── TLS versions considered deprecated ──────────────────────────────────────
DEPRECATED_TLS: frozenset[str] = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})

# ── X.509 OID → short abbreviation (used when rendering DN fields) ───────────
OID_SHORT: dict[str, str] = {
    "commonName": "CN",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "localityName": "L",
    "stateOrProvinceName": "ST",
    "countryName": "C",
    "emailAddress": "email",
    "serialNumber": "serialNumber",
}
