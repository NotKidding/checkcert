# checkcert

A fast, colour-coded SSL/TLS certificate inspector for any domain.  
Zero cost · open source · Python 3.9+ · no external services.

```
Checking example.com:443…

╭─ CERTIFICATE DETAILS ──────────────────────────────────╮
│  Subject CN    example.com                             │
│  Issuer CN     R11                                     │
│  Issuer O      Let's Encrypt                           │
│  Serial        03:AB:4F:…                              │
│  Not Before    2025-03-01T00:00:00+00:00               │
│  Not After     2025-06-01T23:59:59+00:00               │
│  Expiry        82 days remaining                       │
│  SANs          DNS:example.com                         │
│                DNS:www.example.com                     │
│  Key           EC 256-bit (secp256r1)                  │
│  Sig Algorithm ecdsa-with-SHA256                       │
╰────────────────────────────────────────────────────────╯
╭─ TLS CONNECTION ───────────────────────────────────────╮
│  Version       TLSv1.3                                 │
│  Cipher Suite  TLS_AES_256_GCM_SHA384                  │
│  Cipher Bits   256                                     │
╰────────────────────────────────────────────────────────╯
╭─ CHAIN INFO ───────────────────────────────────────────╮
│  #     Subject CN     Issuer CN       Expires          │
│  leaf  example.com    R11             82 days          │
│  1     R11            ISRG Root X1   1234 days         │
╰────────────────────────────────────────────────────────╯
╭─ SECURITY FLAGS ───────────────────────────────────────╮
│  ✓ No issues found                                     │
╰────────────────────────────────────────────────────────╯
```

---

## Requirements

- Python 3.9+
- `pyOpenSSL` · `cryptography` · `rich`

## Install

Most modern Linux distros use an externally-managed Python environment, so a
virtual environment is required.

```bash
# 1 — create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2 — install dependencies
pip install -r requirements.txt
```

To run without activating the venv each time, call the interpreter directly:

```bash
.venv/bin/python3 checkcert.py example.com
```

You can open the project in **Code - OSS** (or VS Code) and set the Python
interpreter to `.venv/bin/python3` via the command palette
(`Ctrl+Shift+P` → *Python: Select Interpreter*).

## Usage

```bash
# Bare domain (defaults to port 443)
python3 checkcert.py example.com

# Custom port
python3 checkcert.py example.com:8443

# Full URL — scheme and path are stripped automatically
python3 checkcert.py https://example.com/some/path

# Longer timeout
python3 checkcert.py example.com --timeout 10

# Machine-readable JSON (good for jq / scripting)
python3 checkcert.py example.com --json

# Quiet mode — only prints flags, silent on success (CI pipelines)
python3 checkcert.py example.com --quiet

# Also works as a module
python3 -m checkcert example.com
```

## Testing

`google.com` is a good baseline for a clean, well-configured cert.
[badssl.com](https://badssl.com) is your best friend for triggering every warning flag —
they maintain dedicated endpoints for expired, self-signed, wrong-host, weak-key, and other broken configurations.

```bash
# Clean cert — should exit 0
python3 checkcert.py google.com

# Expired certificate
python3 checkcert.py expired.badssl.com

# Self-signed certificate
python3 checkcert.py self-signed.badssl.com

# Hostname mismatch
python3 checkcert.py wrong.host.badssl.com

# Weak 1024-bit RSA key
python3 checkcert.py 1000-sans.badssl.com
```

## Flags

| Flag | Description |
|------|-------------|
| `--timeout SECS` | Connection timeout in seconds (default: `5`) |
| `--json` | Emit a single JSON object; no colour output |
| `--quiet` | Suppress all output except security flags; silent if exit 0 |
| `--version` | Print version and exit |

## Security checks

| Check | Severity |
|-------|----------|
| Certificate expired | **Critical** |
| Expires in < 7 days | **Critical** |
| Expires in < 30 days | Warning |
| Self-signed certificate | **Critical** |
| Hostname mismatch | **Critical** |
| RSA key < 2048 bits | Warning |
| EC key < 256 bits | Warning |
| MD5 / SHA-1 signature algorithm | Warning |
| TLS 1.0, 1.1, SSLv2/3 in use | Warning |
| No intermediate certificates sent | Warning |
| Wildcard certificate | Info |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | One or more warnings |
| `2` | One or more critical issues |

Use in CI:

```bash
python3 checkcert.py example.com --quiet || echo "cert problem detected"
```

## JSON output schema

```jsonc
{
  "host": "example.com",
  "port": 443,
  "certificate": {
    "subject":       { "CN": "example.com", "O": "…" },
    "issuer":        { "CN": "R11", "O": "Let's Encrypt" },
    "serial":        "03:AB:…",
    "not_before":    "2025-03-01T00:00:00+00:00",
    "not_after":     "2025-06-01T23:59:59+00:00",
    "days_left":     82,
    "sans":          ["DNS:example.com", "DNS:www.example.com"],
    "key":           { "type": "EC", "bits": 256, "curve": "secp256r1" },
    "sig_alg":       "ecdsa-with-SHA256",
    "is_self_signed": false
  },
  "chain": [ /* same shape, one entry per cert */ ],
  "tls": {
    "version": "TLSv1.3",
    "cipher":  "TLS_AES_256_GCM_SHA384",
    "bits":    256
  },
  "flags": [
    { "level": "warn", "msg": "Expires in 25 days" }
  ],
  "exit_code": 1
}
```

---

## Project structure

```
checkcert/                  ← project root
├── checkcert.py            ← entry-point shim (3 lines)
├── LICENSE                 ← MIT
├── requirements.txt
├── README.md
└── checkcert/              ← Python package (all logic lives here)
    ├── __init__.py
    ├── __main__.py         ← enables: python -m checkcert
    ├── constants.py        ← thresholds, OID map, weak-algo lists
    ├── models.py           ← CertInfo, TLSInfo, KeyInfo, Flag dataclasses
    ├── connection.py       ← TLS socket + SNI handshake
    ├── parser.py           ← X.509 field extraction
    ├── checks.py           ← security check logic (one function per check)
    ├── cli.py              ← argparse + main()
    └── output/
        ├── __init__.py     ← exports render_rich, render_json
        ├── rich_ui.py      ← colour-coded terminal renderer + PALETTE
        └── json_out.py     ← JSON serialiser
```

### Where to make common changes

| Goal | File |
|------|------|
| Change expiry thresholds | `checkcert/constants.py` |
| Add a new security check | `checkcert/checks.py` — add `_check_<name>()`, call it in `run_checks()` |
| Change colours / layout | `checkcert/output/rich_ui.py` — edit `PALETTE` or add a `_<name>_panel()` |
| Add a new output format | `checkcert/output/<format>.py`, export from `output/__init__.py` |
| Add a CLI flag | `checkcert/cli.py` — `build_parser()` |
| Add a cert field | `checkcert/models.py` + `checkcert/parser.py` |

## License

[MIT](LICENSE)
