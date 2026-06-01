"""JSON output — serialises all inspection data to a single JSON string.

Callers receive the string and decide whether to print or pipe it.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import CertInfo, Flag, TLSInfo


def render(
    host: str,
    port: int,
    cert: CertInfo,
    chain: list[CertInfo],
    tls: TLSInfo,
    flags: list[Flag],
    exit_code: int,
) -> str:
    data: dict[str, Any] = {
        "host": host,
        "port": port,
        "certificate": cert.to_dict(),
        "chain": [c.to_dict() for c in chain],
        "tls": tls.to_dict(),
        "flags": [f.to_dict() for f in flags],
        "exit_code": exit_code,
    }
    return json.dumps(data, indent=2, default=str)
