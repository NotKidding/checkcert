"""TLS connection layer — parse the target string, open a socket, run the handshake.

This module is the only place that touches raw sockets and OpenSSL. Everything
above it works with the typed models returned from fetch_cert_chain().
"""

from __future__ import annotations

import select
import socket
import time
from urllib.parse import urlparse

import OpenSSL.SSL
import OpenSSL.crypto

from .models import TLSInfo


def parse_target(raw: str) -> tuple[str, int]:
    """Return (host, port) from a bare domain, domain:port, or full URL."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        raise ValueError(f"Cannot parse host from {raw!r}")
    return host, port


def fetch_cert_chain(
    host: str, port: int, timeout: float
) -> tuple[list[OpenSSL.crypto.X509], TLSInfo]:
    """Open a TLS connection using SNI and return (cert_chain, tls_info).

    Certificate verification is intentionally disabled so we can inspect
    expired, self-signed, and otherwise invalid certificates.
    Chain order is leaf-first.
    """
    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda *_: True)

    raw_sock = socket.create_connection((host, port), timeout=timeout)
    raw_sock.settimeout(timeout)

    conn = OpenSSL.SSL.Connection(ctx, raw_sock)
    conn.set_tlsext_host_name(host.encode())  # SNI
    conn.set_connect_state()

    _do_handshake(conn, raw_sock, timeout)

    try:
        chain = conn.get_peer_cert_chain() or []
        tls = TLSInfo(
            version=conn.get_protocol_version_name() or "Unknown",
            cipher=conn.get_cipher_name() or "Unknown",
            bits=conn.get_cipher_bits(),
        )
    finally:
        try:
            conn.shutdown()
        except Exception:
            pass
        raw_sock.close()

    return chain, tls


# ── Private helpers ──────────────────────────────────────────────────────────

def _do_handshake(
    conn: OpenSSL.SSL.Connection,
    raw_sock: socket.socket,
    timeout: float,
) -> None:
    """Drive the TLS handshake, retrying on WantRead/WantWrite.

    Blocking sockets should complete in one call; the retry loop exists as a
    safety net for servers that require multiple round-trips.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            conn.do_handshake()
            return
        except OpenSSL.SSL.WantReadError:
            _wait(raw_sock, readable=True, deadline=deadline)
        except OpenSSL.SSL.WantWriteError:
            _wait(raw_sock, readable=False, deadline=deadline)


def _wait(sock: socket.socket, readable: bool, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("TLS handshake timed out")
    if readable:
        select.select([sock], [], [], remaining)
    else:
        select.select([], [sock], [], remaining)
