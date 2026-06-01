"""CLI entry point — argument parsing and the main() function.

main() is the single place that orchestrates all other modules:
  parse target → connect → parse cert → run checks → render output → exit.
"""

from __future__ import annotations

import argparse
import socket

from rich.console import Console

from .checks import exit_code, run_checks
from .connection import fetch_cert_chain, parse_target
from .constants import EXIT_CRITICAL, __version__
from .output import render_json, render_rich
from .parser import parse_cert


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="checkcert",
        description="Inspect SSL/TLS certificates for any domain.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  checkcert.py example.com\n"
            "  checkcert.py example.com:8443\n"
            "  checkcert.py https://example.com --timeout 10\n"
            "  checkcert.py example.com --json\n"
            "  checkcert.py example.com --quiet\n"
        ),
    )
    parser.add_argument("target", help="Domain, domain:port, or URL to inspect")
    parser.add_argument(
        "--timeout", type=float, default=5.0, metavar="SECS",
        help="Connection timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--json", dest="json_out", action="store_true",
        help="Output raw JSON",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Only show warnings/errors — silent on success (CI-friendly)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    console = Console()
    err = Console(stderr=True)

    # ── Parse target ─────────────────────────────────────────────────────────
    try:
        host, port = parse_target(args.target)
    except ValueError as exc:
        err.print(f"[bold red]Error:[/bold red] {exc}")
        return EXIT_CRITICAL

    if not args.json_out and not args.quiet:
        console.print(f"\n[bold]Checking[/bold] [cyan]{host}[/cyan]:[cyan]{port}[/cyan]…\n")

    # ── Connect ───────────────────────────────────────────────────────────────
    try:
        openssl_chain, tls = fetch_cert_chain(host, port, args.timeout)
    except socket.timeout:
        err.print(f"[bold red]Timeout:[/bold red] no response from {host}:{port} within {args.timeout}s")
        return EXIT_CRITICAL
    except socket.gaierror as exc:
        err.print(f"[bold red]DNS error:[/bold red] {exc}")
        return EXIT_CRITICAL
    except ConnectionRefusedError:
        err.print(f"[bold red]Connection refused:[/bold red] {host}:{port}")
        return EXIT_CRITICAL
    except OSError as exc:
        err.print(f"[bold red]Network error:[/bold red] {exc}")
        return EXIT_CRITICAL
    except Exception as exc:
        err.print(f"[bold red]Error:[/bold red] {exc}")
        return EXIT_CRITICAL

    if not openssl_chain:
        err.print("[bold red]Error:[/bold red] server returned no certificate")
        return EXIT_CRITICAL

    # ── Parse + check ─────────────────────────────────────────────────────────
    cert = parse_cert(openssl_chain[0])
    chain = [parse_cert(c) for c in openssl_chain]
    flags = run_checks(cert, tls, host, len(openssl_chain))
    code = exit_code(flags)

    # ── Render ────────────────────────────────────────────────────────────────
    if args.json_out:
        print(render_json(host, port, cert, chain, tls, flags, code))
    else:
        render_rich(cert, chain, tls, flags, args.quiet, console)

    return code
