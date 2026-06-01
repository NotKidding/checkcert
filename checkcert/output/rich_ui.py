"""Rich terminal renderer.

The PALETTE dict at the top controls every colour used in the UI.
Change values there to restyle the entire output without touching render logic.

To add a new display section:
  1. Write a _<name>_panel(…) -> Panel function.
  2. Call console.print(_<name>_panel(…)) inside render().
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..constants import CRITICAL_DAYS, WARN_DAYS
from ..models import LEVEL_CRITICAL, LEVEL_INFO, LEVEL_WARN, CertInfo, Flag, TLSInfo

# ── Colour palette ───────────────────────────────────────────────────────────
# Edit these strings (Rich markup colour names) to restyle the whole UI.
PALETTE: dict[str, str] = {
    "panel_border": "blue",
    "ok_border":    "green",
    "warn_border":  "yellow",
    "crit_border":  "red",
    "field_name":   "bold cyan",
    "ok":           "green",
    "warn":         "bold yellow",
    "crit":         "bold red",
    "info":         "cyan",
}

_ICON: dict[str, str] = {
    LEVEL_CRITICAL: f"[{PALETTE['crit']}]✗[/{PALETTE['crit']}]",
    LEVEL_WARN:     f"[{PALETTE['warn']}]⚠[/{PALETTE['warn']}]",
    LEVEL_INFO:     f"[{PALETTE['info']}]ℹ[/{PALETTE['info']}]",
}


# ── Public entry point ───────────────────────────────────────────────────────

def render(
    cert: CertInfo,
    chain: list[CertInfo],
    tls: TLSInfo,
    flags: list[Flag],
    quiet: bool,
    console: Console,
) -> None:
    """Print all sections to console. In quiet mode only the flags panel is shown,
    and only when there are actual warnings or errors (CI-friendly: exit 0 = silent)."""
    if not quiet:
        console.print(_cert_panel(cert))
        console.print(_tls_panel(tls))
        console.print(_chain_panel(chain))

    if flags or not quiet:
        console.print(_flags_panel(flags))


# ── Section builders ─────────────────────────────────────────────────────────

def _cert_panel(cert: CertInfo) -> Panel:
    t = _kv_table()
    _row(t, "Subject CN", cert.subject.get("CN", "—"))
    _opt_row(t, "Subject O",  cert.subject.get("O"))
    _opt_row(t, "Subject OU", cert.subject.get("OU"))
    _row(t, "Issuer CN",  cert.issuer.get("CN", "—"))
    _opt_row(t, "Issuer O", cert.issuer.get("O"))
    _row(t, "Serial",     cert.serial)
    _row(t, "Not Before", cert.not_before)
    _row(t, "Not After",  cert.not_after)
    _row(t, "Expiry",     _expiry_markup(cert.days_left))
    _row(t, "SANs",       "\n".join(cert.sans) if cert.sans else "—")
    _row(t, "Key",        _key_label(cert))
    _row(t, "Sig Algorithm", cert.sig_alg)
    return Panel(t, title="[bold]CERTIFICATE DETAILS[/bold]", border_style=PALETTE["panel_border"])


def _tls_panel(tls: TLSInfo) -> Panel:
    t = _kv_table()
    _row(t, "Version",      tls.version or "—")
    _row(t, "Cipher Suite", tls.cipher  or "—")
    if tls.bits:
        _row(t, "Cipher Bits", str(tls.bits))
    return Panel(t, title="[bold]TLS CONNECTION[/bold]", border_style=PALETTE["panel_border"])


def _chain_panel(chain: list[CertInfo]) -> Panel:
    t = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
    t.add_column("#",          style=PALETTE["field_name"], no_wrap=True)
    t.add_column("Subject CN")
    t.add_column("Issuer CN")
    t.add_column("Expires")
    for i, ci in enumerate(chain):
        label = "[bold]leaf[/bold]" if i == 0 else str(i)
        t.add_row(
            label,
            ci.subject.get("CN", "—"),
            ci.issuer.get("CN",  "—"),
            _expiry_markup(ci.days_left),
        )
    return Panel(t, title="[bold]CHAIN INFO[/bold]", border_style=PALETTE["panel_border"])


def _flags_panel(flags: list[Flag]) -> Panel:
    if not flags:
        body = f"[{PALETTE['ok']}]✓ No issues found[/{PALETTE['ok']}]"
        return Panel(body, title="[bold]SECURITY FLAGS[/bold]", border_style=PALETTE["ok_border"])
    lines = [f"{_ICON.get(f.level, '?')} {f.msg}" for f in flags]
    has_crit = any(f.level == LEVEL_CRITICAL for f in flags)
    border = PALETTE["crit_border"] if has_crit else PALETTE["warn_border"]
    return Panel("\n".join(lines), title="[bold]SECURITY FLAGS[/bold]", border_style=border)


# ── Table helpers ────────────────────────────────────────────────────────────

def _kv_table() -> Table:
    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    t.add_column("field", style=PALETTE["field_name"], no_wrap=True)
    t.add_column("value")
    return t


def _row(t: Table, label: str, value: str) -> None:
    t.add_row(label, value)


def _opt_row(t: Table, label: str, value: str | None) -> None:
    if value:
        t.add_row(label, value)


# ── Formatting helpers ───────────────────────────────────────────────────────

def _expiry_markup(days: int) -> str:
    if days < 0:
        return f"[{PALETTE['crit']}]EXPIRED {abs(days)} days ago[/{PALETTE['crit']}]"
    if days < CRITICAL_DAYS:
        return f"[{PALETTE['crit']}]{days} days remaining[/{PALETTE['crit']}]"
    if days < WARN_DAYS:
        return f"[{PALETTE['warn']}]{days} days remaining[/{PALETTE['warn']}]"
    return f"[{PALETTE['ok']}]{days} days remaining[/{PALETTE['ok']}]"


def _key_label(cert: CertInfo) -> str:
    key = cert.key
    label = f"{key.type} {key.bits}-bit" if key.bits else key.type
    if key.curve:
        label += f" ({key.curve})"
    return label
