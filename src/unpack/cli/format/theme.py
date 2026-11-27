"""Semantic Rich theme, console factory, and formatting primitives for UNPACK CLI."""

from __future__ import annotations

import os
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.theme import Theme

from unpack.i18n import get_lang, resolve_lang

# ── Semantic Color Tokens (safe on both dark & light terminals) ──────────────
C_OK = "green"
C_FAIL = "red"
C_WARN = "yellow"
C_INFO = "cyan"
C_DIM = "dim"
C_ACCENT = "magenta"
C_HEADER = "bold cyan"
C_LABEL = "bold"

UNPACK_THEME = Theme(
    {
        "ok": C_OK,
        "fail": C_FAIL,
        "warn": C_WARN,
        "info": C_INFO,
        "accent": C_ACCENT,
        "muted": C_DIM,
        "label": C_LABEL,
        "header": C_HEADER,
        "cmd": "bold cyan",
        "path": "cyan",
        "border": "dim",
        "badge.critical": "bold white on red",
        "badge.high": "bold red",
        "badge.medium": "bold yellow",
        "badge.low": "cyan",
        "badge.info": "dim",
        "badge.pass": "bold green",
        "badge.fail": "bold red",
    }
)


def create_console(
    *,
    stderr: bool = False,
    no_color: bool = False,
    quiet: bool = False,
) -> Console:
    """Create a themed Console respecting NO_COLOR, FORCE_COLOR, and --no-color."""
    env_no_color = bool(os.environ.get("NO_COLOR"))
    disable_color = no_color or env_no_color
    return Console(
        stderr=stderr,
        theme=UNPACK_THEME,
        no_color=disable_color,
        highlight=False,
        quiet=quiet,
    )


def safe(value: Any) -> str:
    """Escape Rich markup characters in untrusted strings (APK/DEX/class names)."""
    if value is None:
        return ""
    return escape(str(value))


def format_bytes(size: int | float | None) -> str:
    """Format byte counts into concise human-readable units."""
    if size is None:
        return "—"
    n = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{size} B"


def confidence_bar(value: float, width: int = 20) -> str:
    """Render a clamped proportional bar with semantic threshold coloring."""
    clamped = max(0.0, min(1.0, float(value)))
    filled = int(round(clamped * width))
    if clamped >= 0.6:
        color = C_OK
    elif clamped >= 0.3:
        color = C_WARN
    else:
        color = C_FAIL
    return f"[{color}]{'█' * filled}[/][{C_DIM}]{'░' * (width - filled)}[/]"


def render_severity_badge(level: str) -> str:
    """Render a compact severity or status badge."""
    norm = (level or "info").strip().lower()
    mapping = {
        "critical": "[badge.critical] CRIT [/]",
        "high": "[badge.high]HIGH[/]",
        "medium": "[badge.medium]MED[/]",
        "low": "[badge.low]LOW[/]",
        "info": "[badge.info]INFO[/]",
        "pass": "[badge.pass]PASS[/]",
        "ok": "[badge.pass]OK[/]",
        "warn": "[badge.medium]WARN[/]",
        "fail": "[badge.fail]FAIL[/]",
    }
    return mapping.get(norm, f"[{C_DIM}]{safe(norm.upper())}[/]")


def eff_lang(lang: str | None) -> str:
    """Resolve effective locale for rendering helpers."""
    return resolve_lang(lang) if lang is not None else get_lang()
