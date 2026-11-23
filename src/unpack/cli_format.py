"""Commercial-grade Rich Design System & rendering components for the `unpack` CLI.

Provides a restrained, dark/light-terminal-safe semantic theme, pipe/NO_COLOR-aware
console creation, Rich-markup escaping for untrusted APK/DEX strings, reusable layout
components (headers, cards, tables, trees, progress steps, errors, next-step hints),
and domain renderers for every `unpack` subcommand.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.theme import Theme
from rich.tree import Tree

from unpack.i18n import get_lang, resolve_lang, t

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
        "critical": ("[badge.critical] CRIT [/]",),
        "high": ("[badge.high]HIGH[/]",),
        "medium": ("[badge.medium]MED[/]",),
        "low": ("[badge.low]LOW[/]",),
        "info": ("[badge.info]INFO[/]",),
        "pass": ("[badge.pass]PASS[/]",),
        "ok": ("[badge.pass]OK[/]",),
        "warn": ("[badge.medium]WARN[/]",),
        "fail": ("[badge.fail]FAIL[/]",),
    }
    return mapping.get(norm, (f"[{C_DIM}]{safe(norm.upper())}[/]",))[0]


# ── Reusable Layout Components ───────────────────────────────────────────────


def render_header(
    console: Console,
    title: str,
    subtitle: str | None = None,
    meta: str | None = None,
) -> None:
    """Render a crisp, restrained section masthead."""
    left = f"[header]{safe(title)}[/]"
    if subtitle:
        left += f"  [{C_DIM}]{safe(subtitle)}[/]"
    if meta:
        left += f"  [{C_DIM}]· {safe(meta)}[/]"
    console.print(Rule(left, align="left", style=C_DIM))


def render_kv_card(
    console: Console,
    title: str,
    rows: list[tuple[str, str]],
    *,
    border_style: str = C_DIM,
    title_style: str = C_HEADER,
    box_style: box.Box = box.ROUNDED,
) -> None:
    """Render an aligned key-value summary card."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column("key", style=C_LABEL, no_wrap=True)
    grid.add_column("value")
    for k, v in rows:
        grid.add_row(safe(k), v)
    console.print(
        Panel(
            grid,
            title=f"[{title_style}] {safe(title)} [/]",
            title_align="left",
            border_style=border_style,
            box=box_style,
            padding=(0, 1),
        )
    )


def render_table(
    console: Console,
    columns: list[tuple[str, dict[str, Any]]],
    rows: Iterable[list[str]],
    *,
    title: str | None = None,
    caption: str | None = None,
    box_style: box.Box = box.SIMPLE_HEAVY,
) -> None:
    """Render a consistent minimal-grid table."""
    table = Table(
        title=f"[{C_LABEL}]{safe(title)}[/]" if title else None,
        title_justify="left",
        caption=f"[{C_DIM}]{safe(caption)}[/]" if caption else None,
        caption_justify="left",
        box=box_style,
        header_style=C_LABEL,
        border_style=C_DIM,
        pad_edge=False,
    )
    for col_name, kwargs in columns:
        table.add_column(col_name, **kwargs)
    for row in rows:
        table.add_row(*row)
    console.print(table)


def render_tree(console: Console, root_label: str, items: list[dict[str, Any]]) -> None:
    """Render a hierarchical Rich Tree from nested ``{label, children}`` dicts."""
    tree = Tree(f"[header]{safe(root_label)}[/]", guide_style=C_DIM)

    def _add(branch: Tree, nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            label = str(node.get("label") or node.get("name") or "")
            meta = node.get("meta")
            text = f"{safe(label)} [{C_DIM}]{safe(meta)}[/]" if meta else safe(label)
            child_branch = branch.add(text)
            children = node.get("children") or []
            if children:
                _add(child_branch, children)

    _add(tree, items)
    console.print(tree)


def _eff_lang(lang: str | None) -> str:
    return resolve_lang(lang) if lang is not None else get_lang()


def render_pipeline_step(
    console: Console,
    step: int,
    total: int,
    label: str,
    detail: str | None = None,
    *,
    lang: str | None = None,
) -> None:
    """Render a clean numbered pipeline phase header."""
    eff = _eff_lang(lang)
    prefix = t("fmt.step_prefix", eff, step=step, total=total)
    suffix = f"  [{C_DIM}]{safe(detail)}[/]" if detail else ""
    console.print(f"\n[{C_INFO}]▸[/] [{C_HEADER}]{safe(prefix)}[/]  [{C_LABEL}]{safe(label)}[/]{suffix}")


def render_wizard_step(
    console: Console,
    step: int,
    total: int,
    title: str,
    subtitle: str | None = None,
    *,
    lang: str | None = None,
) -> None:
    """Render a step header for the interactive onboarding wizard."""
    eff = _eff_lang(lang)
    prefix = t("fmt.step_prefix", eff, step=step, total=total)
    console.print()
    render_header(console, f"{prefix} · {title}", subtitle=subtitle)


def render_error(
    console: Console,
    title: str,
    detail: str | None = None,
    hint: str | None = None,
    *,
    lang: str | None = None,
) -> None:
    """Render an actionable commercial error callout."""
    eff = _eff_lang(lang)
    lines = [f"[{C_FAIL}]✗ {safe(title)}[/]"]
    if detail:
        lines.append(f"  {safe(detail)}")
    if hint:
        lines.append(f"  [{C_INFO}]{safe(t('fmt.hint_label', eff))}[/] {safe(hint)}")
    console.print("\n".join(lines))


def render_next_steps(
    console: Console,
    steps: list[tuple[str, str]],
    *,
    lang: str | None = None,
) -> None:
    """Render concise, runnable next-step command hints."""
    if not steps:
        return
    eff = _eff_lang(lang)
    console.print(f"\n[{C_DIM}]{safe(t('fmt.next_steps', eff))}[/]")
    for cmd, desc in steps:
        console.print(f"  [{C_INFO}]$[/] [cmd]{safe(cmd)}[/]  [{C_DIM}]# {safe(desc)}[/]")


# ── Domain Renderers (backward-compatible + commercial polish) ───────────────


def print_scan_result(
    console: Console,
    result,
    apk_path: Path | None = None,
    *,
    lang: str | None = None,
) -> None:
    """Render primary packer detection summary card.

    Preserves status tokens ``DETECTED``, ``POSSIBLE``, and ``NO PACKER``
    in English mode for backward compatibility with scripts and tests.
    """
    eff = _eff_lang(lang)
    if result.packer_name:
        level_val = getattr(result.protection_level, "value", str(result.protection_level))
        level_color = {
            "none": C_OK,
            "dex_encryption": C_WARN,
            "function_extraction": C_WARN,
            "vmp": C_FAIL,
            "dex2c": C_FAIL,
            "unknown": C_DIM,
        }.get(level_val, C_DIM)

        rows: list[tuple[str, str]] = []
        if apk_path:
            rows.append((t("fmt.target", eff), f"[path]{safe(apk_path.name)}[/]"))
        packer_display = f"[{C_ACCENT} bold]{safe(result.packer_name)}[/]"
        if getattr(result, "packer_version", None):
            packer_display += f"  [{C_INFO}]{safe(result.packer_version)}[/]"
        rows.append((t("fmt.packer", eff), packer_display))
        rows.append((t("fmt.protection", eff), f"[{level_color} bold]{safe(level_val)}[/]"))
        rows.append((t("fmt.confidence", eff), f"{confidence_bar(result.confidence)}  {result.confidence:.0%}"))

        if getattr(result, "risk_score", None) is not None:
            r_score = int(result.risk_score)
            r_color = C_FAIL if r_score >= 60 else C_WARN if r_score >= 30 else C_OK
            rows.append((t("fmt.risk_score", eff), f"[{r_color}]{r_score}/100[/]"))

        if result.matched_signatures:
            sigs = f" [{C_DIM}]·[/] ".join(
                f"[{C_INFO}]{safe(s)}[/]" for s in result.matched_signatures
            )
            rows.append((t("fmt.signatures", eff), sigs))

        rec_engine = getattr(result, "recommended_engine", None)
        rec_flags = getattr(result, "recommended_flags", None) or []
        if rec_engine:
            strat = f"[{C_OK}]{safe(rec_engine)}[/]"
            if rec_flags:
                strat += f" [{C_DIM}]({safe(' '.join(rec_flags))})[/]"
            rows.append((t("fmt.strategy", eff), strat))

        if result.confidence >= 0.2:
            title = t("fmt.detected", eff)
            border = C_OK
            title_style = f"bold {C_OK}"
        else:
            title = t("fmt.possible", eff)
            border = C_WARN
            title_style = f"bold {C_WARN}"

        render_kv_card(console, title, rows, border_style=border, title_style=title_style)
    else:
        rows = []
        if apk_path:
            rows.append((t("fmt.target", eff), f"[path]{safe(apk_path.name)}[/]"))
        status_txt = result.details or t("fmt.no_packer_default", eff)
        if eff == "zh" and status_txt == "No known packer detected":
            status_txt = t("fmt.no_packer_default", "zh")
        rows.append((t("fmt.status", eff), f"[{C_DIM}]{safe(status_txt)}[/]"))
        render_kv_card(console, t("fmt.no_packer", eff), rows, border_style=C_DIM, title_style=C_DIM)


def print_verbose(console: Console, result, *, lang: str | None = None) -> None:
    """Render detailed scan breakdown: confidence weights, evidence, SOs, DEXs, candidates."""
    eff = _eff_lang(lang)
    if result.score_breakdown:
        rows: list[list[str]] = []
        for b in result.score_breakdown:
            mx = float(b.get("max") or 0.0)
            sc = float(b.get("score") or 0.0)
            ratio = (sc / mx) if mx > 0 else 0.0
            hit = f"[{C_OK}]HIT[/]" if b.get("matched") else f"[{C_DIM}]—[/]"
            rows.append(
                [
                    hit,
                    safe(b.get("dimension", "")),
                    confidence_bar(ratio, width=10),
                    f"[{C_INFO}]{sc:.1f}[/][{C_DIM}]/{mx:.1f}[/]",
                ]
            )
        total = sum(float(b.get("score") or 0.0) for b in result.score_breakdown)
        total_max = sum(float(b.get("max") or 0.0) for b in result.score_breakdown)
        rows.append(
            [
                "",
                f"[{C_LABEL}]{safe(t('fmt.total', eff))}[/]",
                confidence_bar(total / total_max if total_max else 0.0, width=10),
                f"[{C_LABEL}]{total:.1f}[/][{C_DIM}]/{total_max:.1f}[/]",
            ]
        )
        render_table(
            console,
            [
                (t("fmt.col.hit", eff), {"width": 4}),
                (t("fmt.col.dimension", eff), {}),
                (t("fmt.col.weight", eff), {"width": 12}),
                (t("fmt.col.score", eff), {"justify": "right"}),
            ],
            rows,
            title=t("fmt.title.confidence", eff),
        )

    evidence = getattr(result, "evidence", None) or []
    if evidence:
        ev_rows: list[list[str]] = []
        for item in evidence[:20]:
            d = item.to_dict() if hasattr(item, "to_dict") else (item if isinstance(item, dict) else {})
            ev_rows.append(
                [
                    safe(d.get("dimension", "")),
                    f"[{C_INFO}]{safe(d.get('indicator') or d.get('matched_value') or '')}[/]",
                    f"{float(d.get('weight', 0)):.1f}",
                    safe(d.get("reason") or d.get("detail") or ""),
                ]
            )
        render_table(
            console,
            [
                (t("fmt.col.dimension", eff), {}),
                (t("fmt.col.indicator", eff), {}),
                (t("fmt.col.weight", eff), {"justify": "right"}),
                (t("fmt.col.detail", eff), {}),
            ],
            ev_rows,
            title=t("fmt.title.evidence", eff, count=len(evidence)),
        )

    if result.all_so_files:
        so_rows: list[list[str]] = []
        suspicious_kw = (
            "secure", "protect", "shield", "safe", "guard", "crypt",
            "hook", "jiagu", "shell", "sec", "vmp", "dex",
        )
        for so in result.all_so_files[:30]:
            name = so.rsplit("/", 1)[-1]
            is_susp = any(k in name.lower() for k in suspicious_kw)
            badge = f"[{C_WARN}]SUSPECT[/]" if is_susp else f"[{C_DIM}]lib[/]"
            style = C_WARN if is_susp else C_DIM
            so_rows.append([badge, f"[{style}]{safe(so)}[/]"])
        caption = (
            t("fmt.showing_n_of", eff, shown=30, total=len(result.all_so_files))
            if len(result.all_so_files) > 30
            else None
        )
        render_table(
            console,
            [(t("fmt.col.flag", eff), {"width": 9}), (t("fmt.col.library_path", eff), {})],
            so_rows,
            title=t("fmt.title.native_libs", eff, count=len(result.all_so_files)),
            caption=caption,
        )

    if result.all_dex_info:
        dex_rows: list[list[str]] = []
        for d in result.all_dex_info:
            size_kb = float(d.get("size_kb") or 0.0)
            classes = int(d.get("classes") or 0)
            tiny = size_kb < 50 and classes < 10
            flag = f"[{C_WARN}]STUB?[/]" if tiny else f"[{C_DIM}]ok[/]"
            dex_rows.append(
                [
                    safe(d.get("name", "")),
                    f"{size_kb:.0f} KB",
                    f"{classes:,}",
                    flag,
                ]
            )
        render_table(
            console,
            [
                (t("fmt.col.dex", eff), {}),
                (t("fmt.col.size", eff), {"justify": "right"}),
                (t("fmt.col.classes", eff), {"justify": "right"}),
                (t("fmt.col.note", eff), {"width": 8}),
            ],
            dex_rows,
            title=t("fmt.title.dex_files", eff, count=len(result.all_dex_info)),
        )

    if result.suspicious_assets:
        asset_rows = [[f"[{C_WARN}]▸[/]", f"[{C_WARN}]{safe(a)}[/]"] for a in result.suspicious_assets[:20]]
        render_table(
            console,
            [("", {"width": 2}), (t("fmt.col.asset_path", eff), {})],
            asset_rows,
            title=t("fmt.title.suspicious_assets", eff, count=len(result.suspicious_assets)),
        )

    if result.app_class:
        console.print(f"  [{C_LABEL}]{safe(t('fmt.app_class', eff))}[/] [{C_INFO}]{safe(result.app_class)}[/]")

    anomalies = getattr(result, "heuristic_anomalies", None) or []
    if anomalies:
        for a in anomalies:
            console.print(f"  [{C_WARN}]![/] {safe(a)}")

    if result.all_candidates and len(result.all_candidates) > 1:
        cand_rows = [
            [
                safe(c.get("name", "")),
                f"{float(c.get('score', 0)):.1f}",
                safe(", ".join(c.get("signatures") or [])),
            ]
            for c in result.all_candidates
        ]
        render_table(
            console,
            [
                (t("fmt.col.candidate", eff), {}),
                (t("fmt.col.score", eff), {"justify": "right"}),
                (t("fmt.col.signatures", eff), {}),
            ],
            cand_rows,
            title=t("fmt.title.all_candidates", eff),
        )


def print_report(console: Console, report, *, lang: str | None = None) -> None:
    """Render DEX quality report card and optional per-DEX table."""
    eff = _eff_lang(lang)
    cov = float(report.code_coverage)
    sc = float(report.score)
    cov_color = C_OK if cov > 0.8 else C_WARN if cov > 0.5 else C_FAIL
    sc_color = C_OK if sc > 0.8 else C_WARN if sc > 0.5 else C_FAIL

    rows: list[tuple[str, str]] = [
        (t("fmt.dex_files", eff), f"[{C_INFO}]{report.dex_count}[/]"),
        (t("fmt.col.classes", eff), f"[{C_INFO}]{report.total_classes:,}[/]"),
        (t("fmt.col.methods", eff), f"[{C_INFO}]{report.total_methods:,}[/]"),
        (t("fmt.with_code", eff), f"[{C_OK}]{report.methods_with_code:,}[/]"),
    ]
    if report.nop_methods > 0:
        rows.append(
            (
                t("fmt.nop_only", eff),
                f"[{C_FAIL}]{report.nop_methods:,}[/] [{C_DIM}]{safe(t('fmt.still_encrypted', eff))}[/]",
            )
        )
    rows.append((t("fmt.coverage", eff), f"{confidence_bar(cov)}  [{cov_color}]{cov:.1%}[/]"))
    rows.append((t("fmt.col.score", eff), f"{confidence_bar(sc)}  [{sc_color}]{sc:.1%}[/]"))

    render_kv_card(
        console,
        t("fmt.title.quality_report", eff),
        rows,
        border_style=C_INFO,
        title_style=f"bold {C_INFO}",
    )

    per_dex = getattr(report, "per_dex", None) or []
    if per_dex:
        dex_rows = [
            [
                safe(d.get("file", "")),
                format_bytes(d.get("file_size")),
                f"{int(d.get('classes', 0)):,}",
                f"{int(d.get('methods', 0)):,}",
                f"{int(d.get('methods_with_code', 0)):,}",
                f"[{C_WARN if d.get('nop_methods', 0) else C_DIM}]{int(d.get('nop_methods', 0)):,}[/]",
            ]
            for d in per_dex[:20]
        ]
        caption = (
            t("fmt.showing_n_of", eff, shown=20, total=len(per_dex))
            if len(per_dex) > 20
            else None
        )
        render_table(
            console,
            [
                (t("fmt.col.dex_file", eff), {}),
                (t("fmt.col.size", eff), {"justify": "right"}),
                (t("fmt.col.classes", eff), {"justify": "right"}),
                (t("fmt.col.methods", eff), {"justify": "right"}),
                (t("fmt.col.code", eff), {"justify": "right"}),
                (t("fmt.col.nop", eff), {"justify": "right"}),
            ],
            dex_rows,
            title=t("fmt.title.per_dex", eff),
            caption=caption,
        )


def print_verify_result(console: Console, name: str, result) -> None:
    """Render single-file verification status (backward-compatible helper)."""
    if result.valid:
        console.print(f"  [{C_OK}]✓[/] {safe(name)} [{C_OK}]PASS[/]")
    else:
        console.print(f"  [{C_FAIL}]✗[/] {safe(name)} [{C_FAIL}]FAIL[/]")
        for issue in result.issues:
            console.print(f"    [{C_WARN}]▸[/] {safe(issue)}")


def print_verify_summary(
    console: Console,
    items: list[dict[str, Any]],
    *,
    lang: str | None = None,
) -> None:
    """Render tabular summary for one or more DEX verification results."""
    eff = _eff_lang(lang)
    rows: list[list[str]] = []
    passed = 0
    for item in items:
        ok = bool(item.get("valid"))
        if ok:
            passed += 1
        stats = item.get("stats") or {}
        status = f"[{C_OK}]PASS[/]" if ok else f"[{C_FAIL}]FAIL[/]"
        issues = item.get("issues") or []
        detail = f"[{C_DIM}]ok[/]" if not issues else f"[{C_WARN}]{safe('; '.join(issues[:2]))}[/]"
        if len(issues) > 2:
            detail += f" [{C_DIM}](+{len(issues) - 2} more)[/]"
        rows.append(
            [
                safe(item.get("file", "")),
                status,
                format_bytes(stats.get("file_size")),
                f"{int(stats.get('class_count', 0)):,}",
                f"{int(stats.get('method_count', 0)):,}",
                detail,
            ]
        )

    render_table(
        console,
        [
            (t("fmt.col.dex_file", eff), {}),
            (t("fmt.col.status", eff), {"width": 6}),
            (t("fmt.col.size", eff), {"justify": "right"}),
            (t("fmt.col.classes", eff), {"justify": "right"}),
            (t("fmt.col.methods", eff), {"justify": "right"}),
            (t("fmt.col.issues", eff), {}),
        ],
        rows,
        title=t("fmt.title.dex_verify", eff, passed=passed, total=len(items)),
    )


def print_repair_summary(
    console: Console,
    items: list[dict[str, Any]],
    *,
    lang: str | None = None,
) -> None:
    """Render tabular summary for DEX repair results (with optional health delta)."""
    eff = _eff_lang(lang)
    rows: list[list[str]] = []
    ok_count = 0
    for item in items:
        ok = bool(item.get("success"))
        if ok:
            ok_count += 1
        status = f"[{C_OK}]OK[/]" if ok else f"[{C_FAIL}]FAIL[/]"
        actions = ", ".join(item.get("actions") or []) or "—"
        nop = int(item.get("nop_methods") or 0)
        nop_cell = f"[{C_WARN}]{nop:,}[/]" if nop else f"[{C_DIM}]0[/]"
        delta = item.get("health_delta")
        delta_cell = (
            f"[{C_OK}]+{delta:.0%}[/]"
            if isinstance(delta, (int, float)) and delta > 0
            else f"[{C_DIM}]—[/]"
        )
        rows.append([safe(item.get("file", "")), status, safe(actions), nop_cell, delta_cell])

    render_table(
        console,
        [
            (t("fmt.col.dex_file", eff), {}),
            (t("fmt.col.status", eff), {"width": 6}),
            (t("fmt.col.actions", eff), {}),
            (t("fmt.col.nop", eff), {"justify": "right"}),
            (t("fmt.col.delta", eff), {"justify": "right"}),
        ],
        rows,
        title=t("fmt.title.dex_repair", eff, ok=ok_count, total=len(items)),
    )


def print_doctor_report(
    console: Console,
    report: dict[str, Any],
    *,
    lang: str | None = None,
) -> None:
    """Render environment & device diagnostics."""
    eff = _eff_lang(lang)
    overall = str(report.get("overall_status") or "ok")
    render_header(
        console,
        t("fmt.title.doctor", eff),
        subtitle=f"v{report.get('unpack_version', '?')} · Python {report.get('python_version', '?')}",
        meta=t("fmt.doctor.status_meta", eff, status=overall.upper()),
    )

    checks = report.get("checks") or []
    if checks:
        rows: list[list[str]] = []
        hints: list[str] = []
        for chk in checks:
            st = str(chk.get("status") or "info").lower()
            rows.append(
                [
                    render_severity_badge(st),
                    safe(chk.get("category", "")),
                    safe(chk.get("name", "")),
                    safe(chk.get("version") or "—"),
                    safe(chk.get("summary") or chk.get("message") or ""),
                ]
            )
            rem = chk.get("remediation") or chk.get("hint")
            if rem and st in ("warn", "fail") and rem not in hints:
                hints.append(str(rem))
        render_table(
            console,
            [
                (t("fmt.col.status", eff), {"width": 6}),
                (t("fmt.col.category", eff), {}),
                (t("fmt.col.check", eff), {}),
                (t("fmt.col.version", eff), {}),
                (t("fmt.col.details", eff), {}),
            ],
            rows,
            title=t("fmt.title.env_checks", eff),
        )
        if hints:
            console.print(f"\n[{C_LABEL}]{safe(t('fmt.title.remediation', eff))}[/]")
            for h in hints:
                console.print(f"  [{C_INFO}]▸[/] {safe(h)}")

    devices = report.get("devices") or []
    if devices:
        yes_str = t("fmt.yes", eff)
        no_str = t("fmt.no", eff)
        ready_str = t("fmt.ready", eff)
        dev_rows = [
            [
                safe(d.get("serial", "")),
                safe(d.get("model") or "—"),
                safe(d.get("android_version") or d.get("api_level") or "—"),
                f"[{C_OK}]{safe(yes_str)}[/]" if d.get("rooted") or d.get("root") else f"[{C_DIM}]{safe(no_str)}[/]",
                f"[{C_OK}]{safe(ready_str)}[/]" if (d.get("frida_server_running") or d.get("frida_server")) else f"[{C_DIM}]—[/]",
            ]
            for d in devices
        ]
        render_table(
            console,
            [
                (t("fmt.col.serial", eff), {}),
                (t("fmt.col.model", eff), {}),
                (t("fmt.col.android", eff), {}),
                (t("fmt.col.root", eff), {"width": 6}),
                (t("fmt.col.frida", eff), {"width": 7}),
            ],
            dev_rows,
            title=t("fmt.title.adb_devices", eff, count=len(devices)),
        )
    else:
        console.print(f"\n  [{C_DIM}]{safe(t('fmt.doctor.no_devices', eff))}[/]")

    engines = report.get("engines") or []
    if engines:
        eng_ready = t("fmt.engine_ready", eff)
        eng_unavail = t("fmt.engine_unavail", eff)
        eng_rows = [
            [
                f"[{C_LABEL}]{safe(e.get('name', ''))}[/]",
                f"[{C_OK}]{safe(eng_ready)}[/]" if e.get("available") else f"[{C_WARN}]{safe(eng_unavail)}[/]",
                safe(e.get("reason") or t("fmt.ready", eff)),
            ]
            for e in engines
        ]
        render_table(
            console,
            [
                (t("fmt.col.engine", eff), {"width": 10}),
                (t("fmt.col.state", eff), {"width": 13}),
                (t("fmt.col.notes", eff), {}),
            ],
            eng_rows,
            title=t("fmt.title.engines", eff),
        )


def print_inspect_apk(
    console: Console,
    data: dict[str, Any],
    *,
    show_permissions: bool = False,
    lang: str | None = None,
) -> None:
    """Render deep APK static inspection report."""
    eff = _eff_lang(lang)
    manifest = data.get("manifest") or {}
    signing = data.get("signing") or {}
    perms = data.get("permissions") or []
    components = data.get("components") or {}
    native_libs = data.get("native_libs") or []
    dex_files = data.get("dex_files") or []
    findings = data.get("findings") or []

    grade = str(data.get("risk_grade") or "—")
    risk = data.get("risk_score")
    risk_str = f"{grade} ({risk}/100)" if risk is not None else grade

    pkg_val = manifest.get("package") or manifest.get("package_name") or "—"
    rows: list[tuple[str, str]] = [
        (t("fmt.file", eff), f"[path]{safe(data.get('file', ''))}[/]  [{C_DIM}]({format_bytes(data.get('size_bytes'))})[/]"),
        ("SHA-256", f"[{C_DIM}]{safe(data.get('sha256') or '—')}[/]"),
        (t("fmt.package", eff), f"[{C_INFO}]{safe(pkg_val)}[/]"),
        (t("fmt.version", eff), f"{safe(manifest.get('version_name') or '—')} [{C_DIM}](code {safe(manifest.get('version_code') or '—')})[/]"),
        ("SDK", f"min {safe(manifest.get('min_sdk') or '—')} · target {safe(manifest.get('target_sdk') or '—')}"),
        ("Application", f"[{C_INFO}]{safe(manifest.get('application_class') or '—')}[/]"),
        (
            t("fmt.flags", eff),
            f"debuggable={safe(manifest.get('debuggable'))} · "
            f"backup={safe(manifest.get('allow_backup'))} · "
            f"cleartext={safe(manifest.get('uses_cleartext_traffic'))}",
        ),
        (t("fmt.risk_grade", eff), f"[{C_WARN if grade in ('D', 'F') else C_OK if grade in ('A', 'B') else C_INFO}]{safe(risk_str)}[/]"),
    ]
    if signing:
        schemes = ", ".join(signing.get("schemes") or []) or "unknown"
        certs = signing.get("certificates") or []
        cert_subj = certs[0].get("subject") if certs and isinstance(certs[0], dict) else None
        subj = signing.get("subject") or cert_subj or "—"
        rows.append((t("fmt.signing", eff), f"{safe(schemes)}  [{C_DIM}]{safe(subj)}[/]"))
    render_kv_card(console, t("fmt.title.apk_overview", eff), rows, border_style=C_INFO)

    if findings:
        f_rows = [
            [
                render_severity_badge(str(f.get("severity") or "info")),
                safe(f.get("rule_id") or ""),
                safe(f.get("title") or ""),
            ]
            for f in findings[:15]
        ]
        render_table(
            console,
            [
                (t("fmt.col.sev", eff), {"width": 6}),
                (t("fmt.col.rule", eff), {}),
                (t("fmt.col.finding", eff), {}),
            ],
            f_rows,
            title=t("fmt.title.findings", eff, count=len(findings)),
        )

    if show_permissions and perms:
        p_rows = []
        for p in perms[:40]:
            if isinstance(p, dict):
                is_dang = bool(p.get("dangerous") or p.get("protection_level") == "dangerous")
                prot = str(p.get("protection_level") or "normal")
                if is_dang:
                    tier = f"[{C_WARN}]DANGEROUS[/]"
                elif prot == "signature":
                    tier = f"[{C_INFO}]SIGNATURE[/]"
                else:
                    tier = f"[{C_DIM}]{safe(prot)}[/]"
                p_rows.append([tier, safe(p.get("name", ""))])
            else:
                p_rows.append([f"[{C_DIM}]perm[/]", safe(p)])
        render_table(
            console,
            [(t("fmt.col.tier", eff), {"width": 10}), (t("fmt.col.permission", eff), {})],
            p_rows,
            title=t("fmt.title.permissions", eff, count=len(perms)),
            caption=t("fmt.showing_n_of", eff, shown=40, total=len(perms)) if len(perms) > 40 else None,
        )

    if isinstance(components, dict) and any(components.values()):
        comp_rows = []
        for ctype in ("activities", "services", "receivers", "providers"):
            entries = components.get(ctype) or []
            exported = sum(1 for e in entries if isinstance(e, dict) and e.get("exported"))
            comp_rows.append([ctype.capitalize(), f"{len(entries):,}", f"[{C_WARN if exported else C_DIM}]{exported:,}[/]"])
        render_table(
            console,
            [
                (t("fmt.col.comp_type", eff), {}),
                (t("fmt.col.total", eff), {"justify": "right"}),
                (t("fmt.col.exported", eff), {"justify": "right"}),
            ],
            comp_rows,
            title=t("fmt.title.components", eff),
        )

    if native_libs:
        lib_rows = []
        for lib in native_libs[:20]:
            flags = []
            if lib.get("is_pie") is True or lib.get("pie") is True:
                flags.append("PIE")
            if lib.get("has_nx") is True or lib.get("nx") is True:
                flags.append("NX")
            relro = lib.get("relro")
            if relro and str(relro).lower() != "none":
                flags.append(f"RELRO:{relro}")
            if lib.get("has_canary") is True or lib.get("canary") is True:
                flags.append("CANARY")
            lib_rows.append(
                [
                    safe(lib.get("name") or lib.get("path") or ""),
                    safe(lib.get("abi") or "—"),
                    format_bytes(lib.get("size") or lib.get("size_bytes")),
                    safe(", ".join(flags) or "—"),
                ]
            )
        render_table(
            console,
            [
                (t("fmt.col.native_lib", eff), {}),
                (t("fmt.col.abi", eff), {}),
                (t("fmt.col.size", eff), {"justify": "right"}),
                (t("fmt.col.elf_flags", eff), {}),
            ],
            lib_rows,
            title=t("fmt.title.native_libs", eff, count=len(native_libs)),
            caption=t("fmt.showing_n_of", eff, shown=20, total=len(native_libs)) if len(native_libs) > 20 else None,
        )

    if dex_files:
        dex_rows = [
            [
                safe(d.get("name") or ""),
                format_bytes(d.get("size") or d.get("size_bytes")),
                f"{int(d.get('classes') or d.get('class_count') or 0):,}",
                f"{int(d.get('methods') or d.get('method_count') or 0):,}",
            ]
            for d in dex_files[:20]
        ]
        render_table(
            console,
            [
                (t("fmt.col.dex", eff), {}),
                (t("fmt.col.size", eff), {"justify": "right"}),
                (t("fmt.col.classes", eff), {"justify": "right"}),
                (t("fmt.col.methods", eff), {"justify": "right"}),
            ],
            dex_rows,
            title=t("fmt.title.embedded_dex", eff, count=len(dex_files)),
        )


def print_inspect_dex(
    console: Console,
    overview: dict[str, Any],
    *,
    classes: list[dict[str, Any]] | None = None,
    class_detail: dict[str, Any] | None = None,
    disasm: dict[str, Any] | None = None,
    lang: str | None = None,
) -> None:
    """Render static DEX inspection overview, classes, methods, or disassembly."""
    eff = _eff_lang(lang)
    rows: list[tuple[str, str]] = [
        ("DEX", f"[path]{safe(overview.get('name') or overview.get('file') or 'classes.dex')}[/]"),
        (t("fmt.col.size", eff), format_bytes(overview.get("size_bytes") or overview.get("file_size"))),
        (t("fmt.version", eff), safe(overview.get("dex_version") or overview.get("version") or overview.get("magic") or "—")),
        (t("fmt.col.classes", eff), f"[{C_INFO}]{int(overview.get('class_count') or overview.get('classes') or 0):,}[/]"),
        (t("fmt.col.methods", eff), f"[{C_INFO}]{int(overview.get('method_count') or overview.get('methods') or 0):,}[/]"),
        (t("fmt.strings", eff), f"[{C_DIM}]{int(overview.get('string_count') or overview.get('strings') or 0):,}[/]"),
    ]
    nop_val = (
        overview["nop_method_count"]
        if "nop_method_count" in overview
        else overview.get("nop_methods")
    )
    if nop_val is not None:
        rows.append((t("fmt.nop_methods", eff), f"[{C_WARN if nop_val else C_DIM}]{int(nop_val):,}[/]"))
    render_kv_card(console, t("fmt.title.dex_overview", eff), rows, border_style=C_INFO)

    if classes:
        cls_rows = [
            [
                safe(c.get("java_name") or c.get("descriptor") or c.get("name") or c.get("class_name") or ""),
                f"{int(c.get('method_count') or c.get('methods') or 0):,}",
                f"[{C_WARN if c.get('nop_count', 0) else C_DIM}]{int(c.get('nop_count') or 0):,}[/]",
                safe(c.get("health") or "ok"),
            ]
            for c in classes[:40]
        ]
        render_table(
            console,
            [
                (t("fmt.col.class", eff), {}),
                (t("fmt.col.methods", eff), {"justify": "right"}),
                (t("fmt.col.nop", eff), {"justify": "right"}),
                (t("fmt.col.health", eff), {"width": 10}),
            ],
            cls_rows,
            title=t("fmt.title.classes", eff, count=len(classes)),
            caption=t("fmt.showing_n_of", eff, shown=40, total=len(classes)) if len(classes) > 40 else None,
        )

    if class_detail:
        methods = class_detail.get("methods") or []
        m_rows = [
            [
                safe(m.get("name") or ""),
                safe(m.get("signature") or m.get("descriptor") or ""),
                safe(m.get("health") or m.get("classification") or "normal"),
                f"{int(m.get('insns_size') or 0):,}",
            ]
            for m in methods[:50]
        ]
        cls_title = (
            class_detail.get("java_name")
            or class_detail.get("descriptor")
            or class_detail.get("name")
            or ""
        )
        render_table(
            console,
            [
                (t("fmt.col.method", eff), {}),
                (t("fmt.col.signature", eff), {}),
                (t("fmt.col.health", eff), {"width": 10}),
                (t("fmt.col.units", eff), {"justify": "right"}),
            ],
            m_rows,
            title=t("fmt.title.class_methods", eff, name=cls_title),
        )

    if disasm:
        insns = disasm.get("instructions") or []
        i_rows = [
            [
                f"[{C_DIM}]{int(ins.get('offset', 0)):04x}[/]",
                f"[{C_INFO}]{safe(ins.get('mnemonic') or ins.get('opcode_name') or '')}[/]",
                safe(ins.get("operands") or ins.get("detail") or ""),
            ]
            for ins in insns[:120]
        ]
        render_table(
            console,
            [
                (t("fmt.col.offset", eff), {"width": 7}),
                (t("fmt.col.opcode", eff), {"width": 22}),
                (t("fmt.col.operands", eff), {}),
            ],
            i_rows,
            title=t(
                "fmt.title.disasm",
                eff,
                cls=disasm.get("class_name", ""),
                method=disasm.get("method_name", ""),
            ),
            caption=t("fmt.showing_insns", eff, shown=min(len(insns), 120), total=len(insns)) if len(insns) > 120 else None,
        )


def print_vmp_summary(
    console: Console,
    per_dex: list[dict[str, Any]],
    totals: dict[str, int],
    *,
    vmp_methods: list[dict[str, Any]] | None = None,
    lang: str | None = None,
) -> None:
    """Render VMP method classification table and summary card."""
    eff = _eff_lang(lang)
    if per_dex:
        rows = [
            [
                safe(d["file"]),
                f"[{C_OK}]{d['normal']:,}[/]",
                f"[{C_WARN if d['nop'] else C_DIM}]{d['nop']:,}[/]",
                f"[{C_FAIL if d['vmp'] else C_DIM}]{d['vmp']:,}[/]",
            ]
            for d in per_dex
        ]
        render_table(
            console,
            [
                (t("fmt.col.dex_file", eff), {}),
                (t("fmt.col.normal", eff), {"justify": "right"}),
                (t("fmt.col.nop", eff), {"justify": "right"}),
                (t("fmt.col.vmp_stub", eff), {"justify": "right"}),
            ],
            rows,
            title=t("fmt.title.vmp_per_dex", eff),
        )

    total = totals["total_methods"]
    normal = totals["normal_count"]
    nop = totals["nop_count"]
    vmp_total = totals["vmp_count"]
    vmp_color = C_FAIL if vmp_total else C_DIM
    vmp_ratio = (vmp_total / total) if total else 0.0

    card_rows = [
        (t("fmt.total", eff), f"[{C_INFO}]{total:,}[/]"),
        (t("fmt.col.normal", eff), f"[{C_OK}]{normal:,}[/]"),
        (t("fmt.col.nop", eff), f"[{C_WARN if nop else C_DIM}]{nop:,}[/]"),
        (t("fmt.col.vmp_stub", eff), f"[{vmp_color}]{vmp_total:,}[/] [{C_DIM}]({vmp_ratio:.1%})[/]"),
    ]
    render_kv_card(
        console,
        t("fmt.title.vmp_card", eff),
        card_rows,
        border_style=C_INFO,
        title_style=f"bold {C_INFO}",
    )

    if vmp_methods:
        stub_rows = [
            [
                safe(m.get("dex_file", "")),
                safe(m.get("class_name") or m.get("class") or ""),
                f"[{C_FAIL}]{safe(m.get('method_name') or m.get('method') or '')}[/]",
                safe(m.get("target", "")),
            ]
            for m in vmp_methods[:15]
        ]
        render_table(
            console,
            [
                (t("fmt.col.dex", eff), {}),
                (t("fmt.col.class", eff), {}),
                (t("fmt.col.method", eff), {}),
                (t("fmt.col.dispatcher", eff), {}),
            ],
            stub_rows,
            title=t("fmt.title.vmp_stubs", eff, count=len(vmp_methods)),
            caption=t("fmt.showing_n_of", eff, shown=15, total=len(vmp_methods)) if len(vmp_methods) > 15 else None,
        )


def print_xref_summary(
    console: Console,
    merged,
    *,
    file_count: int = 1,
    search: str | None = None,
    lang: str | None = None,
) -> None:
    """Render cross-reference index summary and reflection/dynamic-loading highlights."""
    eff = _eff_lang(lang)
    console.print(f"  [{C_DIM}]{safe(t('fmt.analyzed_dex', eff, count=file_count))}[/]")
    refl = merged.reflection_calls
    if search:
        q = search.lower()
        refl = [
            c for c in refl
            if q in str(c.get("target", "")).lower()
            or q in str((c.get("caller") or {}).get("class", "")).lower()
            or q in str((c.get("caller") or {}).get("method", "")).lower()
        ]

    card_rows = [
        (t("fmt.strings_ref", eff), f"[{C_INFO}]{len(merged.string_refs):,}[/]"),
        (t("fmt.methods_called", eff), f"[{C_INFO}]{len(merged.method_calls):,}[/]"),
        (t("fmt.fields_ref", eff), f"[{C_INFO}]{len(merged.field_refs):,}[/]"),
        (t("fmt.reflection_calls", eff), f"[{C_WARN if refl else C_DIM}]{len(refl):,}[/]"),
    ]
    render_kv_card(
        console,
        t("fmt.title.xref_card", eff),
        card_rows,
        border_style=C_INFO,
        title_style=f"bold {C_INFO}",
    )

    if refl:
        refl_rows = [
            [
                f"[{C_WARN}]{safe((c.get('caller') or {}).get('class', ''))}[/]",
                safe((c.get("caller") or {}).get("method", "")),
                f"[{C_ACCENT}]{safe(c.get('target', ''))}[/]",
            ]
            for c in refl[:30]
        ]
        render_table(
            console,
            [
                (t("fmt.col.caller_class", eff), {}),
                (t("fmt.col.method", eff), {}),
                (t("fmt.col.dynamic_target", eff), {}),
            ],
            refl_rows,
            title=t("fmt.title.reflection", eff, count=len(refl)),
            caption=t("fmt.showing_n_of", eff, shown=30, total=len(refl)) if len(refl) > 30 else None,
        )


def render_pipeline_blueprint(
    console: Console,
    plan: dict[str, Any],
    *,
    lang: str | None = None,
) -> None:
    """Render a rich visual Pipeline Execution Blueprint with live preflight & remediation."""
    eff = _eff_lang(lang)
    console.print()
    render_header(
        console,
        t("pipe.title", eff),
        subtitle=t("pipe.subtitle", eff),
        meta=plan.get("mode_label") or plan.get("mode") or "",
    )

    # 1. Strategy Summary Card
    packer_name = plan.get("packer_name") or t("fmt.no_packer", eff)
    if plan.get("packer_version"):
        packer_name = f"{packer_name} ({plan['packer_version']})"
    conf = plan.get("confidence")
    if plan.get("packer_name") and conf is not None:
        packer_display = f"[{C_ACCENT} bold]{safe(packer_name)}[/]  [{C_DIM}]({float(conf):.0%})[/]"
    else:
        packer_display = f"[{C_DIM}]{safe(packer_name)}[/]"

    prot = str(plan.get("protection_level") or "none")
    rec_flags = " ".join(plan.get("recommended_flags") or []) or "—"
    ready_ok = bool(plan.get("can_execute"))
    ready_txt = (
        f"[{C_OK} bold]{safe(t('pipe.state.ready', eff))}[/]"
        if ready_ok
        else f"[{C_WARN} bold]{safe(t('pipe.state.blocked', eff))}[/]"
    )

    summary_rows: list[tuple[str, str]] = [
        (t("pipe.kv.target", eff), f"[path]{safe(plan.get('target', ''))}[/]"),
        (t("pipe.kv.mode", eff), f"[{C_INFO}]{safe(plan.get('mode_label', ''))}[/]"),
        (t("pipe.kv.packer", eff), packer_display),
        (t("pipe.kv.protection", eff), f"[{C_WARN if prot in ('vmp', 'dex2c', 'function_extraction') else C_INFO}]{safe(prot)}[/]"),
        (t("pipe.kv.rec_engine", eff), f"[{C_OK}]{safe(plan.get('recommended_engine') or 'offline')}[/]"),
        (t("pipe.kv.rec_flags", eff), f"[{C_INFO}]{safe(rec_flags)}[/]"),
        (t("pipe.kv.why", eff), safe(plan.get("strategy_reason") or "")),
        (t("pipe.kv.readiness", eff), ready_txt),
    ]
    render_kv_card(
        console,
        t("pipe.card.summary", eff),
        summary_rows,
        border_style=C_OK if ready_ok else C_WARN,
        title_style=f"bold {C_OK if ready_ok else C_WARN}",
    )

    # 2. Live Preflight Checks Table
    preflight = plan.get("preflight_checks") or []
    blocked_items: list[dict[str, Any]] = []
    if preflight:
        pf_rows: list[list[str]] = []
        for item in preflight:
            st = str(item.get("status") or "pass").lower()
            if st == "block":
                badge = f"[{C_FAIL} bold]{safe(t('pipe.state.blocked', eff))}[/]"
                blocked_items.append(item)
            elif st == "warn":
                badge = f"[{C_WARN} bold]{safe(t('pipe.state.warn', eff))}[/]"
            else:
                badge = f"[{C_OK} bold]{safe(t('pipe.state.ready', eff))}[/]"
            pf_rows.append(
                [
                    badge,
                    f"[{C_LABEL}]{safe(item.get('name', ''))}[/]",
                    safe(item.get("detail", "")),
                    f"[{C_DIM}]{safe(item.get('remediation') or '—')}[/]",
                ]
            )
        render_table(
            console,
            [
                (t("pipe.preflight.col.status", eff), {"width": 9}),
                (t("pipe.preflight.col.check", eff), {}),
                (t("pipe.preflight.col.detail", eff), {}),
                (t("pipe.preflight.col.fix", eff), {}),
            ],
            pf_rows,
            title=t("pipe.preflight.title", eff),
        )

    # 3. Stage-by-Stage Execution Blueprint Table
    stages = plan.get("stages") or []
    active_cnt = sum(1 for s in stages if s.get("will_run"))
    if stages:
        st_rows: list[list[str]] = []
        for s in stages:
            rd = str(s.get("readiness") or "ready").lower()
            if not s.get("will_run") or rd == "skipped":
                rd_badge = f"[{C_DIM}]{safe(t('pipe.state.skipped', eff))}[/]"
            elif rd == "blocked":
                rd_badge = f"[{C_FAIL} bold]{safe(t('pipe.state.blocked', eff))}[/]"
            elif rd == "warn":
                rd_badge = f"[{C_WARN} bold]{safe(t('pipe.state.warn', eff))}[/]"
            else:
                rd_badge = f"[{C_OK} bold]{safe(t('pipe.state.ready', eff))}[/]"

            purpose = str(s.get("what_it_does") or "")
            if s.get("skip_reason"):
                purpose = f"{purpose} [{s['skip_reason']}]"
            io_str = f"{s.get('inputs', '—')} → {s.get('outputs', '—')}"
            st_rows.append(
                [
                    str(s.get("order", "")),
                    f"[{C_LABEL}]{safe(s.get('title', ''))}[/]",
                    rd_badge,
                    safe(purpose),
                    f"[{C_INFO}]{safe(io_str)}[/]",
                    f"[{C_DIM}]{safe(s.get('prerequisites', ''))}[/]",
                ]
            )
        render_table(
            console,
            [
                (t("pipe.col.step", eff), {"width": 3, "justify": "right"}),
                (t("pipe.col.stage", eff), {}),
                (t("pipe.col.state", eff), {"width": 9}),
                (t("pipe.col.purpose", eff), {}),
                (t("pipe.col.io", eff), {}),
                (t("pipe.col.prereq", eff), {}),
            ],
            st_rows,
            title=t("pipe.stages.title", eff, active=active_cnt, total=len(stages)),
        )

    # 4. Remediation Callout if blocked
    if blocked_items:
        console.print(f"\n[{C_WARN} bold]⚠ {safe(t('pipe.remediation.header', eff))}[/]")
        for b in blocked_items:
            if b.get("remediation"):
                console.print(f"  [{C_WARN}]▸[/] [{C_LABEL}]{safe(b.get('name', ''))}:[/] {safe(b['remediation'])}")
        if plan.get("offline_alternative_cmd"):
            console.print(f"\n  [{C_INFO}]{safe(t('pipe.remediation.offline_tip', eff))}[/]")
            console.print(f"    [{C_INFO}]$[/] [cmd]{safe(plan['offline_alternative_cmd'])}[/]")

    # 5. Copyable commands
    cmd_steps: list[tuple[str, str]] = []
    if plan.get("recommended_cmd"):
        cmd_steps.append((plan["recommended_cmd"], t("pipe.cmd.recommended", eff)))
    if plan.get("offline_alternative_cmd") and plan.get("offline_alternative_cmd") != plan.get("recommended_cmd"):
        cmd_steps.append((plan["offline_alternative_cmd"], t("pipe.cmd.offline_alt", eff)))
    if cmd_steps:
        render_next_steps(console, cmd_steps, lang=eff)
