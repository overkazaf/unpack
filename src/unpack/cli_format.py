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


def render_pipeline_step(
    console: Console,
    step: int,
    total: int,
    label: str,
    detail: str | None = None,
) -> None:
    """Render a clean numbered pipeline phase header."""
    suffix = f"  [{C_DIM}]{safe(detail)}[/]" if detail else ""
    console.print(f"\n[{C_INFO}]▸[/] [{C_HEADER}]Step {step}/{total}[/]  [{C_LABEL}]{safe(label)}[/]{suffix}")


def render_error(
    console: Console,
    title: str,
    detail: str | None = None,
    hint: str | None = None,
) -> None:
    """Render an actionable commercial error callout."""
    lines = [f"[{C_FAIL}]✗ {safe(title)}[/]"]
    if detail:
        lines.append(f"  {safe(detail)}")
    if hint:
        lines.append(f"  [{C_INFO}]Hint:[/] {safe(hint)}")
    console.print("\n".join(lines))


def render_next_steps(console: Console, steps: list[tuple[str, str]]) -> None:
    """Render concise, runnable next-step command hints."""
    if not steps:
        return
    console.print(f"\n[{C_DIM}]Next steps:[/]")
    for cmd, desc in steps:
        console.print(f"  [{C_INFO}]$[/] [cmd]{safe(cmd)}[/]  [{C_DIM}]# {safe(desc)}[/]")


# ── Domain Renderers (backward-compatible + commercial polish) ───────────────


def print_scan_result(console: Console, result, apk_path: Path | None = None) -> None:
    """Render primary packer detection summary card.

    Preserves status tokens ``DETECTED``, ``POSSIBLE``, and ``NO PACKER``
    for backward compatibility with scripts and tests.
    """
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
            rows.append(("Target", f"[path]{safe(apk_path.name)}[/]"))
        packer_display = f"[{C_ACCENT} bold]{safe(result.packer_name)}[/]"
        if getattr(result, "packer_version", None):
            packer_display += f"  [{C_INFO}]{safe(result.packer_version)}[/]"
        rows.append(("Packer", packer_display))
        rows.append(("Protection", f"[{level_color} bold]{safe(level_val)}[/]"))
        rows.append(("Confidence", f"{confidence_bar(result.confidence)}  {result.confidence:.0%}"))

        if getattr(result, "risk_score", None) is not None:
            r_score = int(result.risk_score)
            r_color = C_FAIL if r_score >= 60 else C_WARN if r_score >= 30 else C_OK
            rows.append(("Risk Score", f"[{r_color}]{r_score}/100[/]"))

        if result.matched_signatures:
            sigs = f" [{C_DIM}]·[/] ".join(
                f"[{C_INFO}]{safe(s)}[/]" for s in result.matched_signatures
            )
            rows.append(("Signatures", sigs))

        rec_engine = getattr(result, "recommended_engine", None)
        rec_flags = getattr(result, "recommended_flags", None) or []
        if rec_engine:
            strat = f"[{C_OK}]{safe(rec_engine)}[/]"
            if rec_flags:
                strat += f" [{C_DIM}]({safe(' '.join(rec_flags))})[/]"
            rows.append(("Strategy", strat))

        if result.confidence >= 0.2:
            title = "DETECTED"
            border = C_OK
            title_style = f"bold {C_OK}"
        else:
            title = "POSSIBLE"
            border = C_WARN
            title_style = f"bold {C_WARN}"

        render_kv_card(console, title, rows, border_style=border, title_style=title_style)
    else:
        rows = []
        if apk_path:
            rows.append(("Target", f"[path]{safe(apk_path.name)}[/]"))
        rows.append(("Status", f"[{C_DIM}]{safe(result.details or 'No known packer detected')}[/]"))
        render_kv_card(console, "NO PACKER", rows, border_style=C_DIM, title_style=C_DIM)


def print_verbose(console: Console, result) -> None:
    """Render detailed scan breakdown: confidence weights, evidence, SOs, DEXs, candidates."""
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
                f"[{C_LABEL}]Total[/]",
                confidence_bar(total / total_max if total_max else 0.0, width=10),
                f"[{C_LABEL}]{total:.1f}[/][{C_DIM}]/{total_max:.1f}[/]",
            ]
        )
        render_table(
            console,
            [
                ("Hit", {"width": 4}),
                ("Dimension", {}),
                ("Weight", {"width": 12}),
                ("Score", {"justify": "right"}),
            ],
            rows,
            title="Confidence Breakdown",
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
                ("Dimension", {}),
                ("Indicator", {}),
                ("Weight", {"justify": "right"}),
                ("Detail", {}),
            ],
            ev_rows,
            title=f"Evidence Chain ({len(evidence)})",
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
            f"Showing 30 of {len(result.all_so_files)} native libraries"
            if len(result.all_so_files) > 30
            else None
        )
        render_table(
            console,
            [("Flag", {"width": 9}), ("Library Path", {})],
            so_rows,
            title=f"Native Libraries ({len(result.all_so_files)})",
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
                ("DEX", {}),
                ("Size", {"justify": "right"}),
                ("Classes", {"justify": "right"}),
                ("Note", {"width": 8}),
            ],
            dex_rows,
            title=f"DEX Files ({len(result.all_dex_info)})",
        )

    if result.suspicious_assets:
        asset_rows = [[f"[{C_WARN}]▸[/]", f"[{C_WARN}]{safe(a)}[/]"] for a in result.suspicious_assets[:20]]
        render_table(
            console,
            [("", {"width": 2}), ("Asset Path", {})],
            asset_rows,
            title=f"Suspicious Assets ({len(result.suspicious_assets)})",
        )

    if result.app_class:
        console.print(f"  [{C_LABEL}]Application class:[/] [{C_INFO}]{safe(result.app_class)}[/]")

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
            [("Candidate", {}), ("Score", {"justify": "right"}), ("Signatures", {})],
            cand_rows,
            title="All Candidates",
        )


def print_report(console: Console, report) -> None:
    """Render DEX quality report card and optional per-DEX table."""
    cov = float(report.code_coverage)
    sc = float(report.score)
    cov_color = C_OK if cov > 0.8 else C_WARN if cov > 0.5 else C_FAIL
    sc_color = C_OK if sc > 0.8 else C_WARN if sc > 0.5 else C_FAIL

    rows: list[tuple[str, str]] = [
        ("DEX files", f"[{C_INFO}]{report.dex_count}[/]"),
        ("Classes", f"[{C_INFO}]{report.total_classes:,}[/]"),
        ("Methods", f"[{C_INFO}]{report.total_methods:,}[/]"),
        ("With code", f"[{C_OK}]{report.methods_with_code:,}[/]"),
    ]
    if report.nop_methods > 0:
        rows.append(("NOP-only", f"[{C_FAIL}]{report.nop_methods:,}[/] [{C_DIM}](still encrypted)[/]"))
    rows.append(("Coverage", f"{confidence_bar(cov)}  [{cov_color}]{cov:.1%}[/]"))
    rows.append(("Score", f"{confidence_bar(sc)}  [{sc_color}]{sc:.1%}[/]"))

    render_kv_card(console, "QUALITY REPORT", rows, border_style=C_INFO, title_style=f"bold {C_INFO}")

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
        caption = f"Showing 20 of {len(per_dex)} DEX files" if len(per_dex) > 20 else None
        render_table(
            console,
            [
                ("DEX File", {}),
                ("Size", {"justify": "right"}),
                ("Classes", {"justify": "right"}),
                ("Methods", {"justify": "right"}),
                ("Code", {"justify": "right"}),
                ("NOP", {"justify": "right"}),
            ],
            dex_rows,
            title="Per-DEX Breakdown",
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


def print_verify_summary(console: Console, items: list[dict[str, Any]]) -> None:
    """Render tabular summary for one or more DEX verification results."""
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
            ("DEX File", {}),
            ("Status", {"width": 6}),
            ("Size", {"justify": "right"}),
            ("Classes", {"justify": "right"}),
            ("Methods", {"justify": "right"}),
            ("Issues", {}),
        ],
        rows,
        title=f"DEX Verification ({passed}/{len(items)} PASS)",
    )


def print_repair_summary(console: Console, items: list[dict[str, Any]]) -> None:
    """Render tabular summary for DEX repair results (with optional health delta)."""
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
            ("DEX File", {}),
            ("Status", {"width": 6}),
            ("Actions", {}),
            ("NOP", {"justify": "right"}),
            ("Delta", {"justify": "right"}),
        ],
        rows,
        title=f"DEX Repair ({ok_count}/{len(items)} repaired)",
    )


def print_doctor_report(console: Console, report: dict[str, Any]) -> None:
    """Render environment & device diagnostics."""
    overall = str(report.get("overall_status") or "ok")
    render_header(
        console,
        "UNPACK Doctor",
        subtitle=f"v{report.get('unpack_version', '?')} · Python {report.get('python_version', '?')}",
        meta=f"status: {overall.upper()}",
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
                ("Status", {"width": 6}),
                ("Category", {}),
                ("Check", {}),
                ("Version", {}),
                ("Details", {}),
            ],
            rows,
            title="Environment Checks",
        )
        if hints:
            console.print(f"\n[{C_LABEL}]Remediation:[/]")
            for h in hints:
                console.print(f"  [{C_INFO}]▸[/] {safe(h)}")

    devices = report.get("devices") or []
    if devices:
        dev_rows = [
            [
                safe(d.get("serial", "")),
                safe(d.get("model") or "—"),
                safe(d.get("android_version") or d.get("api_level") or "—"),
                f"[{C_OK}]yes[/]" if d.get("rooted") or d.get("root") else f"[{C_DIM}]no[/]",
                f"[{C_OK}]ready[/]" if (d.get("frida_server_running") or d.get("frida_server")) else f"[{C_DIM}]—[/]",
            ]
            for d in devices
        ]
        render_table(
            console,
            [
                ("Serial", {}),
                ("Model", {}),
                ("Android", {}),
                ("Root", {"width": 6}),
                ("Frida", {"width": 7}),
            ],
            dev_rows,
            title=f"Connected ADB Devices ({len(devices)})",
        )
    else:
        console.print(f"\n  [{C_DIM}]No ADB devices connected (offline commands: scan, inspect, repair, verify, vmp, xref, report).[/]")

    engines = report.get("engines") or []
    if engines:
        eng_rows = [
            [
                f"[{C_LABEL}]{safe(e.get('name', ''))}[/]",
                f"[{C_OK}]READY[/]" if e.get("available") else f"[{C_WARN}]UNAVAILABLE[/]",
                safe(e.get("reason") or "ready"),
            ]
            for e in engines
        ]
        render_table(
            console,
            [("Engine", {"width": 10}), ("State", {"width": 13}), ("Notes", {})],
            eng_rows,
            title="Unpacking Engines",
        )


def print_inspect_apk(
    console: Console,
    data: dict[str, Any],
    *,
    show_permissions: bool = False,
) -> None:
    """Render deep APK static inspection report."""
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
        ("File", f"[path]{safe(data.get('file', ''))}[/]  [{C_DIM}]({format_bytes(data.get('size_bytes'))})[/]"),
        ("SHA-256", f"[{C_DIM}]{safe(data.get('sha256') or '—')}[/]"),
        ("Package", f"[{C_INFO}]{safe(pkg_val)}[/]"),
        ("Version", f"{safe(manifest.get('version_name') or '—')} [{C_DIM}](code {safe(manifest.get('version_code') or '—')})[/]"),
        ("SDK", f"min {safe(manifest.get('min_sdk') or '—')} · target {safe(manifest.get('target_sdk') or '—')}"),
        ("Application", f"[{C_INFO}]{safe(manifest.get('application_class') or '—')}[/]"),
        (
            "Flags",
            f"debuggable={safe(manifest.get('debuggable'))} · "
            f"backup={safe(manifest.get('allow_backup'))} · "
            f"cleartext={safe(manifest.get('uses_cleartext_traffic'))}",
        ),
        ("Risk Grade", f"[{C_WARN if grade in ('D', 'F') else C_OK if grade in ('A', 'B') else C_INFO}]{safe(risk_str)}[/]"),
    ]
    if signing:
        schemes = ", ".join(signing.get("schemes") or []) or "unknown"
        certs = signing.get("certificates") or []
        cert_subj = certs[0].get("subject") if certs and isinstance(certs[0], dict) else None
        subj = signing.get("subject") or cert_subj or "—"
        rows.append(("Signing", f"{safe(schemes)}  [{C_DIM}]{safe(subj)}[/]"))
    render_kv_card(console, "APK OVERVIEW", rows, border_style=C_INFO)

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
            [("Sev", {"width": 6}), ("Rule", {}), ("Finding", {})],
            f_rows,
            title=f"Security Findings ({len(findings)})",
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
            [("Tier", {"width": 10}), ("Permission", {})],
            p_rows,
            title=f"Permissions ({len(perms)})",
            caption=f"Showing 40 of {len(perms)}" if len(perms) > 40 else None,
        )

    if isinstance(components, dict) and any(components.values()):
        comp_rows = []
        for ctype in ("activities", "services", "receivers", "providers"):
            entries = components.get(ctype) or []
            exported = sum(1 for e in entries if isinstance(e, dict) and e.get("exported"))
            comp_rows.append([ctype.capitalize(), f"{len(entries):,}", f"[{C_WARN if exported else C_DIM}]{exported:,}[/]"])
        render_table(
            console,
            [("Component Type", {}), ("Total", {"justify": "right"}), ("Exported", {"justify": "right"})],
            comp_rows,
            title="Components",
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
                ("Native Library", {}),
                ("ABI", {}),
                ("Size", {"justify": "right"}),
                ("ELF Flags", {}),
            ],
            lib_rows,
            title=f"Native Libraries ({len(native_libs)})",
            caption=f"Showing 20 of {len(native_libs)}" if len(native_libs) > 20 else None,
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
                ("DEX", {}),
                ("Size", {"justify": "right"}),
                ("Classes", {"justify": "right"}),
                ("Methods", {"justify": "right"}),
            ],
            dex_rows,
            title=f"Embedded DEX ({len(dex_files)})",
        )


def print_inspect_dex(
    console: Console,
    overview: dict[str, Any],
    *,
    classes: list[dict[str, Any]] | None = None,
    class_detail: dict[str, Any] | None = None,
    disasm: dict[str, Any] | None = None,
) -> None:
    """Render static DEX inspection overview, classes, methods, or disassembly."""
    rows: list[tuple[str, str]] = [
        ("DEX", f"[path]{safe(overview.get('name') or overview.get('file') or 'classes.dex')}[/]"),
        ("Size", format_bytes(overview.get("size_bytes") or overview.get("file_size"))),
        ("Version", safe(overview.get("dex_version") or overview.get("version") or overview.get("magic") or "—")),
        ("Classes", f"[{C_INFO}]{int(overview.get('class_count') or overview.get('classes') or 0):,}[/]"),
        ("Methods", f"[{C_INFO}]{int(overview.get('method_count') or overview.get('methods') or 0):,}[/]"),
        ("Strings", f"[{C_DIM}]{int(overview.get('string_count') or overview.get('strings') or 0):,}[/]"),
    ]
    nop_val = (
        overview["nop_method_count"]
        if "nop_method_count" in overview
        else overview.get("nop_methods")
    )
    if nop_val is not None:
        rows.append(("NOP methods", f"[{C_WARN if nop_val else C_DIM}]{int(nop_val):,}[/]"))
    render_kv_card(console, "DEX OVERVIEW", rows, border_style=C_INFO)

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
                ("Class", {}),
                ("Methods", {"justify": "right"}),
                ("NOP", {"justify": "right"}),
                ("Health", {"width": 10}),
            ],
            cls_rows,
            title=f"Classes ({len(classes)})",
            caption=f"Showing 40 of {len(classes)}" if len(classes) > 40 else None,
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
                ("Method", {}),
                ("Signature", {}),
                ("Health", {"width": 10}),
                ("Units", {"justify": "right"}),
            ],
            m_rows,
            title=f"Class Methods: {cls_title}",
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
            [("Offset", {"width": 7}), ("Opcode", {"width": 22}), ("Operands", {})],
            i_rows,
            title=f"Disassembly: {disasm.get('class_name', '')}->{disasm.get('method_name', '')}",
            caption=f"Showing {min(len(insns), 120)} of {len(insns)} instructions" if len(insns) > 120 else None,
        )


def print_vmp_summary(
    console: Console,
    per_dex: list[dict[str, Any]],
    totals: dict[str, int],
    *,
    vmp_methods: list[dict[str, Any]] | None = None,
) -> None:
    """Render VMP method classification table and summary card."""
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
                ("DEX File", {}),
                ("Normal", {"justify": "right"}),
                ("NOP", {"justify": "right"}),
                ("VMP Stub", {"justify": "right"}),
            ],
            rows,
            title="VMP Per-DEX Classification",
        )

    total = totals["total_methods"]
    normal = totals["normal_count"]
    nop = totals["nop_count"]
    vmp_total = totals["vmp_count"]
    vmp_color = C_FAIL if vmp_total else C_DIM
    vmp_ratio = (vmp_total / total) if total else 0.0

    card_rows = [
        ("Total", f"[{C_INFO}]{total:,}[/]"),
        ("Normal", f"[{C_OK}]{normal:,}[/]"),
        ("NOP", f"[{C_WARN if nop else C_DIM}]{nop:,}[/]"),
        ("VMP stub", f"[{vmp_color}]{vmp_total:,}[/] [{C_DIM}]({vmp_ratio:.1%})[/]"),
    ]
    render_kv_card(console, "VMP CLASSIFICATION", card_rows, border_style=C_INFO, title_style=f"bold {C_INFO}")

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
            [("DEX", {}), ("Class", {}), ("Method", {}), ("Dispatcher Target", {})],
            stub_rows,
            title=f"Top VMP Stubs ({len(vmp_methods)} total)",
            caption=f"Showing 15 of {len(vmp_methods)}" if len(vmp_methods) > 15 else None,
        )


def print_xref_summary(
    console: Console,
    merged,
    *,
    file_count: int = 1,
    search: str | None = None,
) -> None:
    """Render cross-reference index summary and reflection/dynamic-loading highlights."""
    console.print(f"  [{C_DIM}]Analyzed {file_count} DEX file(s)[/]")
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
        ("Strings referenced", f"[{C_INFO}]{len(merged.string_refs):,}[/]"),
        ("Methods called", f"[{C_INFO}]{len(merged.method_calls):,}[/]"),
        ("Fields referenced", f"[{C_INFO}]{len(merged.field_refs):,}[/]"),
        ("Reflection calls", f"[{C_WARN if refl else C_DIM}]{len(refl):,}[/]"),
    ]
    render_kv_card(console, "XREF SUMMARY", card_rows, border_style=C_INFO, title_style=f"bold {C_INFO}")

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
            [("Caller Class", {}), ("Method", {}), ("Dynamic Target", {})],
            refl_rows,
            title=f"Reflection / Dynamic Loading ({len(refl)})",
            caption=f"Showing 30 of {len(refl)}" if len(refl) > 30 else None,
        )
