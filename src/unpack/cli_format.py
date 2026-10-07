"""Rich-rendered output formatting for the `unpack` CLI.

Extracted from cli.py so the command definitions in that module stay focused
on argument parsing and orchestration, while the Rich Console/Panel/Table
rendering logic lives here.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# ── Color scheme ──
C_OK = "bright_green"
C_FAIL = "bright_red"
C_WARN = "bright_yellow"
C_INFO = "bright_cyan"
C_DIM = "dim"
C_ACCENT = "bright_magenta"
C_HEADER = "bold bright_green"
C_LABEL = "bright_white"


def confidence_bar(value: float, width: int = 20) -> str:
    filled = int(value * width)
    if value >= 0.6:
        color = C_OK
    elif value >= 0.3:
        color = C_WARN
    else:
        color = C_FAIL
    bar = f"[{color}]{'█' * filled}[/][{C_DIM}]{'░' * (width - filled)}[/]"
    return bar


def print_scan_result(console: Console, result, apk_path: Path | None = None):
    if result.packer_name:
        level_color = {
            "none": C_OK, "dex_encryption": C_WARN,
            "function_extraction": C_WARN, "vmp": C_FAIL,
            "dex2c": C_FAIL, "unknown": C_DIM,
        }.get(result.protection_level.value, C_DIM)

        lines = []
        if apk_path:
            lines.append(f"  [{C_DIM}]Target[/]   {apk_path.name}")
        lines.append(f"  [{C_LABEL}]Packer[/]   [{C_ACCENT}]{result.packer_name}[/]")
        if hasattr(result, "packer_version") and result.packer_version:
            lines.append(f"  [{C_LABEL}]Version[/]  [{C_INFO}]{result.packer_version}[/]")
        lines.append(f"  [{C_LABEL}]Level[/]    [{level_color}]{result.protection_level.value}[/]")

        conf_bar = confidence_bar(result.confidence)
        lines.append(f"  [{C_LABEL}]Conf[/]     {conf_bar} {result.confidence:.0%}")

        if result.matched_signatures:
            sigs = f" [{C_DIM}]|[/] ".join(
                f"[{C_INFO}]{s}[/]" for s in result.matched_signatures
            )
            lines.append(f"  [{C_LABEL}]Sigs[/]     {sigs}")

        content = "\n".join(lines)
        if result.confidence >= 0.2:
            title = f"[{C_OK}] DETECTED [/]"
            border = C_OK
            box_style = box.HEAVY
        else:
            title = f"[{C_WARN}] POSSIBLE [/]"
            border = C_WARN
            box_style = box.ROUNDED
        console.print(Panel(
            content,
            title=title,
            border_style=border,
            box=box_style,
            padding=(0, 1),
        ))
    else:
        lines = []
        if apk_path:
            lines.append(f"  [{C_DIM}]Target[/]  {apk_path.name}")
        lines.append(f"  [{C_DIM}]{result.details}[/]")
        console.print(Panel(
            "\n".join(lines),
            title=f"[{C_DIM}] NO PACKER [/]",
            border_style=C_DIM,
            box=box.ROUNDED,
            padding=(0, 1),
        ))


def print_report(console: Console, report):
    coverage_color = C_OK if report.code_coverage > 0.8 else C_WARN if report.code_coverage > 0.5 else C_FAIL
    score_color = C_OK if report.score > 0.8 else C_WARN if report.score > 0.5 else C_FAIL

    lines = [
        f"  [{C_LABEL}]DEX files[/]       [{C_INFO}]{report.dex_count}[/]",
        f"  [{C_LABEL}]Classes[/]         [{C_INFO}]{report.total_classes:,}[/]",
        f"  [{C_LABEL}]Methods[/]         [{C_INFO}]{report.total_methods:,}[/]",
        f"  [{C_LABEL}]With code[/]       [{C_OK}]{report.methods_with_code:,}[/]",
    ]
    if report.nop_methods > 0:
        lines.append(f"  [{C_LABEL}]NOP-only[/]        [{C_FAIL}]{report.nop_methods:,}[/] [{C_DIM}](still encrypted)[/]")
    lines.append(f"  [{C_LABEL}]Coverage[/]        {confidence_bar(report.code_coverage)} [{coverage_color}]{report.code_coverage:.1%}[/]")
    lines.append(f"  [{C_LABEL}]Score[/]           {confidence_bar(report.score)} [{score_color}]{report.score:.1%}[/]")

    console.print(Panel(
        "\n".join(lines),
        title=f"[{C_INFO}] QUALITY REPORT [/]",
        border_style=C_INFO,
        box=box.HEAVY,
        padding=(0, 1),
    ))


def print_verbose(console: Console, result):
    if result.score_breakdown:
        bd_lines = []
        for b in result.score_breakdown:
            bar = confidence_bar(b["score"] / b["max"] if b["max"] > 0 else 0, width=8)
            hit = f"[{C_OK}]HIT[/]" if b["matched"] else f"[{C_DIM}] - [/]"
            bd_lines.append(
                f"  {hit}  {b['dimension']:<22s}  {bar}  "
                f"[{C_INFO}]{b['score']:.1f}[/][{C_DIM}]/{b['max']:.1f}[/]"
            )
        total = sum(b["score"] for b in result.score_breakdown)
        total_max = sum(b["max"] for b in result.score_breakdown)
        bd_lines.append(f"  {'':5s} {'':22s}  {'':22s}  [{C_LABEL}]{total:.1f}[/][{C_DIM}]/{total_max:.1f}[/]")
        console.print(Panel(
            "\n".join(bd_lines),
            title=f"[{C_LABEL}] Confidence Breakdown [/]",
            border_style=C_INFO, box=box.ROUNDED, padding=(0, 1),
        ))

    if result.all_so_files:
        so_lines = []
        for so in result.all_so_files[:30]:
            name = so.rsplit("/", 1)[-1]
            is_suspicious = any(k in name.lower() for k in [
                "secure", "protect", "shield", "safe", "guard", "crypt",
                "hook", "jiagu", "shell", "sec", "vmp", "dex",
            ])
            style = C_WARN if is_suspicious else C_DIM
            so_lines.append(f"  [{style}]{so}[/]")
        if len(result.all_so_files) > 30:
            so_lines.append(f"  [{C_DIM}]... and {len(result.all_so_files) - 30} more[/]")
        console.print(Panel(
            "\n".join(so_lines),
            title=f"[{C_LABEL}] Native Libraries ({len(result.all_so_files)}) [/]",
            border_style=C_DIM, box=box.ROUNDED, padding=(0, 1),
        ))

    if result.all_dex_info:
        dex_lines = []
        for d in result.all_dex_info:
            size_str = f"{d['size_kb']:.0f}KB"
            cls_str = f"{d['classes']} classes"
            tiny = d['size_kb'] < 50 and d['classes'] < 10
            style = C_WARN if tiny else C_DIM
            dex_lines.append(f"  [{style}]{d['name']:20s} {size_str:>10s}  {cls_str}[/]")
        console.print(Panel(
            "\n".join(dex_lines),
            title=f"[{C_LABEL}] DEX Files ({len(result.all_dex_info)}) [/]",
            border_style=C_DIM, box=box.ROUNDED, padding=(0, 1),
        ))

    if result.suspicious_assets:
        asset_lines = [f"  [{C_WARN}]{a}[/]" for a in result.suspicious_assets]
        console.print(Panel(
            "\n".join(asset_lines),
            title=f"[{C_WARN}] Suspicious Assets [/]",
            border_style=C_WARN, box=box.ROUNDED, padding=(0, 1),
        ))

    if result.app_class:
        console.print(f"  [{C_LABEL}]Application class:[/] [{C_INFO}]{result.app_class}[/]")

    if result.all_candidates and len(result.all_candidates) > 1:
        cand_lines = []
        for c in result.all_candidates:
            cand_lines.append(
                f"  [{C_DIM}]{c['name']:<16s} score={c['score']:.1f}  {c['signatures']}[/]"
            )
        console.print(Panel(
            "\n".join(cand_lines),
            title=f"[{C_LABEL}] All Candidates [/]",
            border_style=C_DIM, box=box.ROUNDED, padding=(0, 1),
        ))


def print_verify_result(console: Console, name: str, result):
    if result.valid:
        console.print(f"  [{C_OK}]✓[/] {name} [{C_OK}]PASS[/]")
    else:
        console.print(f"  [{C_FAIL}]✗[/] {name} [{C_FAIL}]FAIL[/]")
        for issue in result.issues:
            console.print(f"    [{C_WARN}]▸[/] {issue}")
