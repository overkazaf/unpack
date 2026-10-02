from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text
from rich import box

from unpack.core.scanner import PackerScanner, ScanResult
from unpack.core.dispatcher import Dispatcher
from unpack.core.reporter import Reporter
from unpack.engines.base import DumpResult
from unpack.repair.dex_repair import DexRepairPipeline
from unpack.repair.verifier import DexVerifier

app = typer.Typer(
    name="unpack",
    help="Android unpacker: scan · dump · repair · verify",
    rich_markup_mode="rich",
    invoke_without_command=True,
)


def _print_main_help():
    console.print()
    console.print(Panel(
        "[bold bright_green]"
        "  _   _ _   _ ____   _    ____ _  __\n"
        " | | | | \\\\ | |  _ \\\\ / \\\\  / ___| |/ /\n"
        " | | | |  \\\\| | |_) / _ \\\\| |   | ' / \n"
        " | |_| | |\\\\  |  __/ ___ \\\\ |___| . \\\\ \n"
        "  \\\\___/|_| \\\\_|_| /_/   \\\\_\\\\____|_|\\\\_\\\\"
        "[/]",
        subtitle="[dim]v0.1.0[/]",
        border_style="bright_green",
        box=box.DOUBLE,
        padding=(0, 2),
    ))

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column("cmd", style="bright_yellow bold", min_width=10)
    t.add_column("desc")
    t.add_row("scan", "Identify packer type and protection level")
    t.add_row("dump", "Full unpack: scan → dump → repair → verify")
    t.add_row("repair", "Fix dumped DEX files (header, checksum, signature)")
    t.add_row("verify", "Check DEX integrity and quality metrics")
    console.print(Panel(t, title="[bold]Commands[/]", border_style="dim", box=box.ROUNDED))

    examples = [
        ("unpack scan app.apk", "identify packer"),
        ("unpack scan app.apk -j out.json", "export as JSON"),
        ("unpack dump app.apk", "full unpack flow"),
        ("unpack dump app.apk -o ./out -e frida", "force engine + output dir"),
        ("unpack dump app.apk -e ebpf -d SERIAL", "eBPF engine on specific device"),
        ("unpack dump app.apk --skip-repair", "dump only, no repair"),
        ("unpack repair ./unpacked/", "fix all DEX in directory"),
        ("unpack repair classes.dex -i", "repair in place"),
        ("unpack verify ./unpacked/", "check integrity"),
    ]
    et = Table(show_header=False, box=None, padding=(0, 1))
    et.add_column("$", style="bright_cyan", width=2)
    et.add_column("cmd", style="bright_white", min_width=42)
    et.add_column("#", style="dim")
    for cmd, desc in examples:
        et.add_row("$", cmd, f"# {desc}")
    console.print(Panel(et, title="[bold bright_green]Examples[/]", border_style="bright_green", box=box.ROUNDED))

    engines = [
        ("frida", "bright_green", "Frida DBI injection — needs frida-server on device"),
        ("ebpf", "bright_cyan", "eBPF uprobe on libart.so — needs root + bpftrace, stealthier"),
        ("memory", "dim", "Direct memory scan — stub, not yet implemented"),
    ]
    nt = Table(show_header=False, box=None, padding=(0, 1))
    nt.add_column("engine", min_width=10)
    nt.add_column("desc")
    for name, color, desc in engines:
        nt.add_row(f"[{color} bold]{name}[/]", desc)
    console.print(Panel(nt, title="[bold]Engines[/]", border_style="dim", box=box.ROUNDED))

    console.print(f"  [dim]pip install -e '.\\[frida]'   → frida engine[/]")
    console.print(f"  [dim]pip install -e '.\\[analysis]' → androguard + lief[/]")
    console.print(f"  [dim]pip install -e '.\\[all]'     → everything[/]")
    console.print()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        _print_main_help()
        raise typer.Exit()
console = Console()

# ── Color scheme ──
C_OK = "bright_green"
C_FAIL = "bright_red"
C_WARN = "bright_yellow"
C_INFO = "bright_cyan"
C_DIM = "dim"
C_ACCENT = "bright_magenta"
C_HEADER = "bold bright_green"
C_LABEL = "bright_white"


def _phase(n: int, total: int, label: str):
    console.print(f"\n [{C_INFO}]>[/] [{C_HEADER}]Phase {n}/{total}[/] {label}")


import time as _time
from contextlib import contextmanager

@contextmanager
def _spinner(msg: str, show_time: bool = True):
    t0 = _time.monotonic()
    with Progress(
        SpinnerColumn("dots12"),
        TextColumn(f"[{C_INFO}]{{task.description}}[/]"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(msg, total=None)
        yield
    if show_time:
        elapsed = _time.monotonic() - t0
        if elapsed > 0.5:
            console.print(f"  [{C_DIM}]done in {elapsed:.1f}s[/]")


@app.command()
def scan(
    apk: Annotated[Path, typer.Argument(help="Path to APK file")],
    output_json: Annotated[Optional[Path], typer.Option("--json", "-j", help="Save result as JSON (use - for stdout)")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Detailed output with SO list, DEX info, analysis hints")] = False,
    report: Annotated[bool, typer.Option("--report", "-r", help="Output plain-text report (ideal for piping to claude -p)")] = False,
):
    """Identify packer type and protection level.

    Analyzes APK static features — SO files, manifest, assets, DEX structure —
    to detect packer vendor, version, and protection level.
    Covers 24 vendors (360, Tencent, Bangbang, iJiami, NetEase, Ali, etc).
    No device required.
    """
    if not apk.exists():
        console.print(f"[{C_FAIL}]APK not found:[/] {apk}")
        raise typer.Exit(1)

    from unpack.utils.apk import find_sibling_splits
    extra_apks = find_sibling_splits(apk)
    if extra_apks:
        console.print(f"  [{C_DIM}]Found {len(extra_apks)} split APK(s) alongside base[/]")

    scanner = PackerScanner()

    if report:
        result = scanner.scan(apk, verbose=True, extra_apks=extra_apks or None)
        print(result.to_report())
        return

    with _spinner("Scanning APK..."):
        result = scanner.scan(apk, verbose=verbose, extra_apks=extra_apks or None)

    _print_scan_result(result, apk)

    if verbose and not output_json:
        _print_verbose(result)

    if output_json:
        d = result.to_verbose_dict() if verbose else result.to_dict()
        data = json.dumps(d, indent=2, ensure_ascii=False)
        if str(output_json) == "-":
            print(data)
        else:
            output_json.write_text(data)
            console.print(f"  [{C_DIM}]Saved to {output_json}[/]")


@app.command()
def analyze(
    apk: Annotated[Path, typer.Argument(help="Path to APK file")],
    prompt: Annotated[Optional[str], typer.Option("--prompt", "-p", help="Custom analysis prompt for Claude")] = None,
):
    """Generate detailed scan report and pipe to Claude for AI analysis.

    Outputs a structured plain-text report to stdout, designed to be piped
    to `claude -p` for deep analysis of packer characteristics, bypass
    strategies, and similar samples.
    """
    if not apk.exists():
        console.print(f"[{C_FAIL}]APK not found:[/] {apk}", err=True)
        raise typer.Exit(1)

    scanner = PackerScanner()
    result = scanner.scan(apk, verbose=True)

    report_text = result.to_report()

    if prompt:
        analysis_prompt = prompt
    else:
        analysis_prompt = (
            "Based on the scan report above, analyze:\n"
            "1. The specific packer technology used and its technical characteristics\n"
            "2. Known bypass/unpacking techniques for this packer version\n"
            "3. What protection mechanisms to expect (anti-debug, anti-frida, integrity checks)\n"
            "4. Recommended unpacking strategy (tools, order of operations)\n"
            "5. Similar apps that use the same packer and any public writeups\n"
            "Be specific and actionable."
        )

    output = f"{report_text}\n---\n\n{analysis_prompt}\n"
    print(output)


@app.command()
def dump(
    apk: Annotated[Path, typer.Argument(help="Path to APK file")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory for dumped DEX files")] = Path("./unpacked"),
    device: Annotated[Optional[str], typer.Option("--device", "-d", help="ADB device serial (default: first USB device)")] = None,
    engine: Annotated[Optional[str], typer.Option("--engine", "-e", help="Force engine: frida | ebpf | memory")] = None,
    timeout: Annotated[int, typer.Option("--timeout", "-t", help="Seconds to wait for packer to unpack (default: auto)")] = 0,
    deep: Annotated[bool, typer.Option("--deep", help="Active invocation: force-call all methods to defeat function extraction packers")] = False,
    skip_repair: Annotated[bool, typer.Option("--skip-repair", help="Skip automatic DEX repair after dump")] = False,
    no_anti_detect: Annotated[bool, typer.Option("--no-anti-detect", help="Disable Frida anti-detection bypasses")] = False,
):
    """Full unpack flow: scan -> dump -> repair -> verify.

    Requires a connected Android device. Engine is auto-selected based on
    packer type and device capabilities (eBPF > Frida > Memory).

    Use --deep for function extraction packers: after dumping the DEX skeleton,
    Frida active invocation forces every method to resolve, capturing the
    decrypted CodeItems and merging them back into the skeleton.
    """
    if not apk.exists():
        console.print(f"[{C_FAIL}]APK not found:[/] {apk}")
        raise typer.Exit(1)

    output.mkdir(parents=True, exist_ok=True)

    _phase(1, 4, "Scanning packer")
    scanner = PackerScanner()
    with _spinner("Analyzing APK structure..."):
        scan_result = scanner.scan(apk)
    _print_scan_result(scan_result, apk)

    _phase(2, 4, "Dumping DEX")
    dispatcher = Dispatcher()
    wait_label = f"Injecting and waiting for DEX dump ({timeout}s)..." if timeout else "Injecting and waiting for DEX dump..."
    with _spinner(wait_label):
        dump_result = dispatcher.dispatch(
            apk=apk,
            scan_result=scan_result,
            output_dir=output,
            device_serial=device,
            force_engine=engine,
            timeout=timeout if timeout > 0 else None,
            anti_detect=not no_anti_detect,
        )

    if not dump_result.dex_files:
        console.print(f"  [{C_FAIL}]No DEX files dumped.[/]")
        if dump_result.error:
            console.print(f"  [{C_DIM}]{dump_result.error}[/]")
        raise typer.Exit(1)

    console.print(f"  [{C_OK}]+[/] Dumped [{C_OK}]{len(dump_result.dex_files)}[/] DEX file(s) [{C_DIM}]({dump_result.duration_ms}ms)[/]")

    from unpack.core.dedup import dedup_dex_files
    before_count = len(list(output.glob("*.dex")))
    with _spinner("Deduplicating DEX files...", show_time=False):
        unique = dedup_dex_files(output)
    removed_count = before_count - len(unique)
    if removed_count > 0:
        console.print(f"  [{C_DIM}]Removed {removed_count} duplicate(s), {len(unique)} unique DEX file(s)[/]")

    total_phases = 5 if deep else 4
    phase_offset = 0

    if deep:
        from unpack.core.scanner import ProtectionLevel
        _phase(3, total_phases, "Active invocation (deep mode)")

        if scan_result.protection_level not in (
            ProtectionLevel.FUNCTION_EXTRACTION, ProtectionLevel.VMP, ProtectionLevel.DEX2C,
        ):
            console.print(f"  [{C_WARN}]Packer is not function-extraction level, deep mode may not help[/]")

        try:
            from unpack.engines.active_invoke import ActiveInvoker
            from unpack.repair.codeitem_merger import CodeItemMerger

            pkg_name = None
            try:
                from unpack.utils.apk import get_package_name
                pkg_name = get_package_name(apk)
            except Exception:
                pass

            if pkg_name:
                invoker = ActiveInvoker(
                    wait_seconds=timeout if timeout > 0 else 15,
                    anti_detect=not no_anti_detect,
                )
                with _spinner(f"Force-invoking methods in {pkg_name}..."):
                    invoke_result = invoker.invoke(
                        package_name=pkg_name,
                        output_dir=output,
                        device_serial=device,
                    )

                if invoke_result.code_items:
                    console.print(f"  [{C_OK}]+[/] Captured [{C_OK}]{len(invoke_result.code_items)}[/] CodeItem(s)")

                    merger = CodeItemMerger()
                    merged_count = 0
                    for dex_path in list(dump_result.dex_files):
                        with _spinner(f"Merging CodeItems into {dex_path.name}...", show_time=False):
                            merge_result = merger.merge(dex_path, invoke_result.code_items)
                        if merge_result.methods_merged > 0:
                            merged_count += merge_result.methods_merged
                            console.print(
                                f"  [{C_OK}]+[/] {dex_path.name}: "
                                f"[{C_OK}]{merge_result.methods_merged}[/] merged, "
                                f"[{C_WARN}]{merge_result.methods_still_nop}[/] still NOP"
                            )
                    if merged_count > 0:
                        console.print(f"  [{C_OK}]Total: {merged_count} methods restored[/]")
                    else:
                        console.print(f"  [{C_DIM}]No NOP methods found to merge (DEX may not use function extraction)[/]")
                else:
                    msg = invoke_result.error or "no CodeItems captured"
                    console.print(f"  [{C_WARN}]{msg}[/]")
            else:
                console.print(f"  [{C_FAIL}]Could not determine package name for active invocation[/]")
        except ImportError:
            console.print(f"  [{C_FAIL}]Active invocation requires frida: pip install -e '.[frida]'[/]")

        phase_offset = 1

    if not skip_repair:
        _phase(3 + phase_offset, total_phases, "Repairing DEX files")
        pipeline = DexRepairPipeline()
        for dex_path in dump_result.dex_files:
            with _spinner(f"Repairing {dex_path.name}...", show_time=False):
                repair_result = pipeline.repair(dex_path)
            icon = f"[{C_OK}]+[/]" if repair_result.success else f"[{C_FAIL}]x[/]"
            console.print(f"  {icon} {dex_path.name} [{C_DIM}]({', '.join(repair_result.actions)})[/]")

    _phase(4 + phase_offset, total_phases, "Verifying quality")
    with _spinner("Analyzing DEX coverage..."):
        reporter = Reporter()
        report = reporter.evaluate(output, scan_result)
    _print_report(report)

    report_path = output / "report.json"
    report_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    console.print(f"\n  [{C_DIM}]Report saved to {report_path}[/]")


@app.command()
def repair(
    dex: Annotated[Path, typer.Argument(help="DEX file or directory of DEX files")],
    in_place: Annotated[bool, typer.Option("--in-place", "-i", help="Overwrite original instead of creating *_repaired.dex")] = False,
):
    """Repair dumped DEX files.

    Fixes: header fields, Adler32 checksum, SHA-1 signature, map_list
    validation, CodeItem alignment. Detects NOP-only methods
    (still-encrypted extracted methods).
    """
    paths = list(dex.glob("*.dex")) if dex.is_dir() else [dex]
    if not paths:
        console.print(f"[{C_FAIL}]No DEX files found.[/]")
        raise typer.Exit(1)

    pipeline = DexRepairPipeline()
    ok = 0
    console.print(f"  [{C_DIM}]Processing {len(paths)} DEX file(s)...[/]")
    for p in paths:
        with _spinner(f"Repairing {p.name}...", show_time=False):
            result = pipeline.repair(p, in_place=in_place)
        if result.success:
            ok += 1
        icon = f"[{C_OK}]+[/]" if result.success else f"[{C_FAIL}]x[/]"
        console.print(f"  {icon} {p.name} [{C_DIM}]{', '.join(result.actions)}[/]")

    console.print(f"\n  [{C_OK}]{ok}[/]/{len(paths)} repaired")


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(help="DEX file or directory of DEX files")],
):
    """Check DEX integrity and quality metrics.

    Validates magic, checksum, SHA-1, file size, section bounds.
    Reports NOP-only methods from function extraction packers.
    """
    paths = list(path.glob("*.dex")) if path.is_dir() else [path]
    if not paths:
        console.print(f"[{C_FAIL}]No DEX files found.[/]")
        raise typer.Exit(1)

    verifier = DexVerifier()
    console.print(f"  [{C_DIM}]Verifying {len(paths)} DEX file(s)...[/]")
    for p in paths:
        with _spinner(f"Checking {p.name}...", show_time=False):
            result = verifier.verify(p)
        _print_verify_result(p.name, result)


# ── Output formatting ──


def _print_scan_result(result: ScanResult, apk_path: Path | None = None):
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

        conf_bar = _confidence_bar(result.confidence)
        lines.append(f"  [{C_LABEL}]Conf[/]     {conf_bar} {result.confidence:.0%}")

        if result.matched_signatures:
            sigs = f" [{C_DIM}]|[/] ".join(
                f"[{C_INFO}]{s}[/]" for s in result.matched_signatures
            )
            lines.append(f"  [{C_LABEL}]Sigs[/]     {sigs}")

        content = "\n".join(lines)
        console.print(Panel(
            content,
            title=f"[{C_OK}] DETECTED [/]",
            border_style=C_OK,
            box=box.HEAVY,
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


def _confidence_bar(value: float, width: int = 20) -> str:
    filled = int(value * width)
    if value >= 0.6:
        color = C_OK
    elif value >= 0.3:
        color = C_WARN
    else:
        color = C_FAIL
    bar = f"[{color}]{'█' * filled}[/][{C_DIM}]{'░' * (width - filled)}[/]"
    return bar


def _print_report(report):
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
    lines.append(f"  [{C_LABEL}]Coverage[/]        {_confidence_bar(report.code_coverage)} [{coverage_color}]{report.code_coverage:.1%}[/]")
    lines.append(f"  [{C_LABEL}]Score[/]           {_confidence_bar(report.score)} [{score_color}]{report.score:.1%}[/]")

    console.print(Panel(
        "\n".join(lines),
        title=f"[{C_INFO}] QUALITY REPORT [/]",
        border_style=C_INFO,
        box=box.HEAVY,
        padding=(0, 1),
    ))


def _print_verbose(result: ScanResult):
    if result.score_breakdown:
        bd_lines = []
        for b in result.score_breakdown:
            bar = _confidence_bar(b["score"] / b["max"] if b["max"] > 0 else 0, width=8)
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


def _print_verify_result(name: str, result):
    if result.valid:
        console.print(f"  [{C_OK}]✓[/] {name} [{C_OK}]PASS[/]")
    else:
        console.print(f"  [{C_FAIL}]✗[/] {name} [{C_FAIL}]FAIL[/]")
        for issue in result.issues:
            console.print(f"    [{C_WARN}]▸[/] {issue}")


if __name__ == "__main__":
    app()
