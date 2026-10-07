from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Optional

# Suppress androguard's loguru noise before any import can trigger it
os.environ.setdefault("LOGURU_LEVEL", "ERROR")
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.disable("androguard")
except ImportError:
    pass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text
from rich import box

from unpack.cli_format import (
    C_OK, C_FAIL, C_WARN, C_INFO, C_DIM, C_ACCENT, C_HEADER, C_LABEL,
    print_scan_result, print_verbose, print_report, print_verify_result, confidence_bar,
)

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
    t.add_row("export", "Export dumped DEX in alternative formats (FART)")
    t.add_row("repack", "Combine original APK + dumped DEX into analyzable APK")
    t.add_row("rescan", "Trigger components to decrypt remaining NOP methods")
    t.add_row("reassemble", "Map dumped classes back to original DEX numbering")
    t.add_row("vmp", "Classify methods: normal / NOP / VMP-stub")
    t.add_row("xref", "Cross-reference index: strings, calls, fields, reflection")
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
        ("unpack repack app.apk ./unpacked/", "combine into analyzable APK"),
        ("unpack rescan app.apk ./unpacked/ -r 5", "trigger components, re-scan memory"),
        ("unpack reassemble app.apk ./unpacked/", "map classes to original DEX"),
        ("unpack vmp ./unpacked/", "classify methods (VMP stub detection)"),
        ("unpack xref ./unpacked/", "cross-reference strings/calls/fields"),
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
        ("memory", "bright_green", "Zero-injection /proc/pid/mem — multi-process + VDEX/OAT/CDEX (recommended)"),
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

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_DEVICE = 2
EXIT_NO_PACKER = 3
EXIT_DUMP_FAILED = 4
EXIT_NOT_FOUND = 5

CONFIDENCE_HIDE_THRESHOLD = 0.1
CONFIDENCE_POSSIBLE_THRESHOLD = 0.2


def _gate_low_confidence(result, verbose: bool):
    """Suppress sub-10% confidence detections unless --verbose."""
    from unpack.core.scanner import ScanResult
    if result.packer_name and result.confidence < CONFIDENCE_HIDE_THRESHOLD and not verbose:
        return ScanResult(details="No high-confidence packer detected (use -v for low-confidence matches)")
    return result


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
    apk: Annotated[Path, typer.Argument(help="Path to APK file or directory (with --batch)")],
    output_json: Annotated[Optional[Path], typer.Option("--json", "-j", help="Save result as JSON (use - for stdout)")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Detailed output with SO list, DEX info, analysis hints")] = False,
    report: Annotated[bool, typer.Option("--report", "-r", help="Output plain-text report (ideal for piping to claude -p)")] = False,
    batch: Annotated[bool, typer.Option("--batch", "-b", help="Scan all APKs in directory, output JSONL")] = False,
):
    """Identify packer type and protection level.

    Analyzes APK static features — SO files, manifest, assets, DEX structure —
    to detect packer vendor, version, and protection level.
    Covers 24 vendors (360, Tencent, Bangbang, iJiami, NetEase, Ali, etc).
    No device required. Exit code 0 if packer found, 3 if not.
    """
    import sys

    if batch:
        if not apk.is_dir():
            console.print(f"[{C_FAIL}]--batch requires a directory[/]")
            raise typer.Exit(EXIT_ERROR)
        from unpack.core.scanner import PackerScanner
        scanner = PackerScanner()
        for apk_file in sorted(apk.glob("*.apk")):
            try:
                result = scanner.scan(apk_file, verbose=False)
                d = result.to_dict()
                d["file"] = apk_file.name
                print(json.dumps(d, ensure_ascii=False), flush=True)
            except Exception as e:
                print(json.dumps({"file": apk_file.name, "error": str(e)}, ensure_ascii=False), flush=True)
        return

    pipe_mode = report or (output_json and str(output_json) == "-")

    if not apk.exists():
        if pipe_mode:
            if output_json and str(output_json) == "-":
                print(json.dumps({"error": f"APK not found: {apk}"}))
            else:
                print(f"Error: APK not found: {apk}", file=sys.stderr)
        else:
            console.print(f"[{C_FAIL}]APK not found:[/] {apk}")
        raise typer.Exit(EXIT_NOT_FOUND)

    from unpack.core.scanner import PackerScanner
    from unpack.utils.apk import find_sibling_splits
    extra_apks = find_sibling_splits(apk)
    if extra_apks and not pipe_mode:
        console.print(f"  [{C_DIM}]Found {len(extra_apks)} split APK(s) alongside base[/]")
    scanner = PackerScanner()

    if pipe_mode:
        result = scanner.scan(apk, verbose=True, extra_apks=extra_apks or None)
        result_gated = _gate_low_confidence(result, verbose)
        if report:
            print(result_gated.to_report())
        else:
            d = result_gated.to_verbose_dict() if verbose else result_gated.to_dict()
            print(json.dumps(d, indent=2, ensure_ascii=False))
        if not result_gated.packer_name:
            raise typer.Exit(EXIT_NO_PACKER)
        return

    with _spinner("Scanning APK..."):
        result = scanner.scan(apk, verbose=verbose, extra_apks=extra_apks or None)

    result_to_show = _gate_low_confidence(result, verbose)
    print_scan_result(console, result_to_show, apk)

    if verbose:
        print_verbose(console, result)

    if output_json:
        d = result.to_verbose_dict() if verbose else result.to_dict()
        data = json.dumps(d, indent=2, ensure_ascii=False)
        output_json.write_text(data)
        console.print(f"  [{C_DIM}]Saved to {output_json}[/]")

    if not result_to_show.packer_name:
        raise typer.Exit(EXIT_NO_PACKER)


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
        import sys
        print(f"APK not found: {apk}", file=sys.stderr)
        raise typer.Exit(EXIT_NOT_FOUND)

    import sys
    print("# UNPACK Analysis Report", flush=True)
    print(f"# Scanning {apk.name}...", flush=True)

    from unpack.core.scanner import PackerScanner
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
        raise typer.Exit(EXIT_NOT_FOUND)

    from unpack.core.dispatcher import Dispatcher
    from unpack.core.reporter import Reporter
    from unpack.core.scanner import PackerScanner
    from unpack.repair.dex_repair import DexRepairPipeline

    output.mkdir(parents=True, exist_ok=True)

    _phase(1, 4, "Scanning packer")
    scanner = PackerScanner()
    with _spinner("Analyzing APK structure..."):
        scan_result = scanner.scan(apk)
    print_scan_result(console, scan_result, apk)

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

        invoke_result = None
        pkg_name = None
        try:
            from unpack.engines.active_invoke import ActiveInvoker
            from unpack.repair.codeitem_merger import CodeItemMerger

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

        # Fallback: if Frida invoker failed or wasn't available, try memory-based
        if not invoke_result or not invoke_result.code_items:
            try:
                from unpack.engines.active_invoke import MemoryActiveInvoker
                from unpack.utils.adb import get_device_serial

                _serial = device or get_device_serial()
                if _serial:
                    console.print(f"  [{C_DIM}]Trying Frida-free active invocation (app exerciser)...[/]")
                    mem_invoker = MemoryActiveInvoker()
                    mem_invoke_result = mem_invoker.invoke(
                        serial=_serial,
                        pid="",  # not needed for exerciser
                        package_name=pkg_name,
                        output_dir=output,
                    )
                    if mem_invoke_result.success:
                        console.print(f"  [{C_OK}]+[/] Exercised app ({mem_invoke_result.classes_resolved} actions)")
                        console.print(f"  [{C_DIM}]Re-scanning memory for decrypted CodeItems...[/]")
            except Exception:
                pass

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
    print_report(console, report)

    report_path = output / "report.json"
    report_path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    console.print(f"\n  [{C_DIM}]Report saved to {report_path}[/]")


@app.command()
def repair(
    dex: Annotated[Path, typer.Argument(help="DEX file or directory of DEX files")],
    in_place: Annotated[bool, typer.Option("--in-place", "-i", help="Overwrite original instead of creating *_repaired.dex")] = False,
    output_json: Annotated[Optional[Path], typer.Option("--json", "-j", help="Save results as JSON (use - for stdout)")] = None,
):
    """Repair dumped DEX files.

    Fixes: header fields, Adler32 checksum, SHA-1 signature, map_list
    validation, CodeItem alignment. Detects NOP-only methods
    (still-encrypted extracted methods).
    """
    pipe_mode = output_json and str(output_json) == "-"

    if not dex.exists():
        if pipe_mode:
            print(json.dumps({"error": f"Path not found: {dex}"}))
        else:
            console.print(f"[{C_FAIL}]Path not found:[/] {dex}")
        raise typer.Exit(EXIT_NOT_FOUND)

    if dex.is_dir():
        paths = [p for p in sorted(dex.glob("*.dex")) if "_repaired" not in p.stem and "_merged" not in p.stem]
    else:
        paths = [dex]

    if not paths:
        if pipe_mode:
            print(json.dumps({"error": "No DEX files found."}))
        else:
            console.print(f"[{C_FAIL}]No DEX files found.[/]")
        raise typer.Exit(1)

    from unpack.repair.dex_repair import DexRepairPipeline
    pipeline = DexRepairPipeline()

    def _as_dict(name: str, result) -> dict:
        return {
            "file": name,
            "success": result.success,
            "actions": result.actions,
            "nop_methods": result.nop_method_count,
            "output": str(result.output_path) if result.output_path else None,
        }

    if pipe_mode:
        repair_results = [_as_dict(p.name, pipeline.repair(p, in_place=in_place)) for p in paths]
        print(json.dumps(repair_results, indent=2, ensure_ascii=False))
        return

    repair_results = []
    ok = 0
    console.print(f"  [{C_DIM}]Processing {len(paths)} DEX file(s)...[/]")
    for p in paths:
        with _spinner(f"Repairing {p.name}...", show_time=False):
            result = pipeline.repair(p, in_place=in_place)
        if result.success:
            ok += 1
        icon = f"[{C_OK}]+[/]" if result.success else f"[{C_FAIL}]x[/]"
        console.print(f"  {icon} {p.name} [{C_DIM}]{', '.join(result.actions)}[/]")
        repair_results.append(_as_dict(p.name, result))

    console.print(f"\n  [{C_OK}]{ok}[/]/{len(paths)} repaired")

    if output_json:
        payload = json.dumps(repair_results, indent=2, ensure_ascii=False)
        output_json.write_text(payload)
        console.print(f"  [{C_DIM}]Saved to {output_json}[/]")


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(help="DEX file or directory of DEX files")],
    output_json: Annotated[Optional[Path], typer.Option("--json", "-j", help="Save results as JSON (use - for stdout)")] = None,
):
    """Check DEX integrity and quality metrics.

    Validates magic, checksum, SHA-1, file size, section bounds.
    Reports NOP-only methods from function extraction packers.
    """
    pipe_mode = output_json and str(output_json) == "-"

    if not path.exists():
        if pipe_mode:
            print(json.dumps({"error": f"Path not found: {path}"}))
        else:
            console.print(f"[{C_FAIL}]Path not found:[/] {path}")
        raise typer.Exit(EXIT_NOT_FOUND)

    if path.is_dir():
        paths = [p for p in sorted(path.glob("*.dex")) if "_repaired" not in p.stem and "_merged" not in p.stem]
    else:
        paths = [path]

    if not paths:
        if pipe_mode:
            print(json.dumps({"error": "No DEX files found."}))
        else:
            console.print(f"[{C_FAIL}]No DEX files found.[/]")
        raise typer.Exit(1)

    from unpack.repair.verifier import DexVerifier
    verifier = DexVerifier()

    def _as_dict(name: str, result) -> dict:
        return {"file": name, "valid": result.valid, "issues": result.issues, "stats": result.stats}

    if pipe_mode:
        all_results = [_as_dict(p.name, verifier.verify(p)) for p in paths]
        print(json.dumps(all_results, indent=2, ensure_ascii=False))
        return

    all_results = []
    console.print(f"  [{C_DIM}]Verifying {len(paths)} DEX file(s)...[/]")
    for p in paths:
        with _spinner(f"Checking {p.name}...", show_time=False):
            result = verifier.verify(p)
        print_verify_result(console, p.name, result)
        all_results.append(_as_dict(p.name, result))

    if output_json:
        payload = json.dumps(all_results, indent=2, ensure_ascii=False)
        output_json.write_text(payload)
        console.print(f"  [{C_DIM}]Saved to {output_json}[/]")


@app.command()
def export(
    dex_dir: Annotated[Path, typer.Argument(help="Directory containing dumped DEX files")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory")] = Path("./fart_export"),
    format: Annotated[str, typer.Option("--format", "-f", help="Export format: fart")] = "fart",
):
    """Export dumped DEX files in alternative formats (e.g., FART bin/txt)."""
    if format != "fart":
        console.print(f"[{C_FAIL}]Unknown format: {format}[/]")
        raise typer.Exit(1)

    dex_files = sorted(dex_dir.glob("*.dex"))
    if not dex_files:
        console.print(f"[{C_FAIL}]No DEX files found in {dex_dir}[/]")
        raise typer.Exit(1)

    from unpack.export.fart import FartExporter
    exporter = FartExporter()
    total_methods = 0

    for dex_path in dex_files:
        result = exporter.export(dex_path, output)
        total_methods += result.method_count
        console.print(f"  [{C_OK}]+[/] {dex_path.name}: {result.method_count} methods -> {result.bin_path.name}")

    console.print(f"  [{C_OK}]Exported {total_methods} methods in FART format to {output}[/]")


@app.command()
def repack(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[Path, typer.Argument(help="Directory with dumped/repaired DEX files")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory")] = Path("./repacked"),
    output_json: Annotated[Optional[Path], typer.Option("--json", "-j", help="Save result as JSON (use - for stdout)")] = None,
):
    """Repack dumped DEX into an analyzable APK."""
    pipe_mode = output_json and str(output_json) == "-"

    if not apk.exists():
        if pipe_mode:
            print(json.dumps({"error": f"APK not found: {apk}"}))
        else:
            console.print(f"[{C_FAIL}]APK not found:[/] {apk}")
        raise typer.Exit(EXIT_NOT_FOUND)
    if not dex_dir.exists():
        if pipe_mode:
            print(json.dumps({"error": f"DEX directory not found: {dex_dir}"}))
        else:
            console.print(f"[{C_FAIL}]DEX directory not found:[/] {dex_dir}")
        raise typer.Exit(EXIT_NOT_FOUND)

    from unpack.repack.repacker import Repacker
    repacker = Repacker()
    if pipe_mode:
        result = repacker.repack(apk, dex_dir, output)
    else:
        with _spinner(f"Repacking {apk.name}..."):
            result = repacker.repack(apk, dex_dir, output)

    if not result.success:
        if pipe_mode:
            print(json.dumps({"success": False, "error": result.error}, indent=2, ensure_ascii=False))
            raise typer.Exit(1)
        console.print(f"  [{C_FAIL}]x[/] Repack failed: {result.error}")
        raise typer.Exit(1)

    payload = {
        "success": result.success,
        "output": str(result.output_path),
        "dex_count": result.dex_count,
        "resources": result.resources_preserved,
    }

    if pipe_mode:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    console.print(f"  [{C_OK}]+[/] Repacked [{C_OK}]{result.dex_count}[/] DEX file(s), "
                  f"preserved [{C_OK}]{result.resources_preserved}[/] resource(s)")
    console.print(f"  [{C_DIM}]Output:[/] {result.output_path}")

    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {output_json}[/]")


@app.command()
def rescan(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[Path, typer.Argument(help="Directory with dumped DEX files (must have report.json)")],
    device: Annotated[Optional[str], typer.Option("--device", "-d", help="ADB device serial")] = None,
    rounds: Annotated[int, typer.Option("--rounds", "-r", help="Number of trigger rounds")] = 3,
):
    """Incremental re-scan: trigger app components to decrypt more methods."""
    if not apk.exists():
        console.print(f"[{C_FAIL}]APK not found:[/] {apk}")
        raise typer.Exit(EXIT_NOT_FOUND)
    if not dex_dir.exists() or not dex_dir.is_dir():
        console.print(f"[{C_FAIL}]Directory not found:[/] {dex_dir}")
        raise typer.Exit(1)

    report_path = dex_dir / "report.json"
    if not report_path.exists():
        console.print(f"[{C_FAIL}]No report.json found in {dex_dir}.[/] Run unpack dump first.")
        raise typer.Exit(1)

    from unpack.engines.rescan import ComponentExtractor, IncrementalRescanner, RescanPlanner
    from unpack.utils.adb import get_device_serial
    from unpack.utils.apk import get_package_name

    planner = RescanPlanner()
    plan = planner.plan(report_path)

    if plan.nop_count == 0:
        console.print(f"  [{C_OK}]No NOP-only methods found — nothing to rescan.[/]")
        return

    console.print(f"  [{C_WARN}]{plan.nop_count}[/] NOP method(s) across [{C_INFO}]{len(plan.dex_targets)}[/] DEX file(s)")

    pkg_name = get_package_name(apk)
    if not pkg_name:
        console.print(f"[{C_FAIL}]Could not determine package name from APK.[/]")
        raise typer.Exit(1)

    extractor = ComponentExtractor()
    manifest_strings = extractor.extract_manifest_strings(apk)
    plan.components = extractor.classify_components(manifest_strings)
    console.print(f"  [{C_DIM}]Found {len(plan.components)} component(s) to trigger[/]")

    serial = device or get_device_serial()
    if not serial:
        console.print(f"[{C_FAIL}]No ADB device connected.[/]")
        raise typer.Exit(1)

    rescanner = IncrementalRescanner(rounds=rounds)
    with _spinner(f"Running {rounds} round(s)..."):
        result = rescanner.rescan(serial, pkg_name, plan, dex_dir)

    if result.new_dex_files:
        console.print(f"  [{C_DIM}]Re-dumped {len(result.new_dex_files)} new DEX file(s):[/]")
        for new_path in result.new_dex_files:
            console.print(f"    [{C_OK}]+[/] {Path(new_path).name}")

    if result.success:
        console.print(f"  [{C_OK}]+[/] Recovered [{C_OK}]{result.methods_recovered}[/] method(s) over {result.rounds} round(s)")
    elif result.error:
        console.print(f"  [{C_FAIL}]{result.error}[/]")
    if result.methods_still_nop:
        console.print(f"  [{C_WARN}]{result.methods_still_nop}[/] method(s) still NOP")


@app.command()
def reassemble(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[Path, typer.Argument(help="Directory with dumped DEX files")],
):
    """Map dumped DEX classes back to original APK DEX numbering."""
    from collections import Counter
    from unpack.repair.reassemble import DexClassLister, ClassMapper, ReassembleResult

    if not apk.exists():
        console.print(f"[{C_FAIL}]APK not found:[/] {apk}")
        raise typer.Exit(EXIT_NOT_FOUND)
    if not dex_dir.exists():
        console.print(f"[{C_FAIL}]Path not found:[/] {dex_dir}")
        raise typer.Exit(EXIT_NOT_FOUND)

    lister = DexClassLister()
    mapper = ClassMapper()

    with _spinner("Reading original APK classes..."):
        original = lister.list_from_apk(apk)
    if not original:
        console.print(f"[{C_FAIL}]No classes*.dex found in APK.[/]")
        raise typer.Exit(1)

    dex_paths = [p for p in sorted(dex_dir.glob("*.dex")) if "_repaired" not in p.stem and "_merged" not in p.stem]
    if not dex_paths:
        console.print(f"[{C_FAIL}]No DEX files found in:[/] {dex_dir}")
        raise typer.Exit(1)

    dumped: dict[str, list[str]] = {}
    with _spinner(f"Reading {len(dex_paths)} dumped DEX file(s)..."):
        for p in dex_paths:
            try:
                dumped[p.name] = lister.list_from_file(p)
            except Exception:
                dumped[p.name] = []

    mapping = mapper.map_classes(original, dumped)
    classes_mapped = sum(1 for v in mapping.values() if v is not None)
    classes_unmapped = len(mapping) - classes_mapped

    distribution = Counter(v for v in mapping.values() if v is not None)
    table = Table(show_header=True, box=box.ROUNDED)
    table.add_column("Original DEX", style=C_LABEL)
    table.add_column("Classes mapped", style=C_INFO, justify="right")
    for dex_name in sorted(original.keys()):
        table.add_row(dex_name, str(distribution.get(dex_name, 0)))
    unmapped_count = distribution.get("(unmapped)", 0)
    if unmapped_count:
        table.add_row(f"[{C_WARN}](unmapped)[/]", f"[{C_WARN}]{unmapped_count}[/]")
    console.print(table)
    console.print(f"  [{C_OK}]{classes_mapped}[/] mapped, [{C_WARN}]{classes_unmapped}[/] unmapped")


@app.command()
def vmp(
    dex_dir: Annotated[Path, typer.Argument(help="Directory with DEX files or single DEX")],
    output_json: Annotated[Optional[Path], typer.Option("--json", "-j", help="Save VMP report as JSON")] = None,
):
    """Classify methods as normal/NOP/VMP-stub."""
    if not dex_dir.exists():
        console.print(f"[{C_FAIL}]Path not found:[/] {dex_dir}")
        raise typer.Exit(EXIT_NOT_FOUND)

    if dex_dir.is_dir():
        paths = [p for p in sorted(dex_dir.glob("*.dex")) if "_repaired" not in p.stem and "_merged" not in p.stem]
    else:
        paths = [dex_dir]

    if not paths:
        console.print(f"[{C_FAIL}]No DEX files found.[/]")
        raise typer.Exit(1)

    from unpack.analysis.vmp import VmpDetector

    detector = VmpDetector()
    all_vmp_methods: list[dict] = []
    all_call_graph: list[dict] = []
    total = normal = nop = vmp_total = 0

    for p in paths:
        report = detector.analyze_dex(p.read_bytes())
        total += report.total_methods
        normal += report.normal_count
        nop += report.nop_count
        vmp_total += report.vmp_count
        all_vmp_methods.extend({**m, "dex_file": p.name} for m in report.vmp_methods)
        all_call_graph.extend({**c, "dex_file": p.name} for c in report.call_graph)

        vmp_color = C_FAIL if report.vmp_count else C_DIM
        console.print(f"  {p.name}: [{C_OK}]{report.normal_count}[/] normal, [{C_WARN}]{report.nop_count}[/] NOP, [{vmp_color}]{report.vmp_count}[/] VMP-stub")

    vmp_color = C_FAIL if vmp_total else C_DIM
    lines = [
        f"  [{C_LABEL}]Total[/]    [{C_INFO}]{total:,}[/]",
        f"  [{C_LABEL}]Normal[/]   [{C_OK}]{normal:,}[/]",
        f"  [{C_LABEL}]NOP[/]      [{C_WARN}]{nop:,}[/]",
        f"  [{C_LABEL}]VMP stub[/] [{vmp_color}]{vmp_total:,}[/]",
    ]
    console.print(Panel("\n".join(lines), title=f"[{C_INFO}] VMP CLASSIFICATION [/]", border_style=C_INFO, box=box.HEAVY, padding=(0, 1)))

    if output_json:
        data = {"total_methods": total, "normal_count": normal, "nop_count": nop, "vmp_count": vmp_total, "vmp_methods": all_vmp_methods, "call_graph": all_call_graph}
        payload = json.dumps(data, indent=2, ensure_ascii=False)
        if str(output_json) == "-":
            print(payload)
        else:
            output_json.write_text(payload)
            console.print(f"  [{C_DIM}]Saved to {output_json}[/]")


@app.command()
def xref(
    dex_dir: Annotated[Path, typer.Argument(help="Directory with DEX files or single DEX")],
    output_json: Annotated[Optional[Path], typer.Option("--json", "-j", help="Save xref report as JSON (use - for stdout)")] = None,
):
    """Build a cross-reference index: strings, method calls, fields, reflection.

    Disassembles every method body and indexes which methods reference
    which string literals, call which other methods, and touch which
    fields. Flags call sites that use Java reflection or dynamic class
    loading (Class.forName, Method.invoke, DexClassLoader, etc) as a
    likely sign of hidden/obfuscated behavior.
    """
    from unpack.analysis.xref import XrefBuilder

    if not dex_dir.exists():
        console.print(f"[{C_FAIL}]Path not found:[/] {dex_dir}")
        raise typer.Exit(EXIT_NOT_FOUND)

    if dex_dir.is_dir():
        paths = [p for p in sorted(dex_dir.glob("*.dex")) if "_repaired" not in p.stem and "_merged" not in p.stem]
    else:
        paths = [dex_dir]

    if not paths:
        console.print(f"[{C_FAIL}]No DEX files found.[/]")
        raise typer.Exit(1)

    pipe_mode = output_json and str(output_json) == "-"

    builder = XrefBuilder()
    reports = []
    for p in paths:
        reports.append(builder.build_file(p))
    merged = XrefBuilder.merge(reports)

    if pipe_mode:
        print(json.dumps(merged.to_dict(), indent=2, ensure_ascii=False))
        return

    console.print(f"  [{C_DIM}]Analyzed {len(paths)} DEX file(s)[/]")

    lines = [
        f"  [{C_LABEL}]Strings referenced[/]  [{C_INFO}]{len(merged.string_refs):,}[/]",
        f"  [{C_LABEL}]Methods called[/]      [{C_INFO}]{len(merged.method_calls):,}[/]",
        f"  [{C_LABEL}]Fields referenced[/]   [{C_INFO}]{len(merged.field_refs):,}[/]",
        f"  [{C_LABEL}]Reflection calls[/]    [{C_WARN if merged.reflection_calls else C_DIM}]{len(merged.reflection_calls):,}[/]",
    ]
    console.print(Panel("\n".join(lines), title=f"[{C_INFO}] XREF SUMMARY [/]", border_style=C_INFO, box=box.HEAVY, padding=(0, 1)))

    if merged.reflection_calls:
        refl_lines = []
        for call in merged.reflection_calls[:30]:
            caller = call["caller"]
            refl_lines.append(
                f"  [{C_WARN}]{caller['class']}->{caller['method']}[/] "
                f"[{C_DIM}]calls[/] [{C_ACCENT}]{call['target']}[/]"
            )
        if len(merged.reflection_calls) > 30:
            refl_lines.append(f"  [{C_DIM}]... and {len(merged.reflection_calls) - 30} more[/]")
        console.print(Panel(
            "\n".join(refl_lines),
            title=f"[{C_WARN}] Reflection / Dynamic Loading [/]",
            border_style=C_WARN, box=box.ROUNDED, padding=(0, 1),
        ))

    if output_json:
        payload = json.dumps(merged.to_dict(), indent=2, ensure_ascii=False)
        output_json.write_text(payload)
        console.print(f"  [{C_DIM}]Saved to {output_json}[/]")


@app.command()
def web(
    port: Annotated[int, typer.Option("--port", "-p", help="Port to listen on")] = 8080,
    host: Annotated[str, typer.Option("--host", help="Host to bind to")] = "127.0.0.1",
):
    """Launch the web UI.

    Opens a browser-based interface for scan, dump, repair, and verify.
    Requires flask: pip install -e '.[web]'
    """
    try:
        from unpack.web import create_app
    except ImportError:
        console.print(f"[{C_FAIL}]Flask not installed. Run: pip install -e '.\\[web]'[/]")
        raise typer.Exit(1)

    console.print(f"  [{C_OK}]UNPACK Web UI[/] http://{host}:{port}")
    webapp = create_app()
    webapp.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    app()
