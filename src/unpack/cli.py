from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import shutil
import sys
import time as _time
import zipfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any, Optional

# Suppress androguard's loguru noise before any import can trigger it
os.environ.setdefault("LOGURU_LEVEL", "ERROR")
try:
    from loguru import logger as _loguru_logger

    _loguru_logger.disable("androguard")
except ImportError:
    pass

import typer
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from unpack import __version__
from unpack.cli_format import (
    C_ACCENT,
    C_DIM,
    C_FAIL,
    C_HEADER,
    C_INFO,
    C_LABEL,
    C_OK,
    C_WARN,
    confidence_bar,
    create_console,
    print_doctor_report,
    print_inspect_apk,
    print_inspect_dex,
    print_repair_summary,
    print_report,
    print_scan_result,
    print_verbose,
    print_verify_result,
    print_verify_summary,
    print_vmp_summary,
    print_xref_summary,
    render_error,
    render_header,
    render_kv_card,
    render_next_steps,
    render_pipeline_step,
    render_table,
    safe,
)

app = typer.Typer(
    name="unpack",
    help="Android APK unpacker & mobile security workbench: scan · inspect · dump · repair · verify · report",
    rich_markup_mode="rich",
    invoke_without_command=True,
)

# ── Runtime console state (re-initialized per invocation) ────────────────────
console = create_console(stderr=False)
err_console = create_console(stderr=True)
_QUIET = False

# ── Exit Codes (public contract — do not change) ─────────────────────────────
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_DEVICE = 2
EXIT_NO_PACKER = 3
EXIT_DUMP_FAILED = 4
EXIT_NOT_FOUND = 5

CONFIDENCE_HIDE_THRESHOLD = 0.1
CONFIDENCE_POSSIBLE_THRESHOLD = 0.2


def _version_callback(value: bool) -> None:
    if value:
        print(f"unpack {__version__}")
        raise typer.Exit(EXIT_OK)


def _configure_consoles(*, no_color: bool = False, quiet: bool = False) -> None:
    global console, err_console, _QUIET
    _QUIET = quiet
    console = create_console(stderr=False, no_color=no_color, quiet=quiet)
    err_console = create_console(stderr=True, no_color=no_color, quiet=quiet)


def _print_main_help() -> None:
    console.print()
    render_header(
        console,
        "UNPACK",
        subtitle="Android APK Unpacker & Reverse-Engineering Workbench",
        meta=f"v{__version__}",
    )

    groups: list[tuple[str, list[tuple[str, str]]]] = [
        (
            "Recon & Inspection",
            [
                ("scan", "Identify packer vendor, version, protection level & evidence"),
                ("inspect", "Deep static APK/DEX inspection (manifest, signing, classes, disasm)"),
                ("analyze", "Generate AI-ready scan report for piping to claude -p"),
            ],
        ),
        (
            "Unpack & Repair",
            [
                ("dump", "Full pipeline: scan -> dump -> dedup -> repair -> verify"),
                ("repair", "Fix dumped DEX headers, bounds, alignment & checksums"),
                ("verify", "Validate DEX integrity and structural health metrics"),
                ("rescan", "Trigger components to decrypt remaining NOP methods"),
                ("reassemble", "Map dumped classes back to original multi-DEX layout"),
                ("repack", "Rebuild analyzable APK from original resources + dumped DEX"),
            ],
        ),
        (
            "Post-Unpack Analysis",
            [
                ("vmp", "Classify methods: normal / NOP / VMP dispatcher stubs"),
                ("xref", "Cross-reference index: strings, calls, fields, reflection"),
                ("export", "Export dumped DEX in alternative formats (FART)"),
            ],
        ),
        (
            "Reporting & Diagnostics",
            [
                ("report", "Generate commercial HTML / Markdown / SARIF / JSON audit reports"),
                ("doctor", "Check Python deps, RE tools, ADB devices & engine readiness"),
                ("web", "Launch Unpack Studio web workbench"),
            ],
        ),
    ]

    cmd_table = Table(show_header=False, box=None, padding=(0, 2), pad_edge=False)
    cmd_table.add_column("cmd", style="cmd", min_width=12)
    cmd_table.add_column("desc")
    for idx, (group_name, items) in enumerate(groups):
        if idx > 0:
            cmd_table.add_row("", "")
        cmd_table.add_row(f"[{C_DIM}]{group_name.upper()}[/]", "")
        for name, desc in items:
            cmd_table.add_row(f"  {name}", desc)
    console.print(cmd_table)

    examples = [
        ("unpack doctor", "verify tools, devices & engines"),
        ("unpack scan app.apk -v", "detect packer with confidence breakdown"),
        ("unpack inspect app.apk --permissions", "deep static APK inspection"),
        ("unpack dump app.apk --deep", "full unpack with active invocation"),
        ("unpack repair ./unpacked/ && unpack verify ./unpacked/", "repair & verify dumped DEXs"),
        ("unpack report ./unpacked/ --apk app.apk -F html -o audit.html", "commercial HTML audit report"),
        ("unpack web --port 8080", "open Unpack Studio in browser"),
    ]
    console.print(f"\n[{C_LABEL}]Quickstart[/]")
    for cmd, desc in examples:
        console.print(f"  [{C_INFO}]$[/] [cmd]{safe(cmd)}[/]  [{C_DIM}]# {safe(desc)}[/]")
    console.print(
        f"\n  [{C_DIM}]Global flags: --version/-V · --no-color · --quiet/-q · Run `unpack <cmd> --help` for options.[/]\n"
    )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show version and exit",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable ANSI color output (also honors NO_COLOR)"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Reduce non-essential output, spinners, and hints"),
    ] = False,
):
    _configure_consoles(no_color=no_color, quiet=quiet)
    if ctx.invoked_subcommand is None:
        _print_main_help()
        raise typer.Exit()


# ── Shared Helpers ───────────────────────────────────────────────────────────


def _gate_low_confidence(result, verbose: bool):
    """Suppress sub-10% confidence detections unless --verbose."""
    from unpack.core.scanner import ScanResult

    if result.packer_name and result.confidence < CONFIDENCE_HIDE_THRESHOLD and not verbose:
        return ScanResult(
            details="No high-confidence packer detected (use -v for low-confidence matches)"
        )
    return result


def _discover_dex_paths(target: Path) -> list[Path]:
    """Return a single DEX path or sorted non-derived DEX files from a directory."""
    if target.is_dir():
        return [
            p
            for p in sorted(target.glob("*.dex"))
            if "_repaired" not in p.stem and "_merged" not in p.stem
        ]
    return [target]


def _fail_missing(
    label: str,
    path: Path,
    *,
    json_stdout: bool = False,
    plain_stderr: bool = False,
    hint: str | None = None,
) -> None:
    msg = f"{label} not found: {path}"
    if json_stdout:
        print(json.dumps({"error": msg}))
    elif plain_stderr:
        print(f"Error: {msg}", file=sys.stderr)
    else:
        render_error(
            console,
            msg,
            hint=hint or "Check the file path and ensure the target exists.",
        )
    raise typer.Exit(EXIT_NOT_FOUND)


def _fail_error(
    msg: str,
    *,
    json_stdout: bool = False,
    hint: str | None = None,
    code: int = EXIT_ERROR,
) -> None:
    if json_stdout:
        print(json.dumps({"error": msg}))
    else:
        render_error(console, msg, hint=hint)
    raise typer.Exit(code)


@contextmanager
def _spinner(msg: str, show_time: bool = True, enabled: bool = True):
    if not enabled or _QUIET or not err_console.is_terminal:
        yield
        return
    t0 = _time.monotonic()
    with Progress(
        SpinnerColumn("dots12"),
        TextColumn(f"[{C_INFO}]{{task.description}}[/]"),
        console=err_console,
        transient=True,
    ) as progress:
        progress.add_task(msg, total=None)
        yield
    if show_time:
        elapsed = _time.monotonic() - t0
        if elapsed > 0.5:
            err_console.print(f"  [{C_DIM}]done in {elapsed:.1f}s[/]")


def _next_steps_for_scan(apk: Path, result) -> list[tuple[str, str]]:
    if not result.packer_name:
        return [
            (f"unpack inspect {apk}", "inspect manifest, signing, permissions & native libs"),
            (f"unpack scan {apk} -v", "show low-confidence candidates & SO inventory"),
        ]
    level = getattr(result.protection_level, "value", str(result.protection_level))
    if level == "function_extraction":
        return [
            (f"unpack dump {apk} --deep", "dump DEX + active-invoke to recover NOP methods"),
            (f"unpack inspect {apk}", "inspect APK security profile & native libraries"),
        ]
    if level in ("vmp", "dex2c"):
        return [
            (f"unpack inspect {apk}", "inspect native libraries & ELF security flags"),
            (f"unpack dump {apk}", "dump recoverable DEX skeleton for VMP stub mapping"),
        ]
    return [
        (f"unpack dump {apk}", "run full scan -> dump -> repair -> verify pipeline"),
        (f"unpack scan {apk} -F html -o scan.html", "export standalone HTML audit report"),
    ]


# ── Core Fallback Helpers (seamless until/after core-pro merge) ──────────────


def _run_doctor_impl(check_devices: bool = True, device_serial: str | None = None) -> dict[str, Any]:
    """Use core-pro's `unpack.core.doctor.run_doctor` if installed, else built-in fallback."""
    try:
        from unpack.core.doctor import run_doctor

        res = run_doctor(check_devices=check_devices, device_serial=device_serial)
        return res.to_dict() if hasattr(res, "to_dict") else dict(res)
    except ImportError:
        pass

    checks: list[dict[str, Any]] = []

    def _pkg_version(mod: str, install_hint: str, required: bool = False) -> None:
        spec = importlib.util.find_spec(mod)
        if spec is not None:
            ver = "installed"
            try:
                from importlib.metadata import version as pkg_ver

                ver = pkg_ver(mod)
            except Exception:
                pass
            checks.append(
                {
                    "name": mod,
                    "category": "python",
                    "status": "pass",
                    "version": ver,
                    "summary": "available",
                    "remediation": "",
                }
            )
        else:
            checks.append(
                {
                    "name": mod,
                    "category": "python",
                    "status": "fail" if required else "warn",
                    "version": None,
                    "summary": "not installed",
                    "remediation": install_hint,
                }
            )

    _pkg_version("typer", "pip install -e .", required=True)
    _pkg_version("rich", "pip install -e .", required=True)
    _pkg_version("androguard", "pip install -e '.[analysis]'")
    _pkg_version("lief", "pip install -e '.[analysis]'")
    _pkg_version("frida", "pip install -e '.[frida]'")
    _pkg_version("flask", "pip install -e '.[web]'")

    for binary, hint in (
        ("adb", "Install Android Platform Tools and ensure `adb` is on PATH"),
        ("jadx", "Optional: install jadx for decompiling repacked APKs"),
        ("apktool", "Optional: install apktool for resource decoding"),
        ("keytool", "Optional: install JDK keytool for certificate inspection"),
    ):
        found = shutil.which(binary)
        checks.append(
            {
                "name": binary,
                "category": "tool",
                "status": "pass" if found else "warn",
                "version": found or None,
                "summary": "found on PATH" if found else "not found on PATH",
                "remediation": "" if found else hint,
            }
        )

    devices: list[dict[str, Any]] = []
    if check_devices and shutil.which("adb"):
        try:
            from unpack.utils.adb import list_devices

            for serial in list_devices() or []:
                if device_serial and serial != device_serial:
                    continue
                devices.append({"serial": serial, "model": "", "android_version": "", "rooted": False})
        except Exception:
            pass

    engines: list[dict[str, Any]] = []
    for eng_name, mod_path, cls_name in (
        ("memory", "unpack.engines.memory_engine", "MemoryEngine"),
        ("frida", "unpack.engines.frida_engine", "FridaEngine"),
        ("ebpf", "unpack.engines.ebpf_engine", "EbpfEngine"),
    ):
        try:
            mod = __import__(mod_path, fromlist=[cls_name])
            eng = getattr(mod, cls_name)()
            avail = bool(eng.is_available())
            reason = "" if avail else (getattr(eng, "unavailable_reason", "") or "requirements not met")
            engines.append({"name": eng_name, "available": avail, "reason": reason})
        except Exception as exc:
            engines.append({"name": eng_name, "available": False, "reason": str(exc)})

    has_fail = any(c["status"] == "fail" for c in checks)
    has_warn = any(c["status"] == "warn" for c in checks)
    overall = "fail" if has_fail else "warn" if has_warn else "pass"

    return {
        "overall_status": overall,
        "python_version": platform.python_version(),
        "unpack_version": __version__,
        "checks": checks,
        "devices": devices,
        "engines": engines,
    }


def _inspect_apk_impl(apk: Path) -> dict[str, Any]:
    """Use core-pro's `ApkInspector` if available, else lightweight static fallback."""
    try:
        from unpack.core.inspector import ApkInspector

        res = ApkInspector().inspect(apk)
        return res.to_dict() if hasattr(res, "to_dict") else dict(res)
    except ImportError:
        pass

    from unpack.core.scanner import PackerScanner

    sha256 = hashlib.sha256(apk.read_bytes()).hexdigest()
    scan_res = PackerScanner().scan(apk, verbose=True)
    native_libs: list[dict[str, Any]] = []
    dex_files: list[dict[str, Any]] = []
    assets_count = 0
    with zipfile.ZipFile(apk, "r") as zf:
        for info in zf.infolist():
            name = info.filename
            if name.startswith("lib/") and name.endswith(".so"):
                parts = name.split("/")
                abi = parts[1] if len(parts) >= 3 else ""
                native_libs.append(
                    {"name": parts[-1], "path": name, "abi": abi, "size_bytes": info.file_size}
                )
            elif name.endswith(".dex") and "/" not in name:
                dex_files.append({"name": name, "size_bytes": info.file_size, "classes": 0, "methods": 0})
            elif name.startswith("assets/"):
                assets_count += 1

    for d_info in scan_res.all_dex_info:
        for entry in dex_files:
            if entry["name"] == d_info.get("name"):
                entry["classes"] = d_info.get("classes", 0)

    pkg = (scan_res.apk_info or {}).get("package") or ""
    if not pkg:
        try:
            from unpack.utils.apk import get_package_name

            pkg = get_package_name(apk) or ""
        except Exception:
            pkg = ""

    return {
        "file": apk.name,
        "sha256": sha256,
        "size_bytes": apk.stat().st_size,
        "manifest": {
            "package_name": pkg or None,
            "application_class": scan_res.app_class,
        },
        "signing": {},
        "permissions": [],
        "components": {},
        "native_libs": native_libs,
        "dex_files": dex_files,
        "assets_count": assets_count,
        "suspicious_assets": scan_res.suspicious_assets,
        "findings": [],
        "risk_score": 0,
        "risk_grade": "A",
        "warnings": [],
    }


def _inspect_dex_impl(
    dex_path: Path,
    *,
    show_classes: bool = False,
    class_filter: str | None = None,
    method_target: str | None = None,
) -> dict[str, Any]:
    """Use core-pro's `DexInspector` if available, else fallback to `DexFile` + `DalvikDecoder`."""
    try:
        from unpack.analysis.dex_inspector import DexInspector

        insp = DexInspector.from_file(dex_path)
        overview = insp.summary().to_dict()
        out: dict[str, Any] = {"overview": overview}
        if show_classes:
            page = insp.list_classes(query=class_filter or "", limit=100)
            p_dict = page.to_dict()
            out["classes"] = p_dict.get("classes") or p_dict.get("items") or []
        if class_filter and not show_classes:
            detail = insp.inspect_class(class_filter)
            if detail:
                out["class_detail"] = detail.to_dict()
        if method_target and "::" in method_target:
            cls_name, meth_name = method_target.split("::", 1)
            dis = insp.disassemble_method(cls_name, meth_name)
            if dis:
                out["disasm"] = dis.to_dict()
        return out
    except ImportError:
        pass

    from unpack.analysis.disasm import DalvikDecoder
    from unpack.repair.dex_parser import DexFile

    data = dex_path.read_bytes()
    dex = DexFile.parse(data)
    h = dex.header
    overview = {
        "name": dex_path.name,
        "size_bytes": len(data),
        "version": data[:8].decode("ascii", errors="replace").strip("\x00\n"),
        "class_count": h.class_defs_size,
        "method_count": h.method_ids_size,
        "string_count": h.string_ids_size,
    }
    out = {"overview": overview}

    if show_classes or class_filter or method_target:
        classes_list: list[dict[str, Any]] = []
        target_cls = class_filter
        target_meth = None
        if method_target and "::" in method_target:
            target_cls, target_meth = method_target.split("::", 1)

        for cdef in dex.class_defs:
            cname = dex.get_type_name(cdef.class_idx) or f"class_{cdef.class_idx}"
            direct = cdef.class_data.direct_methods if cdef.class_data else []
            virtual = cdef.class_data.virtual_methods if cdef.class_data else []
            all_m = list(direct) + list(virtual)
            if show_classes and (not class_filter or class_filter.lower() in cname.lower()):
                nop_cnt = sum(1 for m in all_m if m.code_item and m.code_item.is_nop_only)
                classes_list.append(
                    {
                        "name": cname,
                        "method_count": len(all_m),
                        "nop_count": nop_cnt,
                        "health": "nop" if nop_cnt else "ok",
                    }
                )
            if target_cls and (cname == target_cls or target_cls in cname):
                if class_filter and not show_classes and "class_detail" not in out:
                    out["class_detail"] = {
                        "name": cname,
                        "methods": [
                            {
                                "name": dex.get_method_name(m.method_idx) or f"m_{m.method_idx}",
                                "signature": "",
                                "health": (
                                    "nop"
                                    if (m.code_item and m.code_item.is_nop_only)
                                    else "normal"
                                    if m.code_item
                                    else "empty"
                                ),
                                "insns_size": m.code_item.insns_size if m.code_item else 0,
                            }
                            for m in all_m
                        ],
                    }
                if target_meth and "disasm" not in out:
                    for m in all_m:
                        mname = dex.get_method_name(m.method_idx) or ""
                        if mname == target_meth and m.code_item:
                            insns = DalvikDecoder().decode(m.code_item.insns)
                            out["disasm"] = {
                                "class_name": cname,
                                "method_name": mname,
                                "instructions": [
                                    {
                                        "offset": ins.offset,
                                        "mnemonic": ins.name,
                                        "operands": f"ref={ins.ref_idx}" if ins.ref_idx is not None else "",
                                    }
                                    for ins in insns
                                ],
                            }
                            break
        if show_classes:
            out["classes"] = classes_list[:100]

    return out


# ── Commands ─────────────────────────────────────────────────────────────────


@app.command()
def doctor(
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save diagnostics as JSON (use - for stdout)"),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-F", help="Output format: table | json"),
    ] = "table",
    device: Annotated[
        Optional[str],
        typer.Option("--device", "-d", help="Check a specific ADB device serial"),
    ] = None,
    no_devices: Annotated[
        bool,
        typer.Option("--no-devices", help="Skip ADB device probing"),
    ] = False,
):
    """Check Python dependencies, RE tools, connected devices, and engine readiness."""
    pipe_json = fmt.lower() == "json" or (output_json is not None and str(output_json) == "-")
    with _spinner("Running environment diagnostics...", enabled=not pipe_json):
        report = _run_doctor_impl(check_devices=not no_devices, device_serial=device)

    payload = json.dumps(report, indent=2, ensure_ascii=False)
    if pipe_json:
        print(payload)
        return

    print_doctor_report(console, report)
    if output_json:
        output_json.write_text(payload)
        console.print(f"\n  [{C_DIM}]Saved to {safe(output_json)}[/]")


@app.command()
def inspect(
    target: Annotated[Path, typer.Argument(help="Path to APK or DEX file")],
    classes: Annotated[bool, typer.Option("--classes", help="List classes inside DEX")] = False,
    methods: Annotated[
        Optional[str],
        typer.Option("--methods", "-m", help="Inspect methods of a specific class (DEX)"),
    ] = None,
    disasm: Annotated[
        Optional[str],
        typer.Option("--disasm", help="Disassemble method (ClassName::methodName) in DEX"),
    ] = None,
    permissions: Annotated[
        bool,
        typer.Option("--permissions", help="Display full APK permission table"),
    ] = False,
    fmt: Annotated[
        str,
        typer.Option("--format", "-F", help="Output format: table | json | markdown | html | sarif"),
    ] = "table",
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save inspection output as JSON (use - for stdout)"),
    ] = None,
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Write formatted report output to file"),
    ] = None,
):
    """Deep static inspection of an APK (manifest, signing, libs) or DEX (classes, methods, disasm)."""
    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )

    if not target.exists():
        _fail_missing("Target", target, json_stdout=json_stdout)

    is_dex = target.suffix.lower() in (".dex", ".cdex")
    if is_dex:
        with _spinner(f"Inspecting DEX {target.name}...", enabled=not json_stdout and fmt_l == "table"):
            data = _inspect_dex_impl(
                target,
                show_classes=classes,
                class_filter=methods,
                method_target=disasm,
            )
        payload = json.dumps(data, indent=2, ensure_ascii=False)
        if json_stdout:
            print(payload)
            return
        if fmt_l == "json" and out:
            out.write_text(payload)
            console.print(f"  [{C_DIM}]Saved to {safe(out)}[/]")
            return
        print_inspect_dex(
            console,
            data.get("overview") or {},
            classes=data.get("classes"),
            class_detail=data.get("class_detail"),
            disasm=data.get("disasm"),
        )
        if output_json:
            output_json.write_text(payload)
            console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")
        return

    # APK inspection
    with _spinner(f"Inspecting APK {target.name}...", enabled=not json_stdout and fmt_l == "table"):
        data = _inspect_apk_impl(target)

    payload = json.dumps(data, indent=2, ensure_ascii=False)
    if json_stdout:
        print(payload)
        return

    if fmt_l in ("markdown", "md", "html", "sarif"):
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(target, inspect=data)
        rendered = ReportGenerator.render(audit, fmt_l)
        if out and str(out) != "-":
            out.write_text(rendered)
            console.print(f"  [{C_OK}]✓[/] Report written to [path]{safe(out)}[/]")
        else:
            print(rendered)
        return

    if fmt_l == "json" and out:
        out.write_text(payload)
        console.print(f"  [{C_DIM}]Saved to {safe(out)}[/]")
        return

    print_inspect_apk(console, data, show_permissions=permissions)
    if output_json:
        output_json.write_text(payload)
        console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")

    if not _QUIET:
        render_next_steps(
            console,
            [
                (f"unpack scan {target} -v", "detect packer signatures & evidence chain"),
                (f"unpack inspect {target} -F html -o audit.html", "export standalone HTML report"),
            ],
        )


@app.command()
def scan(
    apk: Annotated[Path, typer.Argument(help="Path to APK file or directory (with --batch)")],
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save result as JSON (use - for stdout)"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Detailed output with SO list, DEX info, analysis hints"),
    ] = False,
    report: Annotated[
        bool,
        typer.Option("--report", "-r", help="Output plain-text report (ideal for piping to claude -p)"),
    ] = False,
    batch: Annotated[
        bool,
        typer.Option("--batch", "-b", help="Scan all APKs in directory, output JSONL"),
    ] = False,
    fmt: Annotated[
        str,
        typer.Option("--format", "-F", help="Output format: table | json | markdown | html | sarif"),
    ] = "table",
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Write --format report output to file"),
    ] = None,
):
    """Identify packer type and protection level.

    Analyzes APK static features — SO files, manifest, assets, DEX structure —
    to detect packer vendor, version, and protection level.
    Covers 24 vendors (360, Tencent, Bangbang, iJiami, NetEase, Ali, etc).
    No device required. Exit code 0 if packer found, 3 if not.
    """
    if batch:
        if not apk.is_dir():
            _fail_error("--batch requires a directory", hint=f"Pass a directory containing .apk files: unpack scan ./apks/ --batch")
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

    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )
    report_fmt = fmt_l in ("markdown", "md", "html", "sarif")
    pipe_mode = report or json_stdout or (report_fmt and (out is None or str(out) == "-"))

    if not apk.exists():
        _fail_missing(
            "APK",
            apk,
            json_stdout=json_stdout,
            plain_stderr=report or (report_fmt and out is None),
        )

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
        elif report_fmt:
            from unpack.core.reporter import ReportGenerator, Reporter

            audit = Reporter().build_audit_report(apk, scan=result_gated)
            print(ReportGenerator.render(audit, fmt_l))
        else:
            d = result_gated.to_verbose_dict() if verbose else result_gated.to_dict()
            print(json.dumps(d, indent=2, ensure_ascii=False))
        if not result_gated.packer_name:
            raise typer.Exit(EXIT_NO_PACKER)
        return

    with _spinner("Scanning APK..."):
        result = scanner.scan(apk, verbose=verbose or report_fmt, extra_apks=extra_apks or None)

    result_to_show = _gate_low_confidence(result, verbose)

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(apk, scan=result_to_show)
        out.write_text(ReportGenerator.render(audit, fmt_l))
        console.print(f"  [{C_OK}]✓[/] Report written to [path]{safe(out)}[/]")
    else:
        print_scan_result(console, result_to_show, apk)
        if verbose:
            print_verbose(console, result)

    if output_json:
        d = result.to_verbose_dict() if verbose else result.to_dict()
        output_json.write_text(json.dumps(d, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")
    elif fmt_l == "json" and out is not None:
        d = result_to_show.to_verbose_dict() if verbose else result_to_show.to_dict()
        out.write_text(json.dumps(d, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(out)}[/]")

    if not _QUIET and not report_fmt:
        render_next_steps(console, _next_steps_for_scan(apk, result_to_show))

    if not result_to_show.packer_name:
        raise typer.Exit(EXIT_NO_PACKER)


@app.command()
def analyze(
    apk: Annotated[Path, typer.Argument(help="Path to APK file")],
    prompt: Annotated[
        Optional[str],
        typer.Option("--prompt", "-p", help="Custom analysis prompt for Claude"),
    ] = None,
):
    """Generate detailed scan report and pipe to Claude for AI analysis.

    Outputs a structured plain-text report to stdout, designed to be piped
    to `claude -p` for deep analysis of packer characteristics, bypass
    strategies, and similar samples.
    """
    if not apk.exists():
        print(f"APK not found: {apk}", file=sys.stderr)
        raise typer.Exit(EXIT_NOT_FOUND)

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

    print(f"{report_text}\n---\n\n{analysis_prompt}\n")


@app.command()
def dump(
    apk: Annotated[Path, typer.Argument(help="Path to APK file")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output directory for dumped DEX files"),
    ] = Path("./unpacked"),
    device: Annotated[
        Optional[str],
        typer.Option("--device", "-d", help="ADB device serial (default: first USB device)"),
    ] = None,
    engine: Annotated[
        Optional[str],
        typer.Option("--engine", "-e", help="Force engine: frida | ebpf | memory"),
    ] = None,
    timeout: Annotated[
        int,
        typer.Option("--timeout", "-t", help="Seconds to wait for packer to unpack (default: auto)"),
    ] = 0,
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Active invocation: force-call all methods to defeat function extraction packers"),
    ] = False,
    skip_repair: Annotated[
        bool,
        typer.Option("--skip-repair", help="Skip automatic DEX repair after dump"),
    ] = False,
    no_anti_detect: Annotated[
        bool,
        typer.Option("--no-anti-detect", help="Disable Frida anti-detection bypasses"),
    ] = False,
    report_html: Annotated[
        Optional[Path],
        typer.Option("--report-html", help="Also write a standalone commercial HTML audit report"),
    ] = None,
):
    """Full unpack flow: scan -> dump -> repair -> verify.

    Requires a connected Android device. Engine is auto-selected based on
    packer type and device capabilities (eBPF > Frida > Memory).
    """
    if not apk.exists():
        _fail_missing("APK", apk)

    from unpack.core.dedup import dedup_dex_files
    from unpack.core.dispatcher import Dispatcher
    from unpack.core.reporter import Reporter, render_html
    from unpack.core.scanner import PackerScanner, ProtectionLevel
    from unpack.repair.dex_repair import DexRepairPipeline

    output.mkdir(parents=True, exist_ok=True)
    # Fixed phase count upfront (fixes the old 1/4 -> 3/5 numbering bug)
    total_phases = 4 + (1 if deep else 0) - (1 if skip_repair else 0)
    step = 0

    step += 1
    render_pipeline_step(console, step, total_phases, "Scanning packer", detail=apk.name)
    scanner = PackerScanner()
    with _spinner("Analyzing APK structure..."):
        scan_result = scanner.scan(apk)
    print_scan_result(console, scan_result, apk)

    step += 1
    render_pipeline_step(console, step, total_phases, "Dumping DEX")
    dispatcher = Dispatcher()
    wait_label = (
        f"Injecting and waiting for DEX dump ({timeout}s)..."
        if timeout
        else "Injecting and waiting for DEX dump..."
    )
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
        render_error(
            console,
            "No DEX files dumped.",
            detail=dump_result.error,
            hint="Run `unpack doctor` to check device/root/engine readiness, or try `-e memory` / `-t 30`.",
        )
        raise typer.Exit(EXIT_ERROR)

    console.print(
        f"  [{C_OK}]✓[/] Dumped [{C_OK}]{len(dump_result.dex_files)}[/] DEX file(s) "
        f"[{C_DIM}]({dump_result.duration_ms}ms)[/]"
    )

    before_count = len(list(output.glob("*.dex")))
    with _spinner("Deduplicating DEX files...", show_time=False):
        unique = dedup_dex_files(output)
    removed_count = before_count - len(unique)
    if removed_count > 0:
        console.print(
            f"  [{C_DIM}]Removed {removed_count} duplicate(s), {len(unique)} unique DEX file(s)[/]"
        )

    if deep:
        step += 1
        render_pipeline_step(console, step, total_phases, "Active invocation (deep mode)")

        if scan_result.protection_level not in (
            ProtectionLevel.FUNCTION_EXTRACTION,
            ProtectionLevel.VMP,
            ProtectionLevel.DEX2C,
        ):
            console.print(
                f"  [{C_WARN}]Packer is not function-extraction level, deep mode may not help[/]"
            )

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
                    console.print(
                        f"  [{C_OK}]✓[/] Captured [{C_OK}]{len(invoke_result.code_items)}[/] CodeItem(s)"
                    )
                    merger = CodeItemMerger()
                    merged_count = 0
                    for dex_path in list(dump_result.dex_files):
                        with _spinner(f"Merging CodeItems into {dex_path.name}...", show_time=False):
                            merge_result = merger.merge(dex_path, invoke_result.code_items)
                        if merge_result.methods_merged > 0:
                            merged_count += merge_result.methods_merged
                            console.print(
                                f"  [{C_OK}]✓[/] {safe(dex_path.name)}: "
                                f"[{C_OK}]{merge_result.methods_merged}[/] merged, "
                                f"[{C_WARN}]{merge_result.methods_still_nop}[/] still NOP"
                            )
                    if merged_count > 0:
                        console.print(f"  [{C_OK}]Total: {merged_count} methods restored[/]")
                    else:
                        console.print(
                            f"  [{C_DIM}]No NOP methods found to merge (DEX may not use function extraction)[/]"
                        )
                else:
                    msg = invoke_result.error or "no CodeItems captured"
                    console.print(f"  [{C_WARN}]{safe(msg)}[/]")
            else:
                console.print(f"  [{C_FAIL}]Could not determine package name for active invocation[/]")
        except ImportError:
            console.print(
                f"  [{C_FAIL}]Active invocation requires frida: pip install -e '.[frida]'[/]"
            )

        if not invoke_result or not invoke_result.code_items:
            try:
                from unpack.engines.active_invoke import MemoryActiveInvoker
                from unpack.utils.adb import get_device_serial

                _serial = device or get_device_serial()
                if _serial:
                    console.print(
                        f"  [{C_DIM}]Trying Frida-free active invocation (app exerciser)...[/]"
                    )
                    mem_invoker = MemoryActiveInvoker()
                    mem_invoke_result = mem_invoker.invoke(
                        serial=_serial,
                        pid="",
                        package_name=pkg_name,
                        output_dir=output,
                    )
                    if mem_invoke_result.success:
                        console.print(
                            f"  [{C_OK}]✓[/] Exercised app ({mem_invoke_result.classes_resolved} actions)"
                        )
            except Exception:
                pass

    repair_dicts: list[dict[str, Any]] = []
    if not skip_repair:
        step += 1
        render_pipeline_step(console, step, total_phases, "Repairing DEX files")
        pipeline = DexRepairPipeline()
        for dex_path in dump_result.dex_files:
            with _spinner(f"Repairing {dex_path.name}...", show_time=False):
                repair_result = pipeline.repair(dex_path)
            repair_dicts.append(
                {
                    "file": dex_path.name,
                    "success": repair_result.success,
                    "actions": repair_result.actions,
                    "nop_methods": repair_result.nop_method_count,
                    "output": str(repair_result.output_path) if repair_result.output_path else None,
                }
            )
        print_repair_summary(console, repair_dicts)

    step += 1
    render_pipeline_step(console, step, total_phases, "Verifying quality")
    with _spinner("Analyzing DEX coverage..."):
        reporter = Reporter()
        quality_report = reporter.evaluate(output, scan_result)
    print_report(console, quality_report)

    report_path = output / "report.json"
    report_path.write_text(json.dumps(quality_report.to_dict(), indent=2, ensure_ascii=False))
    console.print(f"\n  [{C_DIM}]Report saved to {safe(report_path)}[/]")

    if report_html:
        audit = reporter.build_audit_report(
            apk,
            scan=scan_result,
            quality=quality_report,
            repair_results=repair_dicts,
        )
        report_html.write_text(render_html(audit))
        console.print(f"  [{C_OK}]✓[/] HTML audit report saved to [path]{safe(report_html)}[/]")

    if not _QUIET:
        steps = [
            (f"unpack repack {apk} {output}", "rebuild an analyzable APK for jadx/JEB"),
            (f"unpack report {output} --apk {apk} -F html -o audit.html", "export commercial HTML report"),
        ]
        if quality_report.nop_methods > 0:
            steps.insert(0, (f"unpack rescan {apk} {output} -r 5", "trigger components to decrypt remaining NOP methods"))
        render_next_steps(console, steps)


@app.command()
def repair(
    dex: Annotated[Path, typer.Argument(help="DEX file or directory of DEX files")],
    in_place: Annotated[
        bool,
        typer.Option("--in-place", "-i", help="Overwrite original instead of creating *_repaired.dex"),
    ] = False,
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save results as JSON (use - for stdout)"),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-F", help="Output format: table | json | markdown | html | sarif"),
    ] = "table",
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Write --format report output to file"),
    ] = None,
):
    """Repair dumped DEX files.

    Fixes: header fields, Adler32 checksum, SHA-1 signature, map_list
    validation, CodeItem alignment. Detects NOP-only methods.
    """
    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )
    report_fmt = fmt_l in ("markdown", "md", "html", "sarif")
    pipe_mode = json_stdout or (report_fmt and (out is None or str(out) == "-"))

    if not dex.exists():
        _fail_missing("Path", dex, json_stdout=json_stdout)

    paths = _discover_dex_paths(dex)
    if not paths:
        _fail_error("No DEX files found.", json_stdout=json_stdout)

    from unpack.repair.dex_repair import DexRepairPipeline

    pipeline = DexRepairPipeline()
    has_diff = hasattr(pipeline, "repair_with_diff")

    def _run_one(p: Path) -> dict[str, Any]:
        if has_diff:
            diff = pipeline.repair_with_diff(p, in_place=in_place)
            r = diff.repair
            entry: dict[str, Any] = {
                "file": p.name,
                "success": r.success,
                "actions": r.actions,
                "nop_methods": r.nop_method_count,
                "output": str(r.output_path) if r.output_path else None,
                "health_delta": getattr(diff, "health_delta", None),
                "resolved_issues": getattr(diff, "resolved_issues", []),
            }
            return entry
        r = pipeline.repair(p, in_place=in_place)
        return {
            "file": p.name,
            "success": r.success,
            "actions": r.actions,
            "nop_methods": r.nop_method_count,
            "output": str(r.output_path) if r.output_path else None,
        }

    if pipe_mode:
        repair_results = [_run_one(p) for p in paths]
        if report_fmt:
            from unpack.core.reporter import ReportGenerator, Reporter

            audit = Reporter().build_audit_report(dex, repair_results=repair_results)
            print(ReportGenerator.render(audit, fmt_l))
        else:
            print(json.dumps(repair_results, indent=2, ensure_ascii=False))
        return

    repair_results = []
    for p in paths:
        with _spinner(f"Repairing {p.name}...", show_time=False):
            repair_results.append(_run_one(p))

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(dex, repair_results=repair_results)
        out.write_text(ReportGenerator.render(audit, fmt_l))
        console.print(f"  [{C_OK}]✓[/] Report written to [path]{safe(out)}[/]")
    else:
        print_repair_summary(console, repair_results)
        ok = sum(1 for r in repair_results if r["success"])
        console.print(f"  [{C_OK}]{ok}[/]/{len(paths)} repaired")

    if output_json:
        output_json.write_text(json.dumps(repair_results, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(repair_results, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(out)}[/]")

    if not _QUIET and not report_fmt:
        render_next_steps(console, [(f"unpack verify {dex}", "validate repaired DEX integrity")])


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(help="DEX file or directory of DEX files")],
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save results as JSON (use - for stdout)"),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-F", help="Output format: table | json | markdown | html | sarif"),
    ] = "table",
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Write --format report output to file"),
    ] = None,
):
    """Check DEX integrity and quality metrics.

    Validates magic, checksum, SHA-1, file size, section bounds.
    Reports NOP-only methods from function extraction packers.
    """
    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )
    report_fmt = fmt_l in ("markdown", "md", "html", "sarif")
    pipe_mode = json_stdout or (report_fmt and (out is None or str(out) == "-"))

    if not path.exists():
        _fail_missing("Path", path, json_stdout=json_stdout)

    paths = _discover_dex_paths(path)
    if not paths:
        _fail_error("No DEX files found.", json_stdout=json_stdout)

    from unpack.repair.verifier import DexVerifier

    verifier = DexVerifier()

    def _as_dict(name: str, result) -> dict[str, Any]:
        return {"file": name, "valid": result.valid, "issues": result.issues, "stats": result.stats}

    if pipe_mode:
        all_results = [_as_dict(p.name, verifier.verify(p)) for p in paths]
        if report_fmt:
            from unpack.core.reporter import ReportGenerator, Reporter

            audit = Reporter().build_audit_report(path, verify_results=all_results)
            print(ReportGenerator.render(audit, fmt_l))
        else:
            print(json.dumps(all_results, indent=2, ensure_ascii=False))
        return

    all_results: list[dict[str, Any]] = []
    for p in paths:
        with _spinner(f"Checking {p.name}...", show_time=False):
            result = verifier.verify(p)
        all_results.append(_as_dict(p.name, result))

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(path, verify_results=all_results)
        out.write_text(ReportGenerator.render(audit, fmt_l))
        console.print(f"  [{C_OK}]✓[/] Report written to [path]{safe(out)}[/]")
    else:
        print_verify_summary(console, all_results)

    if output_json:
        output_json.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(out)}[/]")

    failed = [r for r in all_results if not r["valid"]]
    if not _QUIET and not report_fmt and failed:
        render_next_steps(console, [(f"unpack repair {path}", f"repair {len(failed)} failing DEX file(s)")])


@app.command()
def export(
    dex_dir: Annotated[Path, typer.Argument(help="Directory containing dumped DEX files")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory")] = Path("./fart_export"),
    format: Annotated[str, typer.Option("--format", "-f", help="Export format: fart")] = "fart",
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save export summary as JSON (use - for stdout)"),
    ] = None,
):
    """Export dumped DEX files in alternative formats (e.g., FART bin/txt)."""
    json_stdout = output_json is not None and str(output_json) == "-"

    if format != "fart":
        _fail_error(f"Unknown format: {format}", json_stdout=json_stdout, hint="Supported formats: fart")

    if not dex_dir.exists():
        _fail_missing("Directory", dex_dir, json_stdout=json_stdout)

    dex_files = sorted(dex_dir.glob("*.dex"))
    if not dex_files:
        _fail_error(f"No DEX files found in {dex_dir}", json_stdout=json_stdout)

    from unpack.export.fart import FartExporter

    exporter = FartExporter()
    total_methods = 0
    exported_files: list[dict[str, Any]] = []

    for dex_path in dex_files:
        result = exporter.export(dex_path, output)
        total_methods += result.method_count
        exported_files.append(
            {
                "dex": dex_path.name,
                "methods": result.method_count,
                "bin": str(result.bin_path),
            }
        )

    payload = {
        "format": format,
        "output_dir": str(output),
        "total_methods": total_methods,
        "files": exported_files,
    }
    if json_stdout:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    rows = [
        [safe(f["dex"]), f"{f['methods']:,}", f"[path]{safe(Path(f['bin']).name)}[/]"]
        for f in exported_files
    ]
    render_table(
        console,
        [("DEX File", {}), ("Methods", {"justify": "right"}), ("Output", {})],
        rows,
        title="FART Export",
    )
    console.print(f"  [{C_OK}]✓[/] Exported {total_methods:,} methods in FART format to [path]{safe(output)}[/]")

    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")


@app.command()
def repack(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[Path, typer.Argument(help="Directory with dumped/repaired DEX files")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory")] = Path("./repacked"),
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save result as JSON (use - for stdout)"),
    ] = None,
):
    """Repack dumped DEX into an analyzable APK."""
    pipe_mode = output_json is not None and str(output_json) == "-"

    if not apk.exists():
        _fail_missing("APK", apk, json_stdout=pipe_mode)
    if not dex_dir.exists():
        _fail_missing("DEX directory", dex_dir, json_stdout=pipe_mode)

    from unpack.repack.repacker import Repacker

    repacker = Repacker()
    with _spinner(f"Repacking {apk.name}...", enabled=not pipe_mode):
        result = repacker.repack(apk, dex_dir, output)

    if not result.success:
        if pipe_mode:
            print(json.dumps({"success": False, "error": result.error}, indent=2, ensure_ascii=False))
            raise typer.Exit(EXIT_ERROR)
        render_error(console, "Repack failed", detail=result.error)
        raise typer.Exit(EXIT_ERROR)

    payload = {
        "success": result.success,
        "output": str(result.output_path),
        "dex_count": result.dex_count,
        "resources": result.resources_preserved,
    }

    if pipe_mode:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    render_kv_card(
        console,
        "REPACK COMPLETE",
        [
            ("Summary", f"Repacked [{C_OK}]{result.dex_count}[/] DEX file(s), preserved [{C_OK}]{result.resources_preserved}[/] resource(s)"),
            ("Output", f"[path]{safe(result.output_path)}[/]"),
        ],
        border_style=C_OK,
        title_style=f"bold {C_OK}",
    )

    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")

    if not _QUIET:
        render_next_steps(console, [(f"jadx-gui {result.output_path}", "open repacked APK in JADX")])


@app.command()
def rescan(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[
        Path,
        typer.Argument(help="Directory with dumped DEX files (must have report.json)"),
    ],
    device: Annotated[Optional[str], typer.Option("--device", "-d", help="ADB device serial")] = None,
    rounds: Annotated[int, typer.Option("--rounds", "-r", help="Number of trigger rounds")] = 3,
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save rescan result as JSON (use - for stdout)"),
    ] = None,
):
    """Incremental re-scan: trigger app components to decrypt more methods."""
    json_stdout = output_json is not None and str(output_json) == "-"

    if not apk.exists():
        _fail_missing("APK", apk, json_stdout=json_stdout)
    if not dex_dir.exists() or not dex_dir.is_dir():
        _fail_error(f"Directory not found: {dex_dir}", json_stdout=json_stdout)

    report_path = dex_dir / "report.json"
    if not report_path.exists():
        _fail_error(
            f"No report.json found in {dex_dir}.",
            json_stdout=json_stdout,
            hint=f"Run `unpack dump {apk} -o {dex_dir}` first.",
        )

    from unpack.engines.rescan import ComponentExtractor, IncrementalRescanner, RescanPlanner
    from unpack.utils.adb import get_device_serial
    from unpack.utils.apk import get_package_name

    planner = RescanPlanner()
    plan = planner.plan(report_path)

    if plan.nop_count == 0:
        if json_stdout:
            print(json.dumps({"success": True, "nop_count": 0, "methods_recovered": 0}))
        else:
            console.print(f"  [{C_OK}]✓[/] No NOP-only methods found — nothing to rescan.")
        return

    if not json_stdout:
        console.print(
            f"  [{C_WARN}]{plan.nop_count}[/] NOP method(s) across "
            f"[{C_INFO}]{len(plan.dex_targets)}[/] DEX file(s)"
        )

    pkg_name = get_package_name(apk)
    if not pkg_name:
        _fail_error("Could not determine package name from APK.", json_stdout=json_stdout)

    extractor = ComponentExtractor()
    manifest_strings = extractor.extract_manifest_strings(apk)
    plan.components = extractor.classify_components(manifest_strings)
    if not json_stdout:
        console.print(f"  [{C_DIM}]Found {len(plan.components)} component(s) to trigger[/]")

    serial = device or get_device_serial()
    if not serial:
        _fail_error(
            "No ADB device connected.",
            json_stdout=json_stdout,
            hint="Connect a rooted Android device over USB and run `unpack doctor`.",
            code=EXIT_NO_DEVICE,
        )

    rescanner = IncrementalRescanner(rounds=rounds)
    with _spinner(f"Running {rounds} round(s)...", enabled=not json_stdout):
        result = rescanner.rescan(serial, pkg_name, plan, dex_dir)

    payload = {
        "success": result.success,
        "rounds": result.rounds,
        "methods_recovered": result.methods_recovered,
        "methods_still_nop": result.methods_still_nop,
        "new_dex_files": [str(p) for p in (result.new_dex_files or [])],
        "error": result.error,
    }
    if json_stdout:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    if result.new_dex_files:
        console.print(f"  [{C_DIM}]Re-dumped {len(result.new_dex_files)} new DEX file(s):[/]")
        for new_path in result.new_dex_files:
            console.print(f"    [{C_OK}]+[/] {safe(Path(new_path).name)}")

    if result.success:
        console.print(
            f"  [{C_OK}]✓[/] Recovered [{C_OK}]{result.methods_recovered}[/] method(s) over {result.rounds} round(s)"
        )
    elif result.error:
        render_error(console, "Rescan failed", detail=result.error)
    if result.methods_still_nop:
        console.print(f"  [{C_WARN}]{result.methods_still_nop}[/] method(s) still NOP")

    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")


@app.command()
def reassemble(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[Path, typer.Argument(help="Directory with dumped DEX files")],
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save class mapping summary as JSON (use - for stdout)"),
    ] = None,
):
    """Map dumped DEX classes back to original APK DEX numbering."""
    from unpack.repair.reassemble import ClassMapper, DexClassLister

    json_stdout = output_json is not None and str(output_json) == "-"

    if not apk.exists():
        _fail_missing("APK", apk, json_stdout=json_stdout)
    if not dex_dir.exists():
        _fail_missing("Path", dex_dir, json_stdout=json_stdout)

    lister = DexClassLister()
    mapper = ClassMapper()

    with _spinner("Reading original APK classes...", enabled=not json_stdout):
        original = lister.list_from_apk(apk)
    if not original:
        _fail_error("No classes*.dex found in APK.", json_stdout=json_stdout)

    dex_paths = _discover_dex_paths(dex_dir)
    if not dex_paths:
        _fail_error(f"No DEX files found in: {dex_dir}", json_stdout=json_stdout)

    dumped: dict[str, list[str]] = {}
    with _spinner(f"Reading {len(dex_paths)} dumped DEX file(s)...", enabled=not json_stdout):
        for p in dex_paths:
            try:
                dumped[p.name] = lister.list_from_file(p)
            except Exception:
                dumped[p.name] = []

    mapping = mapper.map_classes(original, dumped)
    classes_mapped = sum(1 for v in mapping.values() if v is not None)
    classes_unmapped = len(mapping) - classes_mapped
    distribution = Counter(v for v in mapping.values() if v is not None)

    payload = {
        "classes_mapped": classes_mapped,
        "classes_unmapped": classes_unmapped,
        "distribution": {k: distribution.get(k, 0) for k in sorted(original.keys())},
    }
    if json_stdout:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    rows = [[safe(dex_name), f"{distribution.get(dex_name, 0):,}"] for dex_name in sorted(original.keys())]
    unmapped_count = distribution.get("(unmapped)", 0)
    if unmapped_count:
        rows.append([f"[{C_WARN}](unmapped)[/]", f"[{C_WARN}]{unmapped_count:,}[/]"])
    render_table(
        console,
        [("Original DEX", {}), ("Classes Mapped", {"justify": "right"})],
        rows,
        title="DEX Class Reassembly",
    )
    console.print(f"  [{C_OK}]{classes_mapped:,}[/] mapped, [{C_WARN}]{classes_unmapped:,}[/] unmapped")

    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")


@app.command()
def vmp(
    dex_dir: Annotated[Path, typer.Argument(help="Directory with DEX files or single DEX")],
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save VMP report as JSON (use - for stdout)"),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-F", help="Output format: table | json | markdown | html | sarif"),
    ] = "table",
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Write --format report output to file"),
    ] = None,
):
    """Classify methods as normal / NOP / VMP-stub."""
    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )
    report_fmt = fmt_l in ("markdown", "md", "html", "sarif")
    pipe_mode = json_stdout or (report_fmt and (out is None or str(out) == "-"))

    if not dex_dir.exists():
        _fail_missing("Path", dex_dir, json_stdout=json_stdout)

    paths = _discover_dex_paths(dex_dir)
    if not paths:
        _fail_error("No DEX files found.", json_stdout=json_stdout)

    from unpack.analysis.vmp import VmpDetector

    detector = VmpDetector()
    all_vmp_methods: list[dict[str, Any]] = []
    all_call_graph: list[dict[str, Any]] = []
    per_dex: list[dict[str, Any]] = []
    total = normal = nop = vmp_total = 0

    with _spinner(f"Classifying methods across {len(paths)} DEX file(s)...", enabled=not pipe_mode):
        for p in paths:
            report = detector.analyze_dex(p.read_bytes())
            total += report.total_methods
            normal += report.normal_count
            nop += report.nop_count
            vmp_total += report.vmp_count
            all_vmp_methods.extend({**m, "dex_file": p.name} for m in report.vmp_methods)
            all_call_graph.extend({**c, "dex_file": p.name} for c in report.call_graph)
            per_dex.append(
                {
                    "file": p.name,
                    "normal": report.normal_count,
                    "nop": report.nop_count,
                    "vmp": report.vmp_count,
                }
            )

    # Exact 6-key JSON contract preserved!
    data = {
        "total_methods": total,
        "normal_count": normal,
        "nop_count": nop,
        "vmp_count": vmp_total,
        "vmp_methods": all_vmp_methods,
        "call_graph": all_call_graph,
    }

    # Fixed bug: pure stdout in pipe mode (zero Rich output printed before JSON)
    if pipe_mode:
        if report_fmt:
            from unpack.core.reporter import ReportGenerator, Reporter

            audit = Reporter().build_audit_report(dex_dir, vmp=data)
            print(ReportGenerator.render(audit, fmt_l))
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(dex_dir, vmp=data)
        out.write_text(ReportGenerator.render(audit, fmt_l))
        console.print(f"  [{C_OK}]✓[/] Report written to [path]{safe(out)}[/]")
    else:
        print_vmp_summary(
            console,
            per_dex,
            {"total_methods": total, "normal_count": normal, "nop_count": nop, "vmp_count": vmp_total},
            vmp_methods=all_vmp_methods,
        )

    if output_json:
        output_json.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(out)}[/]")


@app.command()
def xref(
    dex_dir: Annotated[Path, typer.Argument(help="Directory with DEX files or single DEX")],
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save xref report as JSON (use - for stdout)"),
    ] = None,
    search: Annotated[
        Optional[str],
        typer.Option("--search", "-s", help="Filter reflection call sites by class/method/target"),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-F", help="Output format: table | json | markdown | html | sarif"),
    ] = "table",
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Write --format report output to file"),
    ] = None,
):
    """Build a cross-reference index: strings, method calls, fields, reflection."""
    from unpack.analysis.xref import XrefBuilder

    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )
    report_fmt = fmt_l in ("markdown", "md", "html", "sarif")
    pipe_mode = json_stdout or (report_fmt and (out is None or str(out) == "-"))

    if not dex_dir.exists():
        _fail_missing("Path", dex_dir, json_stdout=json_stdout)

    paths = _discover_dex_paths(dex_dir)
    if not paths:
        _fail_error("No DEX files found.", json_stdout=json_stdout)

    builder = XrefBuilder()
    with _spinner(f"Building cross-reference index for {len(paths)} DEX file(s)...", enabled=not pipe_mode):
        reports = [builder.build_file(p) for p in paths]
        merged = XrefBuilder.merge(reports)

    if pipe_mode:
        if report_fmt:
            from unpack.core.reporter import ReportGenerator, Reporter

            audit = Reporter().build_audit_report(dex_dir, xref=merged)
            print(ReportGenerator.render(audit, fmt_l))
        else:
            print(json.dumps(merged.to_dict(), indent=2, ensure_ascii=False))
        return

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(dex_dir, xref=merged)
        out.write_text(ReportGenerator.render(audit, fmt_l))
        console.print(f"  [{C_OK}]✓[/] Report written to [path]{safe(out)}[/]")
    else:
        print_xref_summary(console, merged, file_count=len(paths), search=search)

    if output_json:
        output_json.write_text(json.dumps(merged.to_dict(), indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(merged.to_dict(), indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]Saved to {safe(out)}[/]")


@app.command()
def report(
    target: Annotated[
        Path,
        typer.Argument(help="Unpacked DEX directory, single DEX file, or APK file"),
    ],
    apk: Annotated[
        Optional[Path],
        typer.Option("--apk", "-a", help="Optional source APK to include packer & static security profile"),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-F", help="Report format: html | markdown | sarif | json"),
    ] = "markdown",
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Output file path (omit or use - for stdout)"),
    ] = None,
    title: Annotated[
        Optional[str],
        typer.Option("--title", help="Custom report title"),
    ] = None,
    include_vmp: Annotated[
        bool,
        typer.Option("--vmp/--no-vmp", help="Include VMP method classification for DEX targets"),
    ] = True,
    include_xref: Annotated[
        bool,
        typer.Option("--xref/--no-xref", help="Include cross-reference reflection scan for DEX targets"),
    ] = False,
):
    """Generate a commercial audit report (HTML5 / Markdown / SARIF 2.1.0 / JSON)."""
    fmt_l = fmt.strip().lower()
    if fmt_l not in ("html", "markdown", "md", "sarif", "json"):
        _fail_error(
            f"Unsupported format: {fmt}",
            hint="Use --format html | markdown | sarif | json",
        )

    to_stdout = out is None or str(out) == "-"
    if not target.exists():
        _fail_missing("Target", target, json_stdout=(fmt_l == "json" and to_stdout))
    if apk is not None and not apk.exists():
        _fail_missing("APK", apk, json_stdout=(fmt_l == "json" and to_stdout))

    from unpack.core.reporter import ReportGenerator, Reporter

    reporter = Reporter()
    scan_data: Any = None
    inspect_data: Any = None
    quality_data: Any = None
    verify_list: list[dict[str, Any]] = []
    vmp_data: dict[str, Any] | None = None
    xref_data: Any = None

    source_apk = apk if apk is not None else (target if target.is_file() and target.suffix.lower() == ".apk" else None)

    with _spinner("Collecting audit evidence...", enabled=not to_stdout):
        if source_apk is not None:
            from unpack.core.scanner import PackerScanner

            scan_data = PackerScanner().scan(source_apk, verbose=True)
            inspect_data = _inspect_apk_impl(source_apk)

        if target.is_dir() or target.suffix.lower() in (".dex", ".cdex"):
            dex_paths = _discover_dex_paths(target)
            if target.is_dir():
                quality_data = reporter.evaluate(target, scan_data)
            if dex_paths:
                from unpack.repair.verifier import DexVerifier

                verifier = DexVerifier()
                verify_list = [
                    {
                        "file": p.name,
                        "valid": (vr := verifier.verify(p)).valid,
                        "issues": vr.issues,
                        "stats": vr.stats,
                    }
                    for p in dex_paths
                ]
                if include_vmp:
                    from unpack.analysis.vmp import VmpDetector

                    detector = VmpDetector()
                    tot = norm = nops = vmps = 0
                    v_methods: list[dict[str, Any]] = []
                    c_graph: list[dict[str, Any]] = []
                    for p in dex_paths:
                        vr_vmp = detector.analyze_dex(p.read_bytes())
                        tot += vr_vmp.total_methods
                        norm += vr_vmp.normal_count
                        nops += vr_vmp.nop_count
                        vmps += vr_vmp.vmp_count
                        v_methods.extend({**m, "dex_file": p.name} for m in vr_vmp.vmp_methods)
                        c_graph.extend({**c, "dex_file": p.name} for c in vr_vmp.call_graph)
                    vmp_data = {
                        "total_methods": tot,
                        "normal_count": norm,
                        "nop_count": nops,
                        "vmp_count": vmps,
                        "vmp_methods": v_methods,
                        "call_graph": c_graph,
                    }
                if include_xref:
                    from unpack.analysis.xref import XrefBuilder

                    builder = XrefBuilder()
                    xref_data = XrefBuilder.merge([builder.build_file(p) for p in dex_paths])

    audit = reporter.build_audit_report(
        source_apk or target,
        scan=scan_data,
        inspect=inspect_data,
        quality=quality_data,
        verify_results=verify_list,
        vmp=vmp_data,
        xref=xref_data,
        title=title,
    )
    rendered = ReportGenerator.render(audit, fmt_l)

    if to_stdout:
        print(rendered)
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered)
    render_kv_card(
        console,
        "AUDIT REPORT GENERATED",
        [
            ("Format", f"[{C_INFO}]{safe(fmt_l.upper())}[/]"),
            ("Output", f"[path]{safe(out)}[/]"),
            ("Grade", f"[{C_OK if audit.grade in ('A', 'B') else C_WARN}]{audit.grade}[/] ({audit.risk_score}/100)"),
            ("Findings", f"{len(audit.findings)}"),
        ],
        border_style=C_OK,
        title_style=f"bold {C_OK}",
    )


@app.command()
def web(
    port: Annotated[int, typer.Option("--port", "-p", help="Port to listen on")] = 8080,
    host: Annotated[str, typer.Option("--host", help="Host to bind to")] = "127.0.0.1",
):
    """Launch Unpack Studio web UI.

    Opens a browser-based interface for scan, inspect, dump, repair, and verify.
    Requires flask: pip install -e '.[web]'
    """
    try:
        from unpack.web import create_app
    except ImportError:
        render_error(
            console,
            "Flask not installed.",
            hint="Install web extras with: pip install -e '.[web]'",
        )
        raise typer.Exit(EXIT_ERROR)

    console.print(f"  [{C_OK}]✓[/] [{C_HEADER}]UNPACK Studio[/]  http://{host}:{port}")
    webapp = create_app()
    webapp.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    app()
