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
    format_bytes,
    print_ai_analysis,
    print_ai_config,
    print_ai_test_result,
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
    print_workspace_detail,
    print_workspace_list,
    print_xref_summary,
    render_error,
    render_header,
    render_kv_card,
    render_next_steps,
    render_pipeline_blueprint,
    render_pipeline_step,
    render_table,
    render_wizard_step,
    safe,
)
from unpack.i18n import get_lang, resolve_lang, set_lang, t, use_lang


class _BilingualRootGroup(typer.core.TyperGroup):
    """Intercept root `--help` so `--lang zh --help` / `-L zh --help` / `UNPACK_LANG=zh` renders Chinese help."""

    def parse_args(self, ctx, args: list[str]) -> list[str]:
        found_lang: str | None = None
        found_no_color = False
        has_top_help = False

        idx = 0
        while idx < len(args):
            tok = args[idx]
            if tok in ("--help", "-h"):
                has_top_help = True
                idx += 1
                continue
            if tok == "--no-color":
                found_no_color = True
                idx += 1
                continue
            if tok in ("--lang", "-L"):
                if idx + 1 < len(args):
                    found_lang = args[idx + 1]
                    idx += 2
                    continue
                idx += 1
                continue
            if tok.startswith("--lang="):
                found_lang = tok.split("=", 1)[1]
                idx += 1
                continue
            if tok.startswith("-L") and len(tok) > 2:
                found_lang = tok[2:]
                idx += 1
                continue
            if tok.startswith("-"):
                idx += 1
                continue
            # First positional token is a subcommand; let Typer handle subcommand `--help`.
            break

        if has_top_help and resolve_lang(found_lang) == "zh":
            _configure_consoles(no_color=found_no_color, quiet=False)
            with use_lang("zh"):
                _print_main_help()
            ctx.exit(EXIT_OK)

        return super().parse_args(ctx, args)


app = typer.Typer(
    name="unpack",
    cls=_BilingualRootGroup,
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


def _apply_lang(lang: str | None) -> str:
    """Apply an explicit per-command language override if provided, returning active lang."""
    if lang is not None:
        return set_lang(lang)
    return get_lang()


def _print_main_help() -> None:
    eff = get_lang()
    console.print()
    render_header(
        console,
        "UNPACK",
        subtitle=t("cli.subtitle", eff),
        meta=f"v{__version__}",
    )

    groups: list[tuple[str, list[tuple[str, str]]]] = [
        (
            t("cli.group.onboarding", eff),
            [
                ("guide", t("cli.cmd.guide", eff)),
                ("wizard", t("cli.cmd.wizard", eff)),
                ("pipeline", t("cli.cmd.pipeline", eff)),
            ],
        ),
        (
            t("cli.group.recon", eff),
            [
                ("scan", t("cli.cmd.scan", eff)),
                ("inspect", t("cli.cmd.inspect", eff)),
                ("analyze", t("cli.cmd.analyze", eff)),
            ],
        ),
        (
            t("cli.group.unpack", eff),
            [
                ("dump", t("cli.cmd.dump", eff)),
                ("repair", t("cli.cmd.repair", eff)),
                ("verify", t("cli.cmd.verify", eff)),
                ("rescan", t("cli.cmd.rescan", eff)),
                ("reassemble", t("cli.cmd.reassemble", eff)),
                ("repack", t("cli.cmd.repack", eff)),
            ],
        ),
        (
            t("cli.group.post", eff),
            [
                ("vmp", t("cli.cmd.vmp", eff)),
                ("xref", t("cli.cmd.xref", eff)),
                ("export", t("cli.cmd.export", eff)),
            ],
        ),
        (
            t("cli.group.reporting", eff),
            [
                ("report", t("cli.cmd.report", eff)),
                ("doctor", t("cli.cmd.doctor", eff)),
                ("web", t("cli.cmd.web", eff)),
            ],
        ),
        (
            t("cli.group.ai_ws", eff),
            [
                ("ai", t("cli.cmd.ai", eff)),
                ("workspace", t("cli.cmd.workspace", eff)),
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

    lang_flag = " --lang zh" if eff == "zh" else ""
    examples = [
        (f"unpack guide{lang_flag}", t("cli.example.guide", eff)),
        (f"unpack doctor{lang_flag}", t("cli.example.doctor", eff)),
        (f"unpack scan app.apk -v{lang_flag}", t("cli.example.scan", eff)),
        (f"unpack inspect app.apk --permissions{lang_flag}", t("cli.example.inspect", eff)),
        (f"unpack pipeline app.apk{lang_flag}", t("cli.example.pipeline", eff)),
        ("unpack dump app.apk --deep", t("cli.example.dump", eff)),
        ("unpack repair ./unpacked/ && unpack verify ./unpacked/", t("cli.example.repair", eff)),
        (f"unpack report ./unpacked/ --apk app.apk -F html -o audit.html{lang_flag}", t("cli.example.report", eff)),
        (f"unpack ai show{lang_flag}", t("cli.example.ai", eff)),
        (f"unpack workspace list{lang_flag}", t("cli.example.workspace", eff)),
        ("unpack web --port 8080", t("cli.example.web", eff)),
    ]
    console.print(f"\n[{C_LABEL}]{safe(t('cli.quickstart', eff))}[/]")
    for cmd, desc in examples:
        console.print(f"  [{C_INFO}]$[/] [cmd]{safe(cmd)}[/]  [{C_DIM}]# {safe(desc)}[/]")
    console.print(
        f"\n  [{C_DIM}]{safe(t('cli.global_flags', eff))}[/]\n"
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
    lang: Annotated[
        Optional[str],
        typer.Option(
            "--lang",
            "-L",
            help="Display language: en | zh | auto (default: en, or UNPACK_LANG)",
        ),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable ANSI color output (also honors NO_COLOR)"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Reduce non-essential output, spinners, and hints"),
    ] = False,
):
    set_lang(lang)
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
    eff = get_lang()
    msg = t("cli.not_found", eff, label=label, path=path)
    if json_stdout:
        print(json.dumps({"error": f"{label} not found: {path}"}))
    elif plain_stderr:
        print(f"Error: {msg}", file=sys.stderr)
    else:
        render_error(
            console,
            msg,
            hint=hint or t("cli.not_found_hint", eff),
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
            err_console.print(f"  [{C_DIM}]{safe(t('cli.done_in', get_lang(), elapsed=elapsed))}[/]")


def _next_steps_for_scan(apk: Path, result) -> list[tuple[str, str]]:
    eff = get_lang()
    lf = " --lang zh" if eff == "zh" else ""
    if not result.packer_name:
        return [
            (f"unpack inspect {apk}{lf}", t("cli.next.inspect_apk", eff)),
            (f"unpack pipeline {apk} --mode offline --execute{lf}", t("pipe.cmd.offline_alt", eff)),
            (f"unpack scan {apk} -v{lf}", t("cli.next.scan_verbose", eff)),
        ]
    level = getattr(result.protection_level, "value", str(result.protection_level))
    if level == "function_extraction":
        return [
            (f"unpack dump {apk} --deep --explain{lf}", t("cli.next.explain_pipeline", eff)),
            (f"unpack dump {apk} --deep{lf}", t("cli.next.dump_deep", eff)),
            (f"unpack inspect {apk}{lf}", t("cli.next.inspect_profile", eff)),
        ]
    if level in ("vmp", "dex2c"):
        return [
            (f"unpack inspect {apk}{lf}", t("cli.next.inspect_elf", eff)),
            (f"unpack dump {apk} --explain{lf}", t("cli.next.explain_pipeline", eff)),
            (f"unpack dump {apk}{lf}", t("cli.next.dump_vmp", eff)),
        ]
    return [
        (f"unpack dump {apk} --explain{lf}", t("cli.next.explain_pipeline", eff)),
        (f"unpack dump {apk}{lf}", t("cli.next.dump_full", eff)),
        (f"unpack scan {apk} -F html -o scan.html{lf}", t("cli.next.export_html", eff)),
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
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Check Python dependencies, RE tools, connected devices, and engine readiness."""
    eff = _apply_lang(lang)
    pipe_json = fmt.lower() == "json" or (output_json is not None and str(output_json) == "-")
    with _spinner(t("cli.spinner.doctor", eff), enabled=not pipe_json):
        report = _run_doctor_impl(check_devices=not no_devices, device_serial=device)

    payload = json.dumps(report, indent=2, ensure_ascii=False)
    if pipe_json:
        print(payload)
        return

    print_doctor_report(console, report, lang=eff)
    if output_json:
        output_json.write_text(payload)
        console.print(f"\n  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


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
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display/report language: en | zh | auto"),
    ] = None,
):
    """Deep static inspection of an APK (manifest, signing, libs) or DEX (classes, methods, disasm)."""
    eff = _apply_lang(lang)
    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )

    if not target.exists():
        _fail_missing("Target", target, json_stdout=json_stdout)

    is_dex = target.suffix.lower() in (".dex", ".cdex")
    if is_dex:
        with _spinner(t("cli.spinner.inspect_dex", eff, name=target.name), enabled=not json_stdout and fmt_l == "table"):
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
            console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")
            return
        print_inspect_dex(
            console,
            data.get("overview") or {},
            classes=data.get("classes"),
            class_detail=data.get("class_detail"),
            disasm=data.get("disasm"),
            lang=eff,
        )
        if output_json:
            output_json.write_text(payload)
            console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
        return

    # APK inspection
    with _spinner(t("cli.spinner.inspect_apk", eff, name=target.name), enabled=not json_stdout and fmt_l == "table"):
        data = _inspect_apk_impl(target)

    payload = json.dumps(data, indent=2, ensure_ascii=False)
    if json_stdout:
        print(payload)
        return

    if fmt_l in ("markdown", "md", "html", "sarif"):
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(target, inspect=data, lang=eff)
        rendered = ReportGenerator.render(audit, fmt_l, lang=eff)
        if out and str(out) != "-":
            out.write_text(rendered)
            console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
        else:
            print(rendered)
        return

    if fmt_l == "json" and out:
        out.write_text(payload)
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")
        return

    print_inspect_apk(console, data, show_permissions=permissions, lang=eff)
    if output_json:
        output_json.write_text(payload)
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")

    if not _QUIET:
        lf = " --lang zh" if eff == "zh" else ""
        render_next_steps(
            console,
            [
                (f"unpack scan {target} -v{lf}", t("cli.next.scan_evidence", eff)),
                (f"unpack inspect {target} -F html -o audit.html{lf}", t("cli.next.export_html", eff)),
            ],
            lang=eff,
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
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display/report language: en | zh | auto"),
    ] = None,
):
    """Identify packer type and protection level.

    Analyzes APK static features — SO files, manifest, assets, DEX structure —
    to detect packer vendor, version, and protection level.
    Covers 24 vendors (360, Tencent, Bangbang, iJiami, NetEase, Ali, etc).
    No device required. Exit code 0 if packer found, 3 if not.
    """
    eff = _apply_lang(lang)
    if batch:
        if not apk.is_dir():
            _fail_error("--batch requires a directory", hint="Pass a directory containing .apk files: unpack scan ./apks/ --batch")
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
        console.print(f"  [{C_DIM}]{safe(t('cli.split_apks_found', eff, count=len(extra_apks)))}[/]")
    scanner = PackerScanner()

    if pipe_mode:
        result = scanner.scan(apk, verbose=True, extra_apks=extra_apks or None)
        result_gated = _gate_low_confidence(result, verbose)
        if report:
            print(result_gated.to_report())
        elif report_fmt:
            from unpack.core.reporter import ReportGenerator, Reporter

            audit = Reporter().build_audit_report(apk, scan=result_gated, lang=eff)
            print(ReportGenerator.render(audit, fmt_l, lang=eff))
        else:
            d = result_gated.to_verbose_dict() if verbose else result_gated.to_dict()
            print(json.dumps(d, indent=2, ensure_ascii=False))
        if not result_gated.packer_name:
            raise typer.Exit(EXIT_NO_PACKER)
        return

    with _spinner(t("cli.spinner.scan", eff)):
        result = scanner.scan(apk, verbose=verbose or report_fmt, extra_apks=extra_apks or None)

    result_to_show = _gate_low_confidence(result, verbose)

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(apk, scan=result_to_show, lang=eff)
        out.write_text(ReportGenerator.render(audit, fmt_l, lang=eff))
        console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
    else:
        print_scan_result(console, result_to_show, apk, lang=eff)
        if verbose:
            print_verbose(console, result, lang=eff)

    if output_json:
        d = result.to_verbose_dict() if verbose else result.to_dict()
        output_json.write_text(json.dumps(d, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    elif fmt_l == "json" and out is not None:
        d = result_to_show.to_verbose_dict() if verbose else result_to_show.to_dict()
        out.write_text(json.dumps(d, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")

    if not _QUIET and not report_fmt:
        render_next_steps(console, _next_steps_for_scan(apk, result_to_show), lang=eff)

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
    explain: Annotated[
        bool,
        typer.Option("--explain", "--dry-run", help="Render visual Pipeline Execution Blueprint & live preflight checks without running"),
    ] = False,
    no_devices: Annotated[
        bool,
        typer.Option("--no-devices", help="Skip live ADB device probing when using --explain"),
    ] = False,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display/report language: en | zh | auto"),
    ] = None,
):
    """Full unpack flow: scan -> dump -> repair -> verify.

    Requires a connected Android device. Pass --explain / --dry-run to preview
    the full stage-by-stage execution blueprint, live preflight checks, and
    packer-aware flag recommendations without touching a device.
    """
    eff = _apply_lang(lang)
    if not apk.exists():
        _fail_missing("APK", apk)

    if explain:
        with _spinner(t("cli.spinner.pipeline", eff)):
            plan = build_pipeline_plan(
                apk,
                output=output,
                device=device,
                engine=engine,
                timeout=timeout,
                deep=deep,
                skip_repair=skip_repair,
                no_anti_detect=no_anti_detect,
                report_html=report_html,
                mode="deep" if deep else "standard",
                check_devices=not no_devices,
                lang=eff,
            )
        render_pipeline_blueprint(console, plan, lang=eff)
        return

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
    render_pipeline_step(console, step, total_phases, t("cli.step.scan", eff), detail=apk.name, lang=eff)
    scanner = PackerScanner()
    with _spinner(t("cli.spinner.analyze_apk", eff)):
        scan_result = scanner.scan(apk)
    print_scan_result(console, scan_result, apk, lang=eff)

    step += 1
    render_pipeline_step(console, step, total_phases, t("cli.step.dump", eff), lang=eff)
    dispatcher = Dispatcher()
    wait_label = (
        t("cli.spinner.dump_wait", eff, timeout=timeout)
        if timeout
        else t("cli.spinner.dump", eff)
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
            t("cli.dump.no_dex", eff),
            detail=dump_result.error,
            hint=t("cli.dump.no_dex_hint", eff),
            lang=eff,
        )
        raise typer.Exit(EXIT_ERROR)

    console.print(
        f"  [{C_OK}]✓[/] {safe(t('cli.dump.dumped_count', eff, count=len(dump_result.dex_files)))} "
        f"[{C_DIM}]({dump_result.duration_ms}ms)[/]"
    )

    before_count = len(list(output.glob("*.dex")))
    with _spinner(t("cli.spinner.dedup", eff), show_time=False):
        unique = dedup_dex_files(output)
    removed_count = before_count - len(unique)
    if removed_count > 0:
        console.print(
            f"  [{C_DIM}]{safe(t('cli.dump.dedup_removed', eff, removed=removed_count, unique=len(unique)))}[/]"
        )

    if deep:
        step += 1
        render_pipeline_step(console, step, total_phases, t("cli.step.deep", eff), lang=eff)

        if scan_result.protection_level not in (
            ProtectionLevel.FUNCTION_EXTRACTION,
            ProtectionLevel.VMP,
            ProtectionLevel.DEX2C,
        ):
            console.print(
                f"  [{C_WARN}]{safe(t('cli.dump.deep_warn', eff))}[/]"
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
        render_pipeline_step(console, step, total_phases, t("cli.step.repair", eff), lang=eff)
        pipeline = DexRepairPipeline()
        for dex_path in dump_result.dex_files:
            with _spinner(t("cli.spinner.repair", eff, name=dex_path.name), show_time=False):
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
        print_repair_summary(console, repair_dicts, lang=eff)

    step += 1
    render_pipeline_step(console, step, total_phases, t("cli.step.verify", eff), lang=eff)
    with _spinner(t("cli.spinner.coverage", eff)):
        reporter = Reporter()
        quality_report = reporter.evaluate(output, scan_result)
    print_report(console, quality_report, lang=eff)

    report_path = output / "report.json"
    report_path.write_text(json.dumps(quality_report.to_dict(), indent=2, ensure_ascii=False))
    console.print(f"\n  [{C_DIM}]{safe(t('cli.dump.report_saved', eff, path=report_path))}[/]")

    if report_html:
        audit = reporter.build_audit_report(
            apk,
            scan=scan_result,
            quality=quality_report,
            repair_results=repair_dicts,
            lang=eff,
        )
        report_html.write_text(render_html(audit, lang=eff))
        console.print(f"  [{C_OK}]✓[/] {safe(t('cli.html_report_saved', eff, path=report_html))}")

    if not _QUIET:
        lf = " --lang zh" if eff == "zh" else ""
        steps = [
            (f"unpack repack {apk} {output}", t("cli.next.repack_jadx", eff)),
            (f"unpack report {output} --apk {apk} -F html -o audit.html{lf}", t("cli.next.commercial_report", eff)),
        ]
        if quality_report.nop_methods > 0:
            steps.insert(0, (f"unpack rescan {apk} {output} -r 5", t("cli.next.rescan_nop", eff)))
        render_next_steps(console, steps, lang=eff)


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
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display/report language: en | zh | auto"),
    ] = None,
):
    """Repair dumped DEX files.

    Fixes: header fields, Adler32 checksum, SHA-1 signature, map_list
    validation, CodeItem alignment. Detects NOP-only methods.
    """
    eff = _apply_lang(lang)
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
        _fail_error(t("cli.no_dex_found", eff), json_stdout=json_stdout)

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

            audit = Reporter().build_audit_report(dex, repair_results=repair_results, lang=eff)
            print(ReportGenerator.render(audit, fmt_l, lang=eff))
        else:
            print(json.dumps(repair_results, indent=2, ensure_ascii=False))
        return

    repair_results = []
    for p in paths:
        with _spinner(t("cli.spinner.repair", eff, name=p.name), show_time=False):
            repair_results.append(_run_one(p))

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(dex, repair_results=repair_results, lang=eff)
        out.write_text(ReportGenerator.render(audit, fmt_l, lang=eff))
        console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
    else:
        print_repair_summary(console, repair_results, lang=eff)
        ok = sum(1 for r in repair_results if r["success"])
        console.print(f"  [{C_OK}]{ok}[/]/{len(paths)} repaired")

    if output_json:
        output_json.write_text(json.dumps(repair_results, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(repair_results, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")

    if not _QUIET and not report_fmt:
        lf = " --lang zh" if eff == "zh" else ""
        render_next_steps(console, [(f"unpack verify {dex}{lf}", t("cli.next.verify_repaired", eff))], lang=eff)


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
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display/report language: en | zh | auto"),
    ] = None,
):
    """Check DEX integrity and quality metrics.

    Validates magic, checksum, SHA-1, file size, section bounds.
    Reports NOP-only methods from function extraction packers.
    """
    eff = _apply_lang(lang)
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
        _fail_error(t("cli.no_dex_found", eff), json_stdout=json_stdout)

    from unpack.repair.verifier import DexVerifier

    verifier = DexVerifier()

    def _as_dict(name: str, result) -> dict[str, Any]:
        return {"file": name, "valid": result.valid, "issues": result.issues, "stats": result.stats}

    if pipe_mode:
        all_results = [_as_dict(p.name, verifier.verify(p)) for p in paths]
        if report_fmt:
            from unpack.core.reporter import ReportGenerator, Reporter

            audit = Reporter().build_audit_report(path, verify_results=all_results, lang=eff)
            print(ReportGenerator.render(audit, fmt_l, lang=eff))
        else:
            print(json.dumps(all_results, indent=2, ensure_ascii=False))
        return

    all_results: list[dict[str, Any]] = []
    for p in paths:
        with _spinner(t("cli.spinner.verify", eff, name=p.name), show_time=False):
            result = verifier.verify(p)
        all_results.append(_as_dict(p.name, result))

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(path, verify_results=all_results, lang=eff)
        out.write_text(ReportGenerator.render(audit, fmt_l, lang=eff))
        console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
    else:
        print_verify_summary(console, all_results, lang=eff)

    if output_json:
        output_json.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")

    failed = [r for r in all_results if not r["valid"]]
    if not _QUIET and not report_fmt and failed:
        lf = " --lang zh" if eff == "zh" else ""
        render_next_steps(
            console,
            [(f"unpack repair {path}{lf}", t("cli.next.repair_failing", eff, count=len(failed)))],
            lang=eff,
        )


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
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display/report language: en | zh | auto"),
    ] = None,
):
    """Classify methods as normal / NOP / VMP-stub."""
    eff = _apply_lang(lang)
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
        _fail_error(t("cli.no_dex_found", eff), json_stdout=json_stdout)

    from unpack.analysis.vmp import VmpDetector

    detector = VmpDetector()
    all_vmp_methods: list[dict[str, Any]] = []
    all_call_graph: list[dict[str, Any]] = []
    per_dex: list[dict[str, Any]] = []
    total = normal = nop = vmp_total = 0

    with _spinner(t("cli.spinner.vmp", eff, count=len(paths)), enabled=not pipe_mode):
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

            audit = Reporter().build_audit_report(dex_dir, vmp=data, lang=eff)
            print(ReportGenerator.render(audit, fmt_l, lang=eff))
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(dex_dir, vmp=data, lang=eff)
        out.write_text(ReportGenerator.render(audit, fmt_l, lang=eff))
        console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
    else:
        print_vmp_summary(
            console,
            per_dex,
            {"total_methods": total, "normal_count": normal, "nop_count": nop, "vmp_count": vmp_total},
            vmp_methods=all_vmp_methods,
            lang=eff,
        )

    if output_json:
        output_json.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")


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
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display/report language: en | zh | auto"),
    ] = None,
):
    """Build a cross-reference index: strings, method calls, fields, reflection."""
    from unpack.analysis.xref import XrefBuilder

    eff = _apply_lang(lang)
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
        _fail_error(t("cli.no_dex_found", eff), json_stdout=json_stdout)

    builder = XrefBuilder()
    with _spinner(t("cli.spinner.xref", eff, count=len(paths)), enabled=not pipe_mode):
        reports = [builder.build_file(p) for p in paths]
        merged = XrefBuilder.merge(reports)

    if pipe_mode:
        if report_fmt:
            from unpack.core.reporter import ReportGenerator, Reporter

            audit = Reporter().build_audit_report(dex_dir, xref=merged, lang=eff)
            print(ReportGenerator.render(audit, fmt_l, lang=eff))
        else:
            print(json.dumps(merged.to_dict(), indent=2, ensure_ascii=False))
        return

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(dex_dir, xref=merged, lang=eff)
        out.write_text(ReportGenerator.render(audit, fmt_l, lang=eff))
        console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
    else:
        print_xref_summary(console, merged, file_count=len(paths), search=search, lang=eff)

    if output_json:
        output_json.write_text(json.dumps(merged.to_dict(), indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(merged.to_dict(), indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")


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
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Report & display language: en | zh | auto"),
    ] = None,
):
    """Generate a commercial audit report (HTML5 / Markdown / SARIF 2.1.0 / JSON)."""
    eff = _apply_lang(lang)
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

    with _spinner(t("cli.spinner.evidence", eff), enabled=not to_stdout):
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
        lang=eff,
    )
    rendered = ReportGenerator.render(audit, fmt_l, lang=eff)

    if to_stdout:
        print(rendered)
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered)
    render_kv_card(
        console,
        t("cli.report.generated", eff),
        [
            (t("fmt.col.format", eff), f"[{C_INFO}]{safe(fmt_l.upper())}[/]"),
            (t("fmt.col.output", eff), f"[path]{safe(out)}[/]"),
            (t("fmt.col.grade", eff), f"[{C_OK if audit.grade in ('A', 'B') else C_WARN}]{audit.grade}[/] ({audit.risk_score}/100)"),
            (t("fmt.col.findings", eff), f"{len(audit.findings)}"),
        ],
        border_style=C_OK,
        title_style=f"bold {C_OK}",
    )


# ── Deep Pipeline Planner & Runner ───────────────────────────────────────────


def build_pipeline_plan(
    apk: Path,
    *,
    output: Path = Path("./unpacked"),
    device: str | None = None,
    engine: str | None = None,
    timeout: int = 0,
    deep: bool = False,
    skip_repair: bool = False,
    no_anti_detect: bool = False,
    repack: bool = False,
    report_html: Path | None = None,
    mode: str = "auto",
    check_devices: bool = True,
    lang: str | None = None,
) -> dict[str, Any]:
    """Build a structured, packer-aware Pipeline Execution Blueprint with live preflight checks."""
    eff = resolve_lang(lang) if lang is not None else get_lang()

    # 1. Static scan & archive probe
    apk_valid = False
    apk_size = 0
    dex_entries = 0
    so_entries = 0
    scan_result = None
    if apk.exists() and apk.is_file():
        apk_size = apk.stat().st_size
        try:
            with zipfile.ZipFile(apk, "r") as zf:
                names = zf.namelist()
                apk_valid = True
                dex_entries = sum(1 for n in names if n.endswith(".dex") and "/" not in n)
                so_entries = sum(1 for n in names if n.startswith("lib/") and n.endswith(".so"))
        except zipfile.BadZipFile:
            apk_valid = False

    if apk_valid:
        from unpack.core.scanner import PackerScanner

        scan_result = PackerScanner().scan(apk, verbose=True)

    # 2. Live doctor probe
    doc = _run_doctor_impl(check_devices=check_devices, device_serial=device)
    devices = doc.get("devices") or []
    rooted_cnt = sum(1 for d in devices if d.get("rooted") or d.get("root"))
    engines_map = {str(e.get("name", "")).lower(): e for e in (doc.get("engines") or [])}
    checks_map = {str(c.get("name", "")).lower(): c for c in (doc.get("checks") or [])}

    packer_name = getattr(scan_result, "packer_name", None) if scan_result else None
    packer_version = getattr(scan_result, "packer_version", None) if scan_result else None
    confidence = float(getattr(scan_result, "confidence", 0.0) or 0.0) if scan_result else 0.0
    prot_obj = getattr(scan_result, "protection_level", None) if scan_result else None
    prot_level = getattr(prot_obj, "value", str(prot_obj or "none")) if prot_obj else "none"

    # 3. Resolve mode & recommendations from PackerScanner intelligence
    norm_mode = (mode or "auto").strip().lower()
    if norm_mode == "auto":
        if not packer_name:
            effective_mode = "offline"
        elif prot_level == "function_extraction":
            effective_mode = "deep"
        else:
            effective_mode = "standard"
    elif norm_mode in ("offline", "standard", "deep"):
        effective_mode = norm_mode
    else:
        effective_mode = "deep" if deep else "standard"

    use_deep = deep or effective_mode == "deep"
    is_offline = effective_mode == "offline"

    rec_engine = engine or (getattr(scan_result, "recommended_engine", None) if scan_result else None) or "memory"
    if is_offline:
        rec_engine_display = "offline"
    else:
        rec_engine_display = rec_engine

    rec_flags: list[str] = list(getattr(scan_result, "recommended_flags", None) or []) if scan_result else []
    if use_deep and "--deep" not in rec_flags:
        rec_flags.append("--deep")
    if is_offline:
        rec_flags = ["--mode", "offline", "--execute"]

    if not packer_name:
        why = t("pipe.why.clean", eff)
    elif prot_level in ("vmp", "dex2c"):
        why = t("pipe.why.vmp", eff)
    elif prot_level == "function_extraction":
        why = t("pipe.why.func", eff)
    elif prot_level == "dex_encryption":
        why = t("pipe.why.dex_enc", eff)
    else:
        why = t("pipe.why.unknown", eff)

    # 4. Live Preflight Checks
    preflight: list[dict[str, Any]] = []
    if apk_valid:
        preflight.append(
            {
                "id": "apk",
                "name": t("pipe.preflight.apk", eff),
                "status": "pass",
                "detail": t(
                    "pipe.preflight.apk_ok",
                    eff,
                    size=format_bytes(apk_size),
                    dex=dex_entries,
                    so=so_entries,
                ),
                "remediation": "",
            }
        )
    else:
        preflight.append(
            {
                "id": "apk",
                "name": t("pipe.preflight.apk", eff),
                "status": "block",
                "detail": t("pipe.preflight.apk_bad", eff),
                "remediation": t("pipe.preflight.apk_fix", eff),
            }
        )

    adb_chk = checks_map.get("adb")
    adb_path = (adb_chk or {}).get("version") or shutil.which("adb")
    if not is_offline:
        if adb_path:
            preflight.append(
                {
                    "id": "adb",
                    "name": t("pipe.preflight.adb", eff),
                    "status": "pass",
                    "detail": t("pipe.preflight.adb_ok", eff, path=adb_path),
                    "remediation": "",
                }
            )
        else:
            preflight.append(
                {
                    "id": "adb",
                    "name": t("pipe.preflight.adb", eff),
                    "status": "block",
                    "detail": t("pipe.preflight.adb_miss", eff),
                    "remediation": t("pipe.preflight.adb_fix", eff),
                }
            )

        if devices and rooted_cnt > 0:
            preflight.append(
                {
                    "id": "device",
                    "name": t("pipe.preflight.device", eff),
                    "status": "pass",
                    "detail": t("pipe.preflight.device_ok", eff, count=len(devices), rooted=rooted_cnt),
                    "remediation": "",
                }
            )
        elif devices:
            preflight.append(
                {
                    "id": "device",
                    "name": t("pipe.preflight.device", eff),
                    "status": "warn",
                    "detail": t("pipe.preflight.device_unrooted", eff, count=len(devices)),
                    "remediation": t("pipe.preflight.device_fix", eff),
                }
            )
        else:
            preflight.append(
                {
                    "id": "device",
                    "name": t("pipe.preflight.device", eff),
                    "status": "block",
                    "detail": t("pipe.preflight.device_miss", eff),
                    "remediation": t("pipe.preflight.device_fix", eff),
                }
            )

        eng_info = engines_map.get(rec_engine.lower()) or {"available": False, "reason": "unknown engine"}
        if eng_info.get("available"):
            preflight.append(
                {
                    "id": "engine",
                    "name": t("pipe.preflight.engine", eff, engine=rec_engine),
                    "status": "pass",
                    "detail": t("pipe.preflight.engine_ok", eff, engine=rec_engine),
                    "remediation": "",
                }
            )
        else:
            preflight.append(
                {
                    "id": "engine",
                    "name": t("pipe.preflight.engine", eff, engine=rec_engine),
                    "status": "block",
                    "detail": t(
                        "pipe.preflight.engine_miss",
                        eff,
                        engine=rec_engine,
                        reason=eng_info.get("reason") or "requirements not met",
                    ),
                    "remediation": t("pipe.preflight.engine_fix", eff),
                }
            )

        if use_deep:
            frida_ready = bool((engines_map.get("frida") or {}).get("available"))
            preflight.append(
                {
                    "id": "deep",
                    "name": t("pipe.preflight.deep", eff),
                    "status": "pass" if frida_ready else "warn",
                    "detail": t("pipe.preflight.deep_ok", eff) if frida_ready else t("pipe.preflight.deep_warn", eff),
                    "remediation": "" if frida_ready else "pip install -e '.[frida]'",
                }
            )

    preflight.append(
        {
            "id": "output",
            "name": t("pipe.preflight.output", eff),
            "status": "pass",
            "detail": t("pipe.preflight.output_ok", eff, path=output),
            "remediation": "",
        }
    )

    device_blocked = any(p["status"] == "block" for p in preflight if p["id"] in ("adb", "device", "engine"))
    can_execute = not any(p["status"] == "block" for p in preflight)

    # 5. Stage-by-stage Execution Blueprint
    stages: list[dict[str, Any]] = []
    if is_offline:
        order = 1
        stages.append(
            {
                "order": order,
                "id": "scan",
                "title": t("pipe.stage.scan.title", eff),
                "what_it_does": t("pipe.stage.scan.desc", eff),
                "prerequisites": t("pipe.stage.scan.prereq", eff),
                "readiness": "ready" if apk_valid else "blocked",
                "inputs": apk.name,
                "outputs": "ScanResult (packer, confidence, evidence)",
                "will_run": True,
                "skip_reason": None,
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "inspect",
                "title": t("pipe.stage.inspect.title", eff),
                "what_it_does": t("pipe.stage.inspect.desc", eff),
                "prerequisites": t("pipe.stage.inspect.prereq", eff),
                "readiness": "ready" if apk_valid else "blocked",
                "inputs": apk.name,
                "outputs": "ApkInspectResult (manifest, signing, ELF, risk)",
                "will_run": True,
                "skip_reason": None,
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "extract_dex",
                "title": t("pipe.stage.extract_dex.title", eff),
                "what_it_does": t("pipe.stage.extract_dex.desc", eff),
                "prerequisites": t("pipe.stage.extract_dex.prereq", eff),
                "readiness": "ready" if dex_entries > 0 else "warn",
                "inputs": f"{apk.name} ({dex_entries} DEX)",
                "outputs": f"{output}/*.dex",
                "will_run": dex_entries > 0,
                "skip_reason": None if dex_entries > 0 else "no root classes*.dex",
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "repair",
                "title": f"{order}. {t('pipe.stage.repair.title', eff)}",
                "what_it_does": t("pipe.stage.repair.desc", eff),
                "prerequisites": t("pipe.stage.repair.prereq", eff),
                "readiness": "skipped" if (skip_repair or dex_entries == 0) else "ready",
                "inputs": f"{output}/*.dex",
                "outputs": f"{output}/*_repaired.dex",
                "will_run": not skip_repair and dex_entries > 0,
                "skip_reason": "--skip-repair" if skip_repair else (None if dex_entries > 0 else "no DEX"),
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "verify",
                "title": f"{order}. {t('pipe.stage.verify.title', eff)}",
                "what_it_does": t("pipe.stage.verify.desc", eff),
                "prerequisites": t("pipe.stage.verify.prereq", eff),
                "readiness": "ready" if dex_entries > 0 else "skipped",
                "inputs": f"{output}/*.dex",
                "outputs": f"{output}/report.json",
                "will_run": dex_entries > 0,
                "skip_reason": None if dex_entries > 0 else "no DEX",
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "vmp",
                "title": f"{order}. {t('pipe.stage.vmp.title', eff)}",
                "what_it_does": t("pipe.stage.vmp.desc", eff),
                "prerequisites": t("pipe.stage.vmp.prereq", eff),
                "readiness": "ready" if dex_entries > 0 else "skipped",
                "inputs": f"{output}/*.dex",
                "outputs": "VmpReport (normal / NOP / VMP stubs)",
                "will_run": dex_entries > 0,
                "skip_reason": None if dex_entries > 0 else "no DEX",
            }
        )
        if repack:
            order += 1
            stages.append(
                {
                    "order": order,
                    "id": "repack",
                    "title": f"{order}. {t('pipe.stage.repack.title', eff)}",
                    "what_it_does": t("pipe.stage.repack.desc", eff),
                    "prerequisites": t("pipe.stage.repack.prereq", eff),
                    "readiness": "ready" if dex_entries > 0 else "skipped",
                    "inputs": f"{apk.name} + {output}/*.dex",
                    "outputs": f"{output}/repacked/*.apk",
                    "will_run": dex_entries > 0,
                    "skip_reason": None if dex_entries > 0 else "no DEX",
                }
            )
        order += 1
        report_target = report_html or (output / "audit_report.html")
        stages.append(
            {
                "order": order,
                "id": "report",
                "title": f"{order}. {t('pipe.stage.report.title', eff)}",
                "what_it_does": t("pipe.stage.report.desc", eff),
                "prerequisites": t("pipe.stage.report.prereq", eff),
                "readiness": "ready" if apk_valid else "blocked",
                "inputs": "All stage results",
                "outputs": str(report_target),
                "will_run": True,
                "skip_reason": None,
            }
        )
    else:
        order = 1
        stages.append(
            {
                "order": order,
                "id": "scan",
                "title": t("pipe.stage.scan.title", eff),
                "what_it_does": t("pipe.stage.scan.desc", eff),
                "prerequisites": t("pipe.stage.scan.prereq", eff),
                "readiness": "ready" if apk_valid else "blocked",
                "inputs": apk.name,
                "outputs": "ScanResult (packer, level, strategy)",
                "will_run": True,
                "skip_reason": None,
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "dump",
                "title": t("pipe.stage.dump.title", eff),
                "what_it_does": t("pipe.stage.dump.desc", eff, engine=rec_engine),
                "prerequisites": t("pipe.stage.dump.prereq", eff, engine=rec_engine),
                "readiness": "blocked" if device_blocked else "ready",
                "inputs": apk.name,
                "outputs": f"{output}/classes_*.dex",
                "will_run": True,
                "skip_reason": None,
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "dedup",
                "title": t("pipe.stage.dedup.title", eff),
                "what_it_does": t("pipe.stage.dedup.desc", eff),
                "prerequisites": t("pipe.stage.dedup.prereq", eff),
                "readiness": "blocked" if device_blocked else "ready",
                "inputs": f"{output}/*.dex",
                "outputs": "Unique DEX set",
                "will_run": True,
                "skip_reason": None,
            }
        )
        order += 1
        deep_readiness = (
            "skipped"
            if not use_deep
            else ("blocked" if device_blocked else ("ready" if (engines_map.get("frida") or {}).get("available") else "warn"))
        )
        stages.append(
            {
                "order": order,
                "id": "deep_invoke",
                "title": t("pipe.stage.deep.title", eff),
                "what_it_does": t("pipe.stage.deep.desc", eff),
                "prerequisites": t("pipe.stage.deep.prereq", eff),
                "readiness": deep_readiness,
                "inputs": f"{apk.name} + {output}/*.dex",
                "outputs": "Merged CodeItems (recovered NOPs)",
                "will_run": use_deep,
                "skip_reason": None if use_deep else "pass --deep to enable",
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "repair",
                "title": f"{order}. {t('pipe.stage.repair.title', eff)}",
                "what_it_does": t("pipe.stage.repair.desc", eff),
                "prerequisites": t("pipe.stage.repair.prereq", eff),
                "readiness": "skipped" if skip_repair else ("blocked" if device_blocked else "ready"),
                "inputs": f"{output}/*.dex",
                "outputs": f"{output}/*_repaired.dex",
                "will_run": not skip_repair,
                "skip_reason": "--skip-repair" if skip_repair else None,
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "verify",
                "title": f"{order}. {t('pipe.stage.verify.title', eff)}",
                "what_it_does": t("pipe.stage.verify.desc", eff),
                "prerequisites": t("pipe.stage.verify.prereq", eff),
                "readiness": "blocked" if device_blocked else "ready",
                "inputs": f"{output}/*.dex",
                "outputs": f"{output}/report.json",
                "will_run": True,
                "skip_reason": None,
            }
        )
        if report_html is not None:
            order += 1
            stages.append(
                {
                    "order": order,
                    "id": "report",
                    "title": f"{order}. {t('pipe.stage.report.title', eff)}",
                    "what_it_does": t("pipe.stage.report.desc", eff),
                    "prerequisites": t("pipe.stage.report.prereq", eff),
                    "readiness": "blocked" if device_blocked else "ready",
                    "inputs": "Scan + Quality + Repair",
                    "outputs": str(report_html),
                    "will_run": True,
                    "skip_reason": None,
                }
            )

    # 6. Copyable Commands
    lf = " --lang zh" if eff == "zh" else ""
    if is_offline:
        rec_cmd = f"unpack pipeline {apk} --mode offline -o {output} --execute{lf}"
    else:
        cmd_parts = [f"unpack dump {apk}", f"-o {output}"]
        if engine:
            cmd_parts.append(f"-e {engine}")
        if use_deep:
            cmd_parts.append("--deep")
        if timeout > 0:
            cmd_parts.append(f"-t {timeout}")
        if skip_repair:
            cmd_parts.append("--skip-repair")
        if no_anti_detect:
            cmd_parts.append("--no-anti-detect")
        if report_html:
            cmd_parts.append(f"--report-html {report_html}")
        if eff == "zh":
            cmd_parts.append("--lang zh")
        rec_cmd = " ".join(cmd_parts)

    offline_alt_cmd = f"unpack pipeline {apk} --mode offline -o {output} --execute{lf}"

    return {
        "target": str(apk),
        "output": str(output),
        "mode": effective_mode,
        "mode_label": t(f"pipe.mode.{effective_mode}", eff),
        "lang": eff,
        "packer_name": packer_name,
        "packer_version": packer_version,
        "confidence": round(confidence, 3),
        "protection_level": prot_level,
        "recommended_engine": rec_engine_display,
        "recommended_flags": rec_flags,
        "strategy_reason": why,
        "can_execute": can_execute,
        "preflight_checks": preflight,
        "stages": stages,
        "recommended_cmd": rec_cmd,
        "offline_alternative_cmd": offline_alt_cmd,
    }


def _run_offline_pipeline(
    apk: Path,
    *,
    output: Path,
    skip_repair: bool = False,
    repack: bool = False,
    report_html: Path | None = None,
    lang: str = "en",
) -> dict[str, Any]:
    """Execute the zero-device Offline Audit & Repair Pipeline end-to-end."""
    from unpack.analysis.vmp import VmpDetector
    from unpack.core.reporter import ReportGenerator, Reporter
    from unpack.core.scanner import PackerScanner
    from unpack.repair.dex_repair import DexRepairPipeline
    from unpack.repair.verifier import DexVerifier

    output.mkdir(parents=True, exist_ok=True)
    total_steps = 6 + (1 if repack else 0)
    step = 0

    # 1. Scan
    step += 1
    render_pipeline_step(console, step, total_steps, t("pipe.stage.scan.title", lang), detail=apk.name, lang=lang)
    scan_res = PackerScanner().scan(apk, verbose=True)
    print_scan_result(console, scan_res, apk, lang=lang)

    # 2. Static APK Inspection
    step += 1
    render_pipeline_step(console, step, total_steps, t("pipe.stage.inspect.title", lang), detail=apk.name, lang=lang)
    inspect_data = _inspect_apk_impl(apk)
    print_inspect_apk(console, inspect_data, lang=lang)

    # 3. Extract embedded DEX files
    step += 1
    render_pipeline_step(console, step, total_steps, t("pipe.stage.extract_dex.title", lang), lang=lang)
    extracted: list[Path] = []
    with zipfile.ZipFile(apk, "r") as zf:
        for info in zf.infolist():
            if info.filename.endswith(".dex") and "/" not in info.filename:
                dest = output / Path(info.filename).name
                dest.write_bytes(zf.read(info.filename))
                extracted.append(dest)
    if extracted:
        console.print(f"  [{C_OK}]✓[/] {safe(t('pipe.offline_exec.extracted', lang, count=len(extracted)))}")
    else:
        console.print(f"  [{C_WARN}]![/] {safe(t('pipe.offline_exec.no_dex', lang))}")

    # 4. Repair & Verify
    step += 1
    render_pipeline_step(console, step, total_steps, t("pipe.stage.repair.title", lang), lang=lang)
    repair_dicts: list[dict[str, Any]] = []
    verify_list: list[dict[str, Any]] = []
    if extracted and not skip_repair:
        rp = DexRepairPipeline()
        for p in extracted:
            rr = rp.repair(p)
            repair_dicts.append(
                {
                    "file": p.name,
                    "success": rr.success,
                    "actions": rr.actions,
                    "nop_methods": rr.nop_method_count,
                    "output": str(rr.output_path) if rr.output_path else None,
                }
            )
        print_repair_summary(console, repair_dicts, lang=lang)

    verifier = DexVerifier()
    for p in extracted:
        vr = verifier.verify(p)
        verify_list.append({"file": p.name, "valid": vr.valid, "issues": vr.issues, "stats": vr.stats})
    if verify_list:
        print_verify_summary(console, verify_list, lang=lang)

    # 5. VMP & Quality
    step += 1
    render_pipeline_step(console, step, total_steps, t("pipe.stage.vmp.title", lang), lang=lang)
    reporter = Reporter()
    quality_report = reporter.evaluate(output, scan_res) if extracted else None
    vmp_data: dict[str, Any] | None = None
    if extracted:
        det = VmpDetector()
        tot = norm = nops = vmps = 0
        v_methods: list[dict[str, Any]] = []
        c_graph: list[dict[str, Any]] = []
        per_dex: list[dict[str, Any]] = []
        for p in extracted:
            vr_vmp = det.analyze_dex(p.read_bytes())
            tot += vr_vmp.total_methods
            norm += vr_vmp.normal_count
            nops += vr_vmp.nop_count
            vmps += vr_vmp.vmp_count
            v_methods.extend({**m, "dex_file": p.name} for m in vr_vmp.vmp_methods)
            c_graph.extend({**c, "dex_file": p.name} for c in vr_vmp.call_graph)
            per_dex.append({"file": p.name, "normal": vr_vmp.normal_count, "nop": vr_vmp.nop_count, "vmp": vr_vmp.vmp_count})
        vmp_data = {
            "total_methods": tot,
            "normal_count": norm,
            "nop_count": nops,
            "vmp_count": vmps,
            "vmp_methods": v_methods,
            "call_graph": c_graph,
        }
        print_vmp_summary(console, per_dex, vmp_data, vmp_methods=v_methods, lang=lang)
        (output / "report.json").write_text(json.dumps(quality_report.to_dict(), indent=2, ensure_ascii=False))

    # Optional Repack
    repacked_path: Path | None = None
    if repack and extracted:
        step += 1
        render_pipeline_step(console, step, total_steps, t("pipe.stage.repack.title", lang), lang=lang)
        from unpack.repack.repacker import Repacker

        rep_res = Repacker().repack(apk, output, output / "repacked")
        if rep_res.success:
            repacked_path = rep_res.output_path
            console.print(f"  [{C_OK}]✓[/] {safe(rep_res.output_path)}")

    # 6. Commercial Audit Report
    step += 1
    render_pipeline_step(console, step, total_steps, t("pipe.stage.report.title", lang), lang=lang)
    audit = reporter.build_audit_report(
        apk,
        scan=scan_res,
        inspect=inspect_data,
        quality=quality_report,
        verify_results=verify_list,
        repair_results=repair_dicts,
        vmp=vmp_data,
        lang=lang,
    )
    html_dest = report_html or (output / "audit_report.html")
    html_dest.parent.mkdir(parents=True, exist_ok=True)
    html_dest.write_text(ReportGenerator.render(audit, "html", lang=lang))

    render_kv_card(
        console,
        t("pipe.offline_exec.title", lang),
        [
            (t("fmt.target", lang), f"[path]{safe(apk.name)}[/]"),
            (t("fmt.col.grade", lang), f"[{C_OK if audit.grade in ('A', 'B') else C_WARN}]{audit.grade}[/] ({audit.risk_score}/100)"),
            (t("fmt.col.findings", lang), f"{len(audit.findings)}"),
            (t("fmt.col.output", lang), f"[path]{safe(html_dest)}[/]"),
        ],
        border_style=C_OK,
        title_style=f"bold {C_OK}",
    )
    return {
        "target": str(apk),
        "mode": "offline",
        "grade": audit.grade,
        "risk_score": audit.risk_score,
        "findings": len(audit.findings),
        "extracted_dex": [p.name for p in extracted],
        "report_html": str(html_dest),
        "repacked": str(repacked_path) if repacked_path else None,
    }


@app.command()
def pipeline(
    apk: Annotated[Path, typer.Argument(help="Path to APK file")],
    mode: Annotated[
        str,
        typer.Option("--mode", "-m", help="Pipeline mode: auto | offline | standard | deep"),
    ] = "auto",
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output directory for pipeline artifacts"),
    ] = Path("./unpacked"),
    device: Annotated[
        Optional[str],
        typer.Option("--device", "-d", help="ADB device serial (device modes)"),
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
        typer.Option("--deep", help="Enable active invocation in device mode"),
    ] = False,
    skip_repair: Annotated[
        bool,
        typer.Option("--skip-repair", help="Skip DEX repair stage"),
    ] = False,
    repack: Annotated[
        bool,
        typer.Option("--repack", help="Repack analyzable APK at the end (offline mode)"),
    ] = False,
    report_html: Annotated[
        Optional[Path],
        typer.Option("--report-html", help="Path to write HTML audit report"),
    ] = None,
    explain: Annotated[
        bool,
        typer.Option("--explain", "--dry-run", help="Render execution blueprint only (default unless --execute is passed)"),
    ] = False,
    execute: Annotated[
        bool,
        typer.Option("--execute", "-x", help="Execute the planned pipeline immediately"),
    ] = False,
    no_devices: Annotated[
        bool,
        typer.Option("--no-devices", help="Skip live ADB device probing during preflight"),
    ] = False,
    fmt: Annotated[
        str,
        typer.Option("--format", "-F", help="Output format: table | json"),
    ] = "table",
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save blueprint as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display/report language: en | zh | auto"),
    ] = None,
):
    """Guided Pipeline Planner & Runner: live preflight blueprint + zero-device offline or device execution."""
    eff = _apply_lang(lang)
    json_stdout = fmt.strip().lower() == "json" or (output_json is not None and str(output_json) == "-")
    if not apk.exists():
        _fail_missing("APK", apk, json_stdout=json_stdout)

    with _spinner(t("cli.spinner.pipeline", eff), enabled=not json_stdout):
        plan = build_pipeline_plan(
            apk,
            output=output,
            device=device,
            engine=engine,
            timeout=timeout,
            deep=deep,
            skip_repair=skip_repair,
            repack=repack,
            report_html=report_html,
            mode=mode,
            check_devices=not no_devices,
            lang=eff,
        )

    if json_stdout:
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        return

    render_pipeline_blueprint(console, plan, lang=eff)

    if output_json:
        output_json.write_text(json.dumps(plan, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")

    if execute and not explain:
        if plan["mode"] == "offline":
            _run_offline_pipeline(
                apk,
                output=output,
                skip_repair=skip_repair,
                repack=repack,
                report_html=report_html,
                lang=eff,
            )
        else:
            dump(
                apk=apk,
                output=output,
                device=device,
                engine=engine,
                timeout=timeout,
                deep=deep or plan["mode"] == "deep",
                skip_repair=skip_repair,
                no_anti_detect=False,
                report_html=report_html,
                explain=False,
                no_devices=no_devices,
                lang=eff,
            )


# ── Interactive Onboarding & Guided Wizard (`guide` / `wizard`) ──────────────

_GUIDE_SCENARIOS: tuple[str, ...] = ("audit", "dex", "repair", "pipeline", "web")


def _discover_local_samples(scenario: str) -> list[dict[str, Any]]:
    """Auto-discover local APK/DEX samples in test_apks/, e2e_test/, and workspace."""
    found: list[dict[str, Any]] = []
    seen: set[Path] = set()
    roots = [Path("test_apks"), Path("e2e_test"), Path(".")]

    want_ext = (".apk",)
    if scenario == "dex":
        want_ext = (".dex", ".apk")
    elif scenario == "repair":
        want_ext = (".dex",)

    for root in roots:
        if not root.exists():
            continue
        if scenario == "repair" and root.is_dir():
            for cand_dir in (root / "unpacked", root / "dex"):
                if cand_dir.is_dir() and list(cand_dir.glob("*.dex")):
                    res = cand_dir.resolve()
                    if res not in seen:
                        seen.add(res)
                        found.append({"path": cand_dir, "type": "DEX dir", "size": None})
        pattern_iter = sorted(root.iterdir()) if root == Path(".") else sorted(root.rglob("*"))
        for p in pattern_iter:
            if not p.is_file():
                continue
            if p.suffix.lower() not in want_ext:
                continue
            if any(part.startswith(".") for part in p.parts):
                continue
            res = p.resolve()
            if res in seen:
                continue
            seen.add(res)
            found.append(
                {
                    "path": p,
                    "type": p.suffix.lstrip(".").upper(),
                    "size": p.stat().st_size,
                }
            )
            if len(found) >= 8:
                return found
    return found


def _build_guide_plan(
    scenario: str,
    target: Path,
    *,
    lang: str,
    has_device: bool,
) -> tuple[list[dict[str, str]], list[str]]:
    """Return plain-language stages and copyable CLI commands for a wizard goal."""
    lf = " --lang zh" if lang == "zh" else ""
    if scenario == "audit":
        stages = [
            {
                "stage": t("pipe.stage.scan.title", lang),
                "purpose": t("pipe.stage.scan.desc", lang),
                "prereq": t("pipe.stage.scan.prereq", lang),
                "output": "Packer verdict + evidence chain",
            },
            {
                "stage": t("pipe.stage.inspect.title", lang),
                "purpose": t("pipe.stage.inspect.desc", lang),
                "prereq": t("pipe.stage.inspect.prereq", lang),
                "output": "Manifest, signing, permissions & ELF report",
            },
            {
                "stage": f"3. {t('pipe.stage.report.title', lang)}",
                "purpose": t("pipe.stage.report.desc", lang),
                "prereq": t("pipe.stage.report.prereq", lang),
                "output": "audit.html",
            },
        ]
        cmds = [
            f"unpack scan {target} -v{lf}",
            f"unpack inspect {target} --permissions{lf}",
            f"unpack report {target} -F html -o audit.html{lf}",
        ]
        return stages, cmds

    if scenario == "dex":
        stages = [
            {
                "stage": "1. DEX Overview & Classes" if lang == "en" else "1. DEX 概览与类目录浏览",
                "purpose": "Inspect DEX header, class/method counts & NOP health" if lang == "en" else "查看 DEX 文件头、类与方法数量以及 NOP 抽取健康度",
                "prereq": t("pipe.stage.scan.prereq", lang),
                "output": "Classes & health table",
            },
            {
                "stage": "2. Method & Dalvik Disassembly" if lang == "en" else "2. 方法列表与 Dalvik 反汇编",
                "purpose": "Drill into a target class and disassemble Dalvik instructions" if lang == "en" else "展开指定类的方法清单，并对目标方法进行 Dalvik 字节码反汇编",
                "prereq": t("pipe.stage.scan.prereq", lang),
                "output": "Instruction listing",
            },
        ]
        cmds = [
            f"unpack inspect {target} --classes{lf}",
            f"unpack inspect {target} --methods com.example.MainActivity{lf}",
            f"unpack inspect {target} --disasm com.example.MainActivity::onCreate{lf}",
        ]
        return stages, cmds

    if scenario == "repair":
        stages = [
            {
                "stage": f"1. {t('pipe.stage.repair.title', lang)}",
                "purpose": t("pipe.stage.repair.desc", lang),
                "prereq": t("pipe.stage.repair.prereq", lang),
                "output": "*_repaired.dex",
            },
            {
                "stage": f"2. {t('pipe.stage.verify.title', lang)}",
                "purpose": t("pipe.stage.verify.desc", lang),
                "prereq": t("pipe.stage.verify.prereq", lang),
                "output": "PASS / FAIL integrity table",
            },
        ]
        cmds = [
            f"unpack repair {target}{lf}",
            f"unpack verify {target}{lf}",
        ]
        return stages, cmds

    if scenario == "pipeline":
        stages = [
            {
                "stage": t("pipe.stage.scan.title", lang),
                "purpose": t("pipe.stage.scan.desc", lang),
                "prereq": t("pipe.stage.scan.prereq", lang),
                "output": "Packer & recommended flags",
            },
            {
                "stage": t("pipe.stage.dump.title", lang),
                "purpose": t("pipe.stage.dump.desc", lang, engine="auto"),
                "prereq": t("pipe.stage.dump.prereq", lang, engine="auto"),
                "output": "./unpacked/*.dex",
            },
            {
                "stage": f"3. {t('pipe.stage.repair.title', lang)} & {t('pipe.stage.verify.title', lang)}",
                "purpose": t("pipe.stage.verify.desc", lang),
                "prereq": t("pipe.stage.verify.prereq", lang),
                "output": "./unpacked/report.json",
            },
        ]
        cmds = [f"unpack dump {target} --explain{lf}"]
        if has_device:
            cmds.append(f"unpack dump {target} --deep -o ./unpacked --report-html audit.html{lf}")
        else:
            cmds.append(f"unpack pipeline {target} --mode offline -o ./unpacked --execute{lf}")
        return stages, cmds

    # web
    stages = [
        {
            "stage": "1. Launch Unpack Studio" if lang == "en" else "1. 启动 Unpack Studio 本地服务",
            "purpose": t("guide.goal.web.desc", lang),
            "prereq": "Python Flask (`pip install -e '.[web]'`)" if lang == "en" else "需安装 Flask（`pip install -e '.[web]'`）",
            "output": "http://127.0.0.1:8080",
        }
    ]
    cmds = ["unpack web --port 8080"]
    return stages, cmds


def _run_guide(
    *,
    scenario: str | None = None,
    target: Path | None = None,
    non_interactive: bool = False,
    execute: bool = False,
    no_devices: bool = False,
    lang: str | None = None,
) -> None:
    eff = _apply_lang(lang)
    console.print()
    render_header(
        console,
        t("guide.title", eff),
        subtitle=t("guide.subtitle", eff),
        meta=f"v{__version__}",
    )

    # ── Step 1: Environment Readiness Check ──
    render_wizard_step(console, 1, 5, t("guide.step1.title", eff), t("guide.step1.sub", eff), lang=eff)
    with _spinner(t("cli.spinner.doctor", eff)):
        doc = _run_doctor_impl(check_devices=not no_devices)
    checks = doc.get("checks") or []
    passed = sum(1 for c in checks if str(c.get("status", "")).lower() == "pass")
    warned = sum(1 for c in checks if str(c.get("status", "")).lower() == "warn")
    failed = sum(1 for c in checks if str(c.get("status", "")).lower() == "fail")
    devices = doc.get("devices") or []
    rooted = sum(1 for d in devices if d.get("rooted") or d.get("root"))
    ready_engines = [str(e["name"]) for e in (doc.get("engines") or []) if e.get("available")]

    if devices:
        dev_summary = f"[{C_OK}]{safe(t('guide.env.device_ready', eff, count=len(devices), rooted=rooted, engines=', '.join(ready_engines) or 'none'))}[/]"
    else:
        dev_summary = f"[{C_WARN}]{safe(t('guide.env.device_none', eff))}[/]"

    render_kv_card(
        console,
        t("fmt.title.doctor", eff),
        [
            (t("guide.env.offline_label", eff), f"[{C_OK}]{safe(t('guide.env.offline_ready', eff))}[/]"),
            (t("guide.env.device_label", eff), dev_summary),
            (t("guide.env.checks_summary", eff), t("guide.env.checks_detail", eff, passed=passed, warn=warned, fail=failed)),
        ],
        border_style=C_INFO,
        title_style=f"bold {C_INFO}",
    )

    # ── Step 2: Goal Picker ──
    render_wizard_step(console, 2, 5, t("guide.step2.title", eff), t("guide.step2.sub", eff), lang=eff)
    goal_rows = []
    for idx, key in enumerate(_GUIDE_SCENARIOS, start=1):
        goal_rows.append(
            [
                f"[{C_INFO}]{idx}[/]",
                f"[{C_LABEL}]{safe(t(f'guide.goal.{key}.name', eff))}[/] [{C_DIM}]({key})[/]",
                f"[{C_OK if key in ('audit', 'dex', 'repair') else C_ACCENT}]{safe(t(f'guide.goal.{key}.tag', eff))}[/]",
                safe(t(f"guide.goal.{key}.desc", eff)),
            ]
        )
    render_table(
        console,
        [
            (t("guide.col.num", eff), {"width": 3, "justify": "right"}),
            (t("guide.col.goal", eff), {}),
            (t("guide.col.mode", eff), {"width": 18}),
            (t("guide.col.what", eff), {}),
        ],
        goal_rows,
    )

    chosen_scenario: str
    if scenario:
        norm_s = scenario.strip().lower()
        if norm_s.isdigit() and 1 <= int(norm_s) <= len(_GUIDE_SCENARIOS):
            chosen_scenario = _GUIDE_SCENARIOS[int(norm_s) - 1]
        elif norm_s in _GUIDE_SCENARIOS:
            chosen_scenario = norm_s
        else:
            _fail_error(
                f"Unknown scenario: {scenario}",
                hint=f"Valid scenarios: {', '.join(_GUIDE_SCENARIOS)}",
            )
    elif non_interactive:
        chosen_scenario = "audit"
    else:
        raw_choice = typer.prompt(t("guide.prompt.goal", eff), default="1").strip().lower()
        if raw_choice.isdigit() and 1 <= int(raw_choice) <= len(_GUIDE_SCENARIOS):
            chosen_scenario = _GUIDE_SCENARIOS[int(raw_choice) - 1]
        elif raw_choice in _GUIDE_SCENARIOS:
            chosen_scenario = raw_choice
        else:
            chosen_scenario = "audit"

    # ── Step 3: Target Selection ──
    render_wizard_step(console, 3, 5, t("guide.step3.title", eff), t("guide.step3.sub", eff), lang=eff)
    chosen_target: Path
    if chosen_scenario == "web":
        chosen_target = Path("http://127.0.0.1:8080")
    else:
        discovered = _discover_local_samples(chosen_scenario)
        if discovered:
            s_rows = [
                [
                    f"[{C_INFO}]{idx}[/]",
                    f"[path]{safe(item['path'])}[/]",
                    safe(item["type"]),
                    format_bytes(item["size"]),
                ]
                for idx, item in enumerate(discovered, start=1)
            ]
            render_table(
                console,
                [
                    (t("guide.col.num", eff), {"width": 3, "justify": "right"}),
                    (t("guide.col.sample", eff), {}),
                    (t("guide.col.type", eff), {"width": 8}),
                    (t("guide.col.size", eff), {"justify": "right"}),
                ],
                s_rows,
                title=t("guide.discovered_title", eff, count=len(discovered)),
            )
        else:
            console.print(f"  [{C_DIM}]{safe(t('guide.no_local_targets', eff))}[/]")

        default_placeholder = Path("./unpacked") if chosen_scenario == "repair" else Path("sample.apk")
        if target is not None:
            chosen_target = target
        elif non_interactive:
            chosen_target = discovered[0]["path"] if discovered else default_placeholder
        else:
            default_in = "1" if discovered else str(default_placeholder)
            raw_t = typer.prompt(t("guide.prompt.target", eff), default=default_in).strip()
            if raw_t.isdigit() and 1 <= int(raw_t) <= len(discovered):
                chosen_target = discovered[int(raw_t) - 1]["path"]
            else:
                chosen_target = Path(raw_t)

        console.print(f"  [{C_OK}]▸[/] {safe(t('guide.selected_target', eff, target=chosen_target))}")
        if chosen_target.exists() and chosen_target.is_file() and chosen_target.suffix.lower() == ".apk":
            try:
                from unpack.core.scanner import PackerScanner

                preview = PackerScanner().scan(chosen_target, verbose=False)
                if preview.packer_name:
                    console.print(
                        f"  [{C_INFO}]ℹ[/] {safe(t('guide.preview_packer', eff, packer=preview.packer_name, level=preview.protection_level.value, conf=preview.confidence))}"
                    )
                else:
                    console.print(f"  [{C_DIM}]ℹ {safe(t('guide.preview_clean', eff))}[/]")
            except Exception:
                pass

    # ── Step 4: Plain-Language Execution Plan Preview ──
    render_wizard_step(console, 4, 5, t("guide.step4.title", eff), t("guide.step4.sub", eff), lang=eff)
    plan_stages, plan_cmds = _build_guide_plan(
        chosen_scenario,
        chosen_target,
        lang=eff,
        has_device=bool(devices),
    )
    goal_name = t(f"guide.goal.{chosen_scenario}.name", eff)
    render_table(
        console,
        [
            (t("guide.col.stage", eff), {}),
            (t("guide.col.purpose", eff), {}),
            (t("guide.col.prereq", eff), {}),
            (t("guide.col.output", eff), {}),
        ],
        [
            [
                f"[{C_LABEL}]{safe(s['stage'])}[/]",
                safe(s["purpose"]),
                f"[{C_DIM}]{safe(s['prereq'])}[/]",
                f"[{C_INFO}]{safe(s['output'])}[/]",
            ]
            for s in plan_stages
        ],
        title=t("guide.plan_title", eff, goal=goal_name),
    )

    console.print(f"\n[{C_LABEL}]{safe(t('guide.commands_title', eff))}[/]")
    for cmd in plan_cmds:
        console.print(f"  [{C_INFO}]$[/] [cmd]{safe(cmd)}[/]")

    # ── Step 5: Optional Immediate Execution ──
    render_wizard_step(console, 5, 5, t("guide.step5.title", eff), t("guide.step5.sub", eff), lang=eff)
    should_run = execute
    if not non_interactive and not execute:
        ans = typer.prompt(t("guide.prompt.execute", eff), default="n").strip().lower()
        should_run = ans in ("y", "yes", "是")

    if not should_run:
        note = t("guide.non_interactive_note", eff) if non_interactive else t("guide.exec_cancelled", eff)
        console.print(f"  [{C_DIM}]{safe(note)}[/]")
        return

    if chosen_scenario != "web" and not chosen_target.exists():
        console.print(f"  [{C_WARN}]![/] {safe(t('guide.exec_skipped_missing', eff, target=chosen_target))}")
        return

    console.print(f"  [{C_INFO}]▸[/] {safe(t('guide.exec_starting', eff))}")
    if chosen_scenario == "audit":
        from unpack.core.scanner import PackerScanner

        res = PackerScanner().scan(chosen_target, verbose=True)
        print_scan_result(console, res, chosen_target, lang=eff)
        data = _inspect_apk_impl(chosen_target)
        print_inspect_apk(console, data, lang=eff)
    elif chosen_scenario == "dex":
        if chosen_target.suffix.lower() in (".dex", ".cdex"):
            data = _inspect_dex_impl(chosen_target, show_classes=True)
            print_inspect_dex(console, data.get("overview") or {}, classes=data.get("classes"), lang=eff)
        else:
            data = _inspect_apk_impl(chosen_target)
            print_inspect_apk(console, data, lang=eff)
    elif chosen_scenario == "repair":
        dex_paths = _discover_dex_paths(chosen_target)
        if not dex_paths:
            _fail_error(t("cli.no_dex_found", eff))
        from unpack.repair.dex_repair import DexRepairPipeline
        from unpack.repair.verifier import DexVerifier

        rp = DexRepairPipeline()
        rep_items = []
        for p in dex_paths:
            rr = rp.repair(p)
            rep_items.append(
                {
                    "file": p.name,
                    "success": rr.success,
                    "actions": rr.actions,
                    "nop_methods": rr.nop_method_count,
                }
            )
        print_repair_summary(console, rep_items, lang=eff)
        ver = DexVerifier()
        ver_items = [
            {"file": p.name, "valid": (vr := ver.verify(p)).valid, "issues": vr.issues, "stats": vr.stats}
            for p in dex_paths
        ]
        print_verify_summary(console, ver_items, lang=eff)
    elif chosen_scenario == "pipeline":
        plan = build_pipeline_plan(
            chosen_target,
            mode="auto",
            check_devices=not no_devices,
            lang=eff,
        )
        render_pipeline_blueprint(console, plan, lang=eff)
    elif chosen_scenario == "web":
        web(port=8080, host="127.0.0.1")

    console.print(f"  [{C_OK}]✓[/] {safe(t('guide.exec_done', eff))}")


@app.command()
def guide(
    scenario: Annotated[
        Optional[str],
        typer.Option("--scenario", "-s", help="Goal preset: audit | dex | repair | pipeline | web"),
    ] = None,
    target: Annotated[
        Optional[Path],
        typer.Option("--target", "-t", help="Target APK, DEX, or directory path"),
    ] = None,
    non_interactive: Annotated[
        bool,
        typer.Option("--non-interactive", "-y", help="Run without interactive prompts (ideal for scripts & CI)"),
    ] = False,
    execute: Annotated[
        bool,
        typer.Option("--execute", "-x", help="Execute the generated workflow immediately"),
    ] = False,
    no_devices: Annotated[
        bool,
        typer.Option("--no-devices", help="Skip live ADB device probing during environment check"),
    ] = False,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Interactive onboarding wizard: check environment, pick a goal, preview & run."""
    _run_guide(
        scenario=scenario,
        target=target,
        non_interactive=non_interactive,
        execute=execute,
        no_devices=no_devices,
        lang=lang,
    )


@app.command()
def wizard(
    scenario: Annotated[
        Optional[str],
        typer.Option("--scenario", "-s", help="Goal preset: audit | dex | repair | pipeline | web"),
    ] = None,
    target: Annotated[
        Optional[Path],
        typer.Option("--target", "-t", help="Target APK, DEX, or directory path"),
    ] = None,
    non_interactive: Annotated[
        bool,
        typer.Option("--non-interactive", "-y", help="Run without interactive prompts (ideal for scripts & CI)"),
    ] = False,
    execute: Annotated[
        bool,
        typer.Option("--execute", "-x", help="Execute the generated workflow immediately"),
    ] = False,
    no_devices: Annotated[
        bool,
        typer.Option("--no-devices", help="Skip live ADB device probing during environment check"),
    ] = False,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Alias for `guide` — interactive step-by-step onboarding wizard."""
    _run_guide(
        scenario=scenario,
        target=target,
        non_interactive=non_interactive,
        execute=execute,
        no_devices=no_devices,
        lang=lang,
    )


# ── AI Configuration & Reverse-Engineering Analysis (`unpack ai`) ────────────

ai_app = typer.Typer(
    name="ai",
    help="Configure multi-provider AI models, test connectivity & run AI reverse-engineering analysis",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
app.add_typer(ai_app, name="ai")


@ai_app.command("show")
def ai_show(
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output public AI config & presets as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Display current AI provider configuration (API key masked) and supported presets."""
    from unpack.core.ai_engine import AIConfigStore, list_provider_presets

    eff = _apply_lang(lang)
    pub = AIConfigStore().load().to_public_dict()
    presets = list_provider_presets()
    payload = {"config": pub, "presets": presets}

    if output_json is not None and str(output_json) == "-":
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    print_ai_config(console, pub, presets=presets, lang=eff)
    if not pub.get("configured") and not _QUIET:
        console.print(f"\n  [{C_DIM}]{safe(t('ai.config_hint', eff))}[/]")
    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@ai_app.command("config")
def ai_config(
    provider: Annotated[
        Optional[str],
        typer.Option("--provider", "-p", help="Provider: openai | anthropic | gemini | deepseek | qwen | ollama | custom"),
    ] = None,
    model: Annotated[
        Optional[str],
        typer.Option("--model", "-m", help="Model name (e.g. gpt-4o-mini, deepseek-chat, qwen-plus)"),
    ] = None,
    base_url: Annotated[
        Optional[str],
        typer.Option("--base-url", help="Custom API base URL"),
    ] = None,
    api_key: Annotated[
        Optional[str],
        typer.Option("--api-key", "-k", help="API key (stored with 0600 permissions, never echoed raw)"),
    ] = None,
    enable: Annotated[
        Optional[bool],
        typer.Option("--enable/--disable", help="Enable or disable AI features"),
    ] = None,
    clear_key: Annotated[
        bool,
        typer.Option("--clear-key", help="Clear the stored API key"),
    ] = False,
    temperature: Annotated[
        Optional[float],
        typer.Option("--temperature", help="Sampling temperature (0.0 - 2.0)"),
    ] = None,
    timeout: Annotated[
        Optional[float],
        typer.Option("--timeout", help="HTTP timeout in seconds (3 - 300)"),
    ] = None,
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output updated public config as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Save AI provider configuration securely (API key is masked in all output)."""
    from unpack.core.ai_engine import AIConfigStore

    eff = _apply_lang(lang)
    payload: dict[str, Any] = {}
    if provider is not None:
        payload["provider"] = provider
    if model is not None:
        payload["model"] = model
    if base_url is not None:
        payload["base_url"] = base_url
    if api_key is not None:
        payload["api_key"] = api_key
    if enable is not None:
        payload["enabled"] = enable
    if temperature is not None:
        payload["temperature"] = temperature
    if timeout is not None:
        payload["timeout_seconds"] = timeout

    updated = AIConfigStore().update(payload, clear_api_key=clear_key)
    pub = updated.to_public_dict()

    if output_json is not None and str(output_json) == "-":
        print(json.dumps(pub, indent=2, ensure_ascii=False))
        return

    print_ai_config(console, pub, lang=eff)
    console.print(f"  [{C_OK}]✓[/] {safe(t('ai.config_saved', eff))}")
    if output_json:
        output_json.write_text(json.dumps(pub, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@ai_app.command("test")
def ai_test(
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output connectivity test result as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Test connectivity to the configured AI model provider."""
    from unpack.core.ai_engine import test_connection

    eff = _apply_lang(lang)
    json_stdout = output_json is not None and str(output_json) == "-"
    with _spinner(t("ai.spinner.test", eff), enabled=not json_stdout):
        res = test_connection(lang=eff)

    if json_stdout:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        if not res.get("ok"):
            raise typer.Exit(EXIT_ERROR)
        return

    print_ai_test_result(console, res, lang=eff)
    if output_json:
        output_json.write_text(json.dumps(res, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    if not res.get("ok"):
        raise typer.Exit(EXIT_ERROR)


@ai_app.command("analyze")
def ai_analyze(
    target: Annotated[Path, typer.Argument(help="Path to APK file, DEX file, or DEX directory")],
    module: Annotated[
        str,
        typer.Option("--module", "-m", help="Analysis module: scan | security | vmp | method"),
    ] = "scan",
    method: Annotated[
        Optional[str],
        typer.Option("--method", help="Target method (ClassName::methodName) for --module method"),
    ] = None,
    save_workspace: Annotated[
        Optional[str],
        typer.Option("--save-workspace", "-w", help="Workspace ID to archive sample & AI analysis"),
    ] = None,
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output AI analysis result as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Analysis & display language: en | zh | auto"),
    ] = None,
):
    """Run domain-expert AI reverse-engineering analysis on an APK or DEX target."""
    from unpack.core.ai_engine import AIAnalyzer
    from unpack.core.errors import UnpackError

    eff = _apply_lang(lang)
    mod_l = module.strip().lower()
    json_stdout = output_json is not None and str(output_json) == "-"

    if mod_l not in ("scan", "security", "vmp", "method"):
        _fail_error(
            f"Unsupported AI module: {module}",
            json_stdout=json_stdout,
            hint="Use --module scan | security | vmp | method",
        )
    if not target.exists():
        _fail_missing("Target", target, json_stdout=json_stdout)
    if mod_l == "method" and (not method or "::" not in method):
        _fail_error(t("ai.method.required", eff), json_stdout=json_stdout)

    analyzer = AIAnalyzer()
    scan_d: dict[str, Any] | None = None
    inspect_d: dict[str, Any] | None = None
    vmp_d: dict[str, Any] | None = None
    xref_d: dict[str, Any] | None = None

    try:
        with _spinner(t("ai.spinner.analyze", eff, module=mod_l, name=target.name), enabled=not json_stdout):
            if mod_l == "scan":
                from unpack.core.scanner import PackerScanner

                scan_d = PackerScanner().scan(target, verbose=True).to_verbose_dict()
                if target.is_file() and target.suffix.lower() == ".apk":
                    inspect_d = _inspect_apk_impl(target)
                result = analyzer.analyze_scan(scan_d, inspect=inspect_d, lang=eff)

            elif mod_l == "security":
                inspect_d = _inspect_apk_impl(target)
                result = analyzer.analyze_security(
                    inspect_d,
                    findings=inspect_d.get("findings") or [],
                    lang=eff,
                )

            elif mod_l == "vmp":
                from unpack.analysis.vmp import VmpDetector

                native_libs: list[dict[str, Any]] | None = None
                dex_blobs: list[tuple[str, bytes]] = []
                if target.is_file() and target.suffix.lower() == ".apk":
                    inspect_d = _inspect_apk_impl(target)
                    native_libs = inspect_d.get("native_libs") or []
                    with zipfile.ZipFile(target, "r") as zf:
                        for info in zf.infolist():
                            if info.filename.endswith(".dex") and "/" not in info.filename:
                                dex_blobs.append((info.filename, zf.read(info.filename)))
                else:
                    for p in _discover_dex_paths(target):
                        dex_blobs.append((p.name, p.read_bytes()))

                det = VmpDetector()
                tot = norm = nops = vmps = 0
                v_methods: list[dict[str, Any]] = []
                c_graph: list[dict[str, Any]] = []
                for fname, blob in dex_blobs:
                    vr = det.analyze_dex(blob)
                    tot += vr.total_methods
                    norm += vr.normal_count
                    nops += vr.nop_count
                    vmps += vr.vmp_count
                    v_methods.extend({**m, "dex_file": fname} for m in vr.vmp_methods)
                    c_graph.extend({**c, "dex_file": fname} for c in vr.call_graph)
                vmp_d = {
                    "dex": target.name,
                    "total_methods": tot,
                    "normal_count": norm,
                    "nop_count": nops,
                    "vmp_count": vmps,
                    "vmp_methods": v_methods,
                    "call_graph": c_graph,
                }
                result = analyzer.analyze_vmp_native(
                    vmp=vmp_d,
                    native_libs=native_libs,
                    xref=xref_d,
                    lang=eff,
                )

            else:  # method
                assert method is not None
                cls_name, _meth_name = method.split("::", 1)
                disasm_dict: dict[str, Any] | None = None
                if target.is_file() and target.suffix.lower() in (".dex", ".cdex"):
                    dex_info = _inspect_dex_impl(target, method_target=method)
                    disasm_dict = dex_info.get("disasm")
                elif target.is_file() and target.suffix.lower() == ".apk":
                    import tempfile

                    with zipfile.ZipFile(target, "r") as zf, tempfile.TemporaryDirectory() as td:
                        for info in zf.infolist():
                            if info.filename.endswith(".dex") and "/" not in info.filename:
                                tmp_dex = Path(td) / Path(info.filename).name
                                tmp_dex.write_bytes(zf.read(info.filename))
                                dex_info = _inspect_dex_impl(tmp_dex, method_target=method)
                                if dex_info.get("disasm"):
                                    disasm_dict = dex_info["disasm"]
                                    break
                if not disasm_dict:
                    _fail_error(
                        t("ai.method.not_found", eff, method=method, target=target.name),
                        json_stdout=json_stdout,
                    )
                result = analyzer.analyze_method(disasm_dict, class_name=cls_name, lang=eff)
    except UnpackError as exc:
        if json_stdout:
            print(json.dumps({"error": exc.message, "hint": exc.hint}, indent=2, ensure_ascii=False))
            raise typer.Exit(EXIT_ERROR)
        render_error(console, exc.message, hint=exc.hint, lang=eff)
        raise typer.Exit(EXIT_ERROR)

    res_dict = result.to_dict()

    saved_ws_label: str | None = None
    if save_workspace:
        from unpack.core.workspace_store import WorkspaceStore

        store = WorkspaceStore()
        try:
            sha = ""
            size_b = 0
            if target.is_file():
                raw = target.read_bytes()
                sha = hashlib.sha256(raw).hexdigest()
                size_b = len(raw)
            kind = "apk" if target.suffix.lower() == ".apk" else "dex"
            saved_sample = store.save_sample(
                save_workspace,
                {
                    "filename": target.name,
                    "sha256": sha,
                    "kind": kind,
                    "size_bytes": size_b,
                    "source_path": str(target.resolve()),
                    "scan_result": scan_d,
                    "inspect_result": inspect_d,
                    "vmp_result": vmp_d,
                    "xref_result": xref_d,
                },
            )
            store.save_ai_analysis(save_workspace, saved_sample["sample_id"], result.module, result)
            saved_ws_label = f"{save_workspace} ({saved_sample['sample_id']})"
            res_dict["saved_workspace"] = save_workspace
            res_dict["sample_id"] = saved_sample["sample_id"]
        finally:
            store.close()

    if json_stdout:
        print(json.dumps(res_dict, indent=2, ensure_ascii=False))
        return

    print_ai_analysis(console, res_dict, saved_workspace=saved_ws_label, lang=eff)
    if output_json:
        output_json.write_text(json.dumps(res_dict, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


# ── Persistent Workspace Storage (`unpack workspace`) ────────────────────────

workspace_app = typer.Typer(
    name="workspace",
    help="Manage persistent workspaces, saved samples, pipeline runs & AI analysis history",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
app.add_typer(workspace_app, name="workspace")


@workspace_app.command("list")
def workspace_list(
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output workspace list as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """List saved workspaces with sample, pipeline run, and AI analysis counts."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = _apply_lang(lang)
    store = WorkspaceStore()
    try:
        workspaces = store.list_workspaces()
    finally:
        store.close()

    if output_json is not None and str(output_json) == "-":
        print(json.dumps(workspaces, indent=2, ensure_ascii=False))
        return

    print_workspace_list(console, workspaces, lang=eff)
    if output_json:
        output_json.write_text(json.dumps(workspaces, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@workspace_app.command("show")
def workspace_show(
    ws_id: Annotated[str, typer.Argument(help="Workspace ID (e.g. default or ws_...)")],
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output full workspace snapshot as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Show saved samples, pipeline run history, and AI analyses inside a workspace."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = _apply_lang(lang)
    json_stdout = output_json is not None and str(output_json) == "-"
    store = WorkspaceStore()
    try:
        ws = store.get_workspace(ws_id)
        if ws is None:
            _fail_error(t("ws.not_found", eff, ws_id=ws_id), json_stdout=json_stdout, code=EXIT_NOT_FOUND)
        samples = store.list_samples(workspace_id=ws_id)
        runs = store.list_pipeline_runs(workspace_id=ws_id, limit=50)
        analyses = store.list_ai_analyses(workspace_id=ws_id, limit=50)
    finally:
        store.close()

    payload = {
        "workspace": ws,
        "samples": samples,
        "pipeline_runs": runs,
        "ai_analyses": analyses,
    }
    if json_stdout:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    print_workspace_detail(console, ws, samples, runs, analyses, lang=eff)
    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@workspace_app.command("create")
def workspace_create(
    name: Annotated[str, typer.Argument(help="Workspace display name")],
    desc: Annotated[str, typer.Option("--desc", "-d", help="Optional description")] = "",
    tags: Annotated[Optional[str], typer.Option("--tags", "-t", help="Comma-separated tags")] = None,
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output created workspace as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Create a new persistent workspace."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = _apply_lang(lang)
    store = WorkspaceStore()
    try:
        tag_list = [x.strip() for x in tags.split(",") if x.strip()] if tags else None
        ws = store.create_workspace(name, description=desc, tags=tag_list)
    finally:
        store.close()

    if output_json is not None and str(output_json) == "-":
        print(json.dumps(ws, indent=2, ensure_ascii=False))
        return

    render_kv_card(
        console,
        t("ws.title.created", eff),
        [
            (t("ws.kv.id", eff), f"[{C_INFO}]{safe(ws['id'])}[/]"),
            (t("ws.kv.name", eff), f"[{C_LABEL}]{safe(ws['name'])}[/]"),
            (t("ws.kv.desc", eff), safe(ws.get("description") or "—")),
        ],
        border_style=C_OK,
        title_style=f"bold {C_OK}",
    )
    if output_json:
        output_json.write_text(json.dumps(ws, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@workspace_app.command("delete")
def workspace_delete(
    ws_id: Annotated[str, typer.Argument(help="Workspace ID to delete")],
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output deletion status as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Delete a saved workspace and its archived snapshots."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = _apply_lang(lang)
    json_stdout = output_json is not None and str(output_json) == "-"
    store = WorkspaceStore()
    try:
        deleted = store.delete_workspace(ws_id)
    except ValueError as exc:
        _fail_error(str(exc), json_stdout=json_stdout)
    finally:
        store.close()

    if not deleted:
        _fail_error(t("ws.not_found", eff, ws_id=ws_id), json_stdout=json_stdout, code=EXIT_NOT_FOUND)

    payload = {"deleted": True, "id": ws_id}
    if json_stdout:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    console.print(f"  [{C_OK}]✓[/] {safe(t('ws.deleted', eff, ws_id=ws_id))}")


@workspace_app.command("export")
def workspace_export(
    ws_id: Annotated[str, typer.Argument(help="Workspace ID to export")],
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Destination JSON file (omit or use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Export a workspace and all saved samples, runs, and AI analyses to a JSON bundle."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = _apply_lang(lang)
    to_stdout = out is None or str(out) == "-"
    store = WorkspaceStore()
    try:
        try:
            bundle = store.export_workspace_json(ws_id)
        except KeyError:
            _fail_error(t("ws.not_found", eff, ws_id=ws_id), json_stdout=to_stdout, code=EXIT_NOT_FOUND)
    finally:
        store.close()

    serialized = json.dumps(bundle, indent=2, ensure_ascii=False)
    if to_stdout:
        print(serialized)
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(serialized)
    console.print(f"  [{C_OK}]✓[/] {safe(t('ws.exported', eff, ws_id=ws_id, path=out))}")


@workspace_app.command("import")
def workspace_import(
    bundle_file: Annotated[Path, typer.Argument(help="Path to exported workspace JSON file")],
    name: Annotated[
        Optional[str],
        typer.Option("--name", "-n", help="Optional override name for the imported workspace"),
    ] = None,
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output imported workspace metadata as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
):
    """Import a workspace snapshot JSON file into a newly restored workspace."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = _apply_lang(lang)
    json_stdout = output_json is not None and str(output_json) == "-"
    if not bundle_file.exists():
        _fail_missing("Bundle", bundle_file, json_stdout=json_stdout)

    try:
        bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _fail_error(t("ws.invalid_bundle", eff, err=str(exc)), json_stdout=json_stdout)

    store = WorkspaceStore()
    try:
        try:
            restored = store.import_workspace_json(bundle, name_override=name)
        except ValueError as exc:
            _fail_error(t("ws.invalid_bundle", eff, err=str(exc)), json_stdout=json_stdout)
    finally:
        store.close()

    if json_stdout:
        print(json.dumps(restored, indent=2, ensure_ascii=False))
        return

    render_kv_card(
        console,
        t("ws.title.imported", eff),
        [
            (t("ws.kv.id", eff), f"[{C_INFO}]{safe(restored['id'])}[/]"),
            (t("ws.kv.name", eff), f"[{C_LABEL}]{safe(restored['name'])}[/]"),
            (
                t("ws.kv.counts", eff),
                t(
                    "ws.counts_val",
                    eff,
                    samples=restored.get("sample_count", 0),
                    runs=restored.get("pipeline_run_count", 0),
                    ai=restored.get("ai_analysis_count", 0),
                ),
            ),
        ],
        border_style=C_OK,
        title_style=f"bold {C_OK}",
    )
    if output_json:
        output_json.write_text(json.dumps(restored, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@app.command()
def web(
    port: Annotated[int, typer.Option("--port", "-p", help="Port to listen on")] = 8080,
    host: Annotated[str, typer.Option("--host", help="Host to bind to")] = "127.0.0.1",
):
    """Launch Unpack Studio web UI.

    Opens a browser-based interface for scan, inspect, dump, repair, and verify.
    Requires flask: pip install -e '.[web]'
    """
    eff = get_lang()
    try:
        from unpack.web import create_app
    except ImportError:
        render_error(
            console,
            t("cli.web.no_flask", eff),
            hint=t("cli.web.no_flask_hint", eff),
            lang=eff,
        )
        raise typer.Exit(EXIT_ERROR)

    console.print(f"  [{C_OK}]✓[/] [{C_HEADER}]UNPACK Studio[/]  http://{host}:{port}")
    webapp = create_app()
    webapp.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    app()
