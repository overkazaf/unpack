"""Shared CLI runtime state, exit codes, and helper utilities."""

from __future__ import annotations

import json
import sys
import time as _time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from unpack.cli.format import (
    C_DIM,
    C_INFO,
    create_console,
    render_error,
    safe,
)
from unpack.i18n import get_lang, set_lang, t
from unpack.logging_config import get_logger

logger = get_logger(__name__)

# ── Exit Codes (public contract — do not change) ─────────────────────────────
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_DEVICE = 2
EXIT_NO_PACKER = 3
EXIT_DUMP_FAILED = 4
EXIT_NOT_FOUND = 5

CONFIDENCE_HIDE_THRESHOLD = 0.1
CONFIDENCE_POSSIBLE_THRESHOLD = 0.2

# ── Runtime console state (re-initialized per invocation) ────────────────────
console = create_console(stderr=False)
err_console = create_console(stderr=True)
_QUIET = False


from unpack.utils.apk import silence_androguard_logs


def configure_consoles(*, no_color: bool = False, quiet: bool = False) -> None:
    """Re-initialize stdout and stderr Rich consoles for the active CLI invocation."""
    global console, err_console, _QUIET
    _QUIET = quiet
    console = create_console(stderr=False, no_color=no_color, quiet=quiet)
    err_console = create_console(stderr=True, no_color=no_color, quiet=quiet)


def is_quiet() -> bool:
    """Return True when the current CLI invocation runs in ``--quiet`` mode."""
    return _QUIET


def apply_lang(lang: str | None) -> str:
    """Apply an explicit per-command language override if provided, returning active lang."""
    if lang is not None:
        return set_lang(lang)
    return get_lang()


def gate_low_confidence(result: Any, verbose: bool) -> Any:
    """Suppress sub-10% confidence detections unless ``--verbose``."""
    from unpack.core.scanner import ScanResult

    if result.packer_name and result.confidence < CONFIDENCE_HIDE_THRESHOLD and not verbose:
        return ScanResult(
            details="No high-confidence packer detected (use -v for low-confidence matches)"
        )
    return result


def discover_dex_paths(target: Path) -> list[Path]:
    """Return a single DEX path or sorted non-derived DEX files from a directory."""
    if target.is_dir():
        return [
            p
            for p in sorted(target.glob("*.dex"))
            if "_repaired" not in p.stem and "_merged" not in p.stem
        ]
    return [target]


def fail_missing(
    label: str,
    path: Path,
    *,
    json_stdout: bool = False,
    plain_stderr: bool = False,
    hint: str | None = None,
) -> None:
    """Render a missing-target error and exit with ``EXIT_NOT_FOUND``."""
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


def fail_error(
    msg: str,
    *,
    json_stdout: bool = False,
    hint: str | None = None,
    code: int = EXIT_ERROR,
) -> None:
    """Render an actionable CLI error and exit with ``code``."""
    if json_stdout:
        print(json.dumps({"error": msg}))
    else:
        render_error(console, msg, hint=hint)
    raise typer.Exit(code)


@contextmanager
def spinner(msg: str, show_time: bool = True, enabled: bool = True) -> Iterator[None]:
    """Display a transient stderr spinner when running interactively."""
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


def next_steps_for_scan(apk: Path, result: Any) -> list[tuple[str, str]]:
    """Build context-aware runnable next-step CLI commands after ``unpack scan``."""
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


# ── Core Service Adapters ────────────────────────────────────────────────────


def run_doctor_dict(
    check_devices: bool = True,
    device_serial: str | None = None,
) -> dict[str, Any]:
    """Run environment diagnostics via ``unpack.core.doctor.run_doctor``."""
    from unpack.core.doctor import run_doctor

    res = run_doctor(check_devices=check_devices, device_serial=device_serial)
    return res.to_dict() if hasattr(res, "to_dict") else dict(res)


def inspect_apk_dict(apk: Path) -> dict[str, Any]:
    """Run static APK inspection via ``unpack.core.inspector.ApkInspector``."""
    from unpack.core.inspector import ApkInspector

    res = ApkInspector().inspect(apk)
    return res.to_dict() if hasattr(res, "to_dict") else dict(res)


def inspect_dex_dict(
    dex_path: Path,
    *,
    show_classes: bool = False,
    class_filter: str | None = None,
    method_target: str | None = None,
) -> dict[str, Any]:
    """Run static DEX inspection via ``unpack.analysis.dex_inspector.DexInspector``."""
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
