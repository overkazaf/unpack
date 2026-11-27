"""Recon & diagnostics commands: ``doctor``, ``inspect``, ``scan``, ``analyze``."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from unpack.cli import common
from unpack.cli.format import (
    C_DIM,
    C_OK,
    print_doctor_report,
    print_inspect_apk,
    print_inspect_dex,
    print_scan_result,
    print_verbose,
    render_next_steps,
    safe,
)
from unpack.i18n import t


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
) -> None:
    """Check Python dependencies, RE tools, connected devices, and engine readiness."""
    eff = common.apply_lang(lang)
    pipe_json = fmt.lower() == "json" or (output_json is not None and str(output_json) == "-")
    with common.spinner(t("cli.spinner.doctor", eff), enabled=not pipe_json):
        report = common.run_doctor_dict(check_devices=not no_devices, device_serial=device)

    payload = json.dumps(report, indent=2, ensure_ascii=False)
    if pipe_json:
        print(payload)
        return

    print_doctor_report(common.console, report, lang=eff)
    if output_json:
        output_json.write_text(payload)
        common.console.print(f"\n  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


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
) -> None:
    """Deep static inspection of an APK (manifest, signing, libs) or DEX (classes, methods, disasm)."""
    eff = common.apply_lang(lang)
    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )

    if not target.exists():
        common.fail_missing("Target", target, json_stdout=json_stdout)

    is_dex = target.suffix.lower() in (".dex", ".cdex")
    if is_dex:
        with common.spinner(
            t("cli.spinner.inspect_dex", eff, name=target.name),
            enabled=not json_stdout and fmt_l == "table",
        ):
            data = common.inspect_dex_dict(
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
            common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")
            return
        print_inspect_dex(
            common.console,
            data.get("overview") or {},
            classes=data.get("classes"),
            class_detail=data.get("class_detail"),
            disasm=data.get("disasm"),
            lang=eff,
        )
        if output_json:
            output_json.write_text(payload)
            common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
        return

    # APK inspection
    with common.spinner(
        t("cli.spinner.inspect_apk", eff, name=target.name),
        enabled=not json_stdout and fmt_l == "table",
    ):
        data = common.inspect_apk_dict(target)

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
            common.console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
        else:
            print(rendered)
        return

    if fmt_l == "json" and out:
        out.write_text(payload)
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")
        return

    print_inspect_apk(common.console, data, show_permissions=permissions, lang=eff)
    if output_json:
        output_json.write_text(payload)
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")

    if not common.is_quiet():
        lf = " --lang zh" if eff == "zh" else ""
        render_next_steps(
            common.console,
            [
                (f"unpack scan {target} -v{lf}", t("cli.next.scan_evidence", eff)),
                (f"unpack inspect {target} -F html -o audit.html{lf}", t("cli.next.export_html", eff)),
            ],
            lang=eff,
        )


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
) -> None:
    """Identify packer type and protection level.

    Analyzes APK static features — SO files, manifest, assets, DEX structure —
    to detect packer vendor, version, and protection level.
    Covers 24 vendors (360, Tencent, Bangbang, iJiami, NetEase, Ali, etc).
    No device required. Exit code 0 if packer found, 3 if not.
    """
    eff = common.apply_lang(lang)
    if batch:
        if not apk.is_dir():
            common.fail_error(
                "--batch requires a directory",
                hint="Pass a directory containing .apk files: unpack scan ./apks/ --batch",
            )
        from unpack.core.scanner import PackerScanner

        scanner = PackerScanner()
        for apk_file in sorted(apk.glob("*.apk")):
            try:
                result = scanner.scan(apk_file, verbose=False)
                d = result.to_dict()
                d["file"] = apk_file.name
                print(json.dumps(d, ensure_ascii=False), flush=True)
            except Exception as exc:
                common.logger.debug("Batch scan failed for %s: %s", apk_file, exc)
                print(json.dumps({"file": apk_file.name, "error": str(exc)}, ensure_ascii=False), flush=True)
        return

    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )
    report_fmt = fmt_l in ("markdown", "md", "html", "sarif")
    pipe_mode = report or json_stdout or (report_fmt and (out is None or str(out) == "-"))

    if not apk.exists():
        common.fail_missing(
            "APK",
            apk,
            json_stdout=json_stdout,
            plain_stderr=report or (report_fmt and out is None),
        )

    from unpack.core.scanner import PackerScanner
    from unpack.utils.apk import find_sibling_splits

    extra_apks = find_sibling_splits(apk)
    if extra_apks and not pipe_mode:
        common.console.print(
            f"  [{C_DIM}]{safe(t('cli.split_apks_found', eff, count=len(extra_apks)))}[/]"
        )
    scanner = PackerScanner()

    if pipe_mode:
        result = scanner.scan(apk, verbose=True, extra_apks=extra_apks or None)
        result_gated = common.gate_low_confidence(result, verbose)
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
            raise typer.Exit(common.EXIT_NO_PACKER)
        return

    with common.spinner(t("cli.spinner.scan", eff)):
        result = scanner.scan(apk, verbose=verbose or report_fmt, extra_apks=extra_apks or None)

    result_to_show = common.gate_low_confidence(result, verbose)

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(apk, scan=result_to_show, lang=eff)
        out.write_text(ReportGenerator.render(audit, fmt_l, lang=eff))
        common.console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
    else:
        print_scan_result(common.console, result_to_show, apk, lang=eff)
        if verbose:
            print_verbose(common.console, result, lang=eff)

    if output_json:
        d = result.to_verbose_dict() if verbose else result.to_dict()
        output_json.write_text(json.dumps(d, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    elif fmt_l == "json" and out is not None:
        d = result_to_show.to_verbose_dict() if verbose else result_to_show.to_dict()
        out.write_text(json.dumps(d, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")

    if not common.is_quiet() and not report_fmt:
        render_next_steps(common.console, common.next_steps_for_scan(apk, result_to_show), lang=eff)

    if not result_to_show.packer_name:
        raise typer.Exit(common.EXIT_NO_PACKER)


def analyze(
    apk: Annotated[Path, typer.Argument(help="Path to APK file")],
    prompt: Annotated[
        Optional[str],
        typer.Option("--prompt", "-p", help="Custom analysis prompt for Claude"),
    ] = None,
) -> None:
    """Generate detailed scan report and pipe to Claude for AI analysis.

    Outputs a structured plain-text report to stdout, designed to be piped
    to `claude -p` for deep analysis of packer characteristics, bypass
    strategies, and similar samples.
    """
    if not apk.exists():
        print(f"APK not found: {apk}", file=sys.stderr)
        raise typer.Exit(common.EXIT_NOT_FOUND)

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
