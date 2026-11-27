"""Guided pipeline planner & runner command: ``pipeline``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Optional

import typer

from unpack.cli import common
from unpack.cli.commands.dump import dump
from unpack.cli.format import (
    C_DIM,
    C_OK,
    C_WARN,
    print_inspect_apk,
    print_repair_summary,
    print_scan_result,
    print_verify_summary,
    print_vmp_summary,
    render_kv_card,
    render_pipeline_blueprint,
    render_pipeline_step,
    safe,
)
from unpack.core.pipeline import build_pipeline_plan, run_offline_pipeline
from unpack.i18n import t


def _render_offline_pipeline(
    apk: Path,
    *,
    output: Path,
    skip_repair: bool = False,
    repack: bool = False,
    report_html: Path | None = None,
    lang: str = "en",
) -> dict[str, Any]:
    """Execute ``unpack.core.pipeline.run_offline_pipeline`` with Rich CLI rendering."""

    def _on_event(event: str, payload: dict[str, Any]) -> None:
        con = common.console
        if event == "stage_start":
            render_pipeline_step(
                con,
                int(payload["step"]),
                int(payload["total_steps"]),
                str(payload["title"]),
                detail=payload.get("detail"),
                lang=lang,
            )
        elif event == "scan_done":
            print_scan_result(con, payload["scan"], payload["apk"], lang=lang)
        elif event == "inspect_done":
            print_inspect_apk(con, payload["inspect"], lang=lang)
        elif event == "extract_done":
            extracted = payload.get("extracted") or []
            if extracted:
                con.print(f"  [{C_OK}]✓[/] {safe(t('pipe.offline_exec.extracted', lang, count=len(extracted)))}")
            else:
                con.print(f"  [{C_WARN}]![/] {safe(t('pipe.offline_exec.no_dex', lang))}")
        elif event == "repair_done":
            print_repair_summary(con, payload["repair_results"], lang=lang)
        elif event == "verify_done":
            print_verify_summary(con, payload["verify_results"], lang=lang)
        elif event == "vmp_done":
            print_vmp_summary(
                con,
                payload["per_dex"],
                payload["vmp"],
                vmp_methods=payload.get("vmp_methods"),
                lang=lang,
            )
        elif event == "repack_done":
            rep_path = payload.get("repacked_path")
            if rep_path:
                con.print(f"  [{C_OK}]✓[/] {safe(rep_path)}")
        elif event == "report_done":
            audit = payload["audit"]
            html_dest = payload["report_html"]
            target_apk = payload["apk"]
            render_kv_card(
                con,
                t("pipe.offline_exec.title", lang),
                [
                    (t("fmt.target", lang), f"[path]{safe(target_apk.name)}[/]"),
                    (
                        t("fmt.col.grade", lang),
                        f"[{C_OK if audit.grade in ('A', 'B') else C_WARN}]{audit.grade}[/] ({audit.risk_score}/100)",
                    ),
                    (t("fmt.col.findings", lang), f"{len(audit.findings)}"),
                    (t("fmt.col.output", lang), f"[path]{safe(html_dest)}[/]"),
                ],
                border_style=C_OK,
                title_style=f"bold {C_OK}",
            )

    return run_offline_pipeline(
        apk,
        output=output,
        skip_repair=skip_repair,
        repack=repack,
        report_html=report_html,
        lang=lang,
        on_event=_on_event,
    )


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
) -> None:
    """Guided Pipeline Planner & Runner: live preflight blueprint + zero-device offline or device execution."""
    eff = common.apply_lang(lang)
    json_stdout = fmt.strip().lower() == "json" or (output_json is not None and str(output_json) == "-")
    if not apk.exists():
        common.fail_missing("APK", apk, json_stdout=json_stdout)

    with common.spinner(t("cli.spinner.pipeline", eff), enabled=not json_stdout):
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

    render_pipeline_blueprint(common.console, plan, lang=eff)

    if output_json:
        output_json.write_text(json.dumps(plan, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")

    if execute and not explain:
        if plan["mode"] == "offline":
            _render_offline_pipeline(
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
