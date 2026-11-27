"""Dynamic unpacking & incremental rescan commands: ``dump``, ``rescan``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Optional

import typer

from unpack.cli import common
from unpack.cli.format import (
    C_DIM,
    C_FAIL,
    C_INFO,
    C_OK,
    C_WARN,
    print_repair_summary,
    print_report,
    print_scan_result,
    render_error,
    render_next_steps,
    render_pipeline_blueprint,
    render_pipeline_step,
    safe,
)
from unpack.core.pipeline import build_pipeline_plan
from unpack.i18n import t
from unpack.logging_config import get_logger

logger = get_logger(__name__)


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
) -> None:
    """Full unpack flow: scan -> dump -> repair -> verify.

    Requires a connected Android device. Pass --explain / --dry-run to preview
    the full stage-by-stage execution blueprint, live preflight checks, and
    packer-aware flag recommendations without touching a device.
    """
    eff = common.apply_lang(lang)
    if not apk.exists():
        common.fail_missing("APK", apk)

    if explain:
        with common.spinner(t("cli.spinner.pipeline", eff)):
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
        render_pipeline_blueprint(common.console, plan, lang=eff)
        return

    from unpack.core.dedup import dedup_dex_files
    from unpack.core.dispatcher import Dispatcher
    from unpack.core.reporter import Reporter, render_html
    from unpack.core.scanner import PackerScanner, ProtectionLevel
    from unpack.repair.dex_repair import DexRepairPipeline

    output.mkdir(parents=True, exist_ok=True)
    total_phases = 4 + (1 if deep else 0) - (1 if skip_repair else 0)
    step = 0

    step += 1
    render_pipeline_step(common.console, step, total_phases, t("cli.step.scan", eff), detail=apk.name, lang=eff)
    scanner = PackerScanner()
    with common.spinner(t("cli.spinner.analyze_apk", eff)):
        scan_result = scanner.scan(apk)
    print_scan_result(common.console, scan_result, apk, lang=eff)

    step += 1
    render_pipeline_step(common.console, step, total_phases, t("cli.step.dump", eff), lang=eff)
    dispatcher = Dispatcher()
    wait_label = (
        t("cli.spinner.dump_wait", eff, timeout=timeout)
        if timeout
        else t("cli.spinner.dump", eff)
    )
    with common.spinner(wait_label):
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
            common.console,
            t("cli.dump.no_dex", eff),
            detail=dump_result.error,
            hint=t("cli.dump.no_dex_hint", eff),
            lang=eff,
        )
        raise typer.Exit(common.EXIT_DUMP_FAILED)

    common.console.print(
        f"  [{C_OK}]✓[/] {safe(t('cli.dump.dumped_count', eff, count=len(dump_result.dex_files)))} "
        f"[{C_DIM}]({dump_result.duration_ms}ms)[/]"
    )

    before_count = len(list(output.glob("*.dex")))
    with common.spinner(t("cli.spinner.dedup", eff), show_time=False):
        unique = dedup_dex_files(output)
    removed_count = before_count - len(unique)
    if removed_count > 0:
        common.console.print(
            f"  [{C_DIM}]{safe(t('cli.dump.dedup_removed', eff, removed=removed_count, unique=len(unique)))}[/]"
        )

    # Always operate on the post-dedup unique DEX list so unlinked duplicates never cause FileNotFoundError.
    active_dex_files: list[Path] = list(unique)

    if deep:
        step += 1
        render_pipeline_step(common.console, step, total_phases, t("cli.step.deep", eff), lang=eff)

        if scan_result.protection_level not in (
            ProtectionLevel.FUNCTION_EXTRACTION,
            ProtectionLevel.VMP,
            ProtectionLevel.DEX2C,
        ):
            common.console.print(f"  [{C_WARN}]{safe(t('cli.dump.deep_warn', eff))}[/]")

        invoke_result = None
        pkg_name: str | None = None
        try:
            from unpack.engines.active_invoke import ActiveInvoker
            from unpack.repair.codeitem_merger import CodeItemMerger

            try:
                from unpack.utils.apk import get_package_name

                pkg_name = get_package_name(apk)
            except Exception as exc:
                logger.debug("Could not extract package name from %s: %s", apk, exc)

            if pkg_name:
                invoker = ActiveInvoker(
                    wait_seconds=timeout if timeout > 0 else 15,
                    anti_detect=not no_anti_detect,
                )
                with common.spinner(f"Force-invoking methods in {pkg_name}..."):
                    invoke_result = invoker.invoke(
                        package_name=pkg_name,
                        output_dir=output,
                        device_serial=device,
                    )

                if invoke_result.code_items:
                    common.console.print(
                        f"  [{C_OK}]✓[/] Captured [{C_OK}]{len(invoke_result.code_items)}[/] CodeItem(s)"
                    )
                    merger = CodeItemMerger()
                    merged_count = 0
                    for dex_path in active_dex_files:
                        with common.spinner(f"Merging CodeItems into {dex_path.name}...", show_time=False):
                            merge_result = merger.merge(dex_path, invoke_result.code_items)
                        if merge_result.methods_merged > 0:
                            merged_count += merge_result.methods_merged
                            common.console.print(
                                f"  [{C_OK}]✓[/] {safe(dex_path.name)}: "
                                f"[{C_OK}]{merge_result.methods_merged}[/] merged, "
                                f"[{C_WARN}]{merge_result.methods_still_nop}[/] still NOP"
                            )
                    if merged_count > 0:
                        common.console.print(f"  [{C_OK}]Total: {merged_count} methods restored[/]")
                    else:
                        common.console.print(
                            f"  [{C_DIM}]No NOP methods found to merge (DEX may not use function extraction)[/]"
                        )
                else:
                    msg = invoke_result.error or "no CodeItems captured"
                    common.console.print(f"  [{C_WARN}]{safe(msg)}[/]")
            else:
                common.console.print(f"  [{C_FAIL}]Could not determine package name for active invocation[/]")
        except ImportError:
            common.console.print(
                f"  [{C_FAIL}]Active invocation requires frida: pip install -e '.[frida]'[/]"
            )

        if (not invoke_result or not invoke_result.code_items) and pkg_name:
            try:
                from unpack.engines.active_invoke import MemoryActiveInvoker
                from unpack.utils.adb import get_device_serial

                _serial = device or get_device_serial()
                if _serial:
                    common.console.print(
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
                        common.console.print(
                            f"  [{C_OK}]✓[/] Exercised app ({mem_invoke_result.classes_resolved} actions)"
                        )
            except Exception as exc:
                logger.debug("MemoryActiveInvoker fallback failed: %s", exc)

    repair_dicts: list[dict[str, Any]] = []
    if not skip_repair:
        step += 1
        render_pipeline_step(common.console, step, total_phases, t("cli.step.repair", eff), lang=eff)
        pipeline = DexRepairPipeline()
        for dex_path in active_dex_files:
            with common.spinner(t("cli.spinner.repair", eff, name=dex_path.name), show_time=False):
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
        print_repair_summary(common.console, repair_dicts, lang=eff)

    step += 1
    render_pipeline_step(common.console, step, total_phases, t("cli.step.verify", eff), lang=eff)
    with common.spinner(t("cli.spinner.coverage", eff)):
        reporter = Reporter()
        quality_report = reporter.evaluate(output, scan_result)
    print_report(common.console, quality_report, lang=eff)

    report_path = output / "report.json"
    report_path.write_text(json.dumps(quality_report.to_dict(), indent=2, ensure_ascii=False))
    common.console.print(f"\n  [{C_DIM}]{safe(t('cli.dump.report_saved', eff, path=report_path))}[/]")

    if report_html:
        audit = reporter.build_audit_report(
            apk,
            scan=scan_result,
            quality=quality_report,
            repair_results=repair_dicts,
            lang=eff,
        )
        report_html.write_text(render_html(audit, lang=eff))
        common.console.print(f"  [{C_OK}]✓[/] {safe(t('cli.html_report_saved', eff, path=report_html))}")

    if not common.is_quiet():
        lf = " --lang zh" if eff == "zh" else ""
        steps = [
            (f"unpack repack {apk} {output}", t("cli.next.repack_jadx", eff)),
            (f"unpack report {output} --apk {apk} -F html -o audit.html{lf}", t("cli.next.commercial_report", eff)),
        ]
        if quality_report.nop_methods > 0:
            steps.insert(0, (f"unpack rescan {apk} {output} -r 5", t("cli.next.rescan_nop", eff)))
        render_next_steps(common.console, steps, lang=eff)


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
) -> None:
    """Incremental re-scan: trigger app components to decrypt more methods."""
    json_stdout = output_json is not None and str(output_json) == "-"

    if not apk.exists():
        common.fail_missing("APK", apk, json_stdout=json_stdout)
    if not dex_dir.exists() or not dex_dir.is_dir():
        common.fail_error(f"Directory not found: {dex_dir}", json_stdout=json_stdout)

    report_path = dex_dir / "report.json"
    if not report_path.exists():
        common.fail_error(
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
            common.console.print(f"  [{C_OK}]✓[/] No NOP-only methods found — nothing to rescan.")
        return

    if not json_stdout:
        common.console.print(
            f"  [{C_WARN}]{plan.nop_count}[/] NOP method(s) across "
            f"[{C_INFO}]{len(plan.dex_targets)}[/] DEX file(s)"
        )

    pkg_name = get_package_name(apk)
    if not pkg_name:
        common.fail_error("Could not determine package name from APK.", json_stdout=json_stdout)

    extractor = ComponentExtractor()
    manifest_strings = extractor.extract_manifest_strings(apk)
    plan.components = extractor.classify_components(manifest_strings)
    if not json_stdout:
        common.console.print(f"  [{C_DIM}]Found {len(plan.components)} component(s) to trigger[/]")

    serial = device or get_device_serial()
    if not serial:
        common.fail_error(
            "No ADB device connected.",
            json_stdout=json_stdout,
            hint="Connect a rooted Android device over USB and run `unpack doctor`.",
            code=common.EXIT_NO_DEVICE,
        )

    rescanner = IncrementalRescanner(rounds=rounds)
    with common.spinner(f"Running {rounds} round(s)...", enabled=not json_stdout):
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
        common.console.print(f"  [{C_DIM}]Re-dumped {len(result.new_dex_files)} new DEX file(s):[/]")
        for new_path in result.new_dex_files:
            common.console.print(f"    [{C_OK}]+[/] {safe(Path(new_path).name)}")

    if result.success:
        common.console.print(
            f"  [{C_OK}]✓[/] Recovered [{C_OK}]{result.methods_recovered}[/] method(s) over {result.rounds} round(s)"
        )
    elif result.error:
        render_error(common.console, "Rescan failed", detail=result.error)
    if result.methods_still_nop:
        common.console.print(f"  [{C_WARN}]{result.methods_still_nop}[/] method(s) still NOP")

    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")
