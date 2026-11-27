"""DEX repair, verification, export, repack, and reassemble commands."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Annotated, Any, Optional

import typer

from unpack.cli import common
from unpack.cli.format import (
    C_DIM,
    C_OK,
    C_WARN,
    print_repair_summary,
    print_verify_summary,
    render_error,
    render_kv_card,
    render_next_steps,
    render_table,
    safe,
)
from unpack.i18n import t
from unpack.logging_config import get_logger

logger = get_logger(__name__)


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
) -> None:
    """Repair dumped DEX files.

    Fixes: header fields, Adler32 checksum, SHA-1 signature, map_list
    validation, CodeItem alignment. Detects NOP-only methods.
    """
    eff = common.apply_lang(lang)
    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )
    report_fmt = fmt_l in ("markdown", "md", "html", "sarif")
    pipe_mode = json_stdout or (report_fmt and (out is None or str(out) == "-"))

    if not dex.exists():
        common.fail_missing("Path", dex, json_stdout=json_stdout)

    paths = common.discover_dex_paths(dex)
    if not paths:
        common.fail_error(t("cli.no_dex_found", eff), json_stdout=json_stdout)

    from unpack.repair.dex_repair import DexRepairPipeline

    pipeline = DexRepairPipeline()
    has_diff = hasattr(pipeline, "repair_with_diff")

    def _run_one(p: Path) -> dict[str, Any]:
        if has_diff:
            diff = pipeline.repair_with_diff(p, in_place=in_place)
            r = diff.repair
            return {
                "file": p.name,
                "success": r.success,
                "actions": r.actions,
                "nop_methods": r.nop_method_count,
                "output": str(r.output_path) if r.output_path else None,
                "health_delta": getattr(diff, "health_delta", None),
                "resolved_issues": getattr(diff, "resolved_issues", []),
            }
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
        with common.spinner(t("cli.spinner.repair", eff, name=p.name), show_time=False):
            repair_results.append(_run_one(p))

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(dex, repair_results=repair_results, lang=eff)
        out.write_text(ReportGenerator.render(audit, fmt_l, lang=eff))
        common.console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
    else:
        print_repair_summary(common.console, repair_results, lang=eff)
        ok = sum(1 for r in repair_results if r["success"])
        common.console.print(f"  [{C_OK}]{ok}[/]/{len(paths)} repaired")

    if output_json:
        output_json.write_text(json.dumps(repair_results, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(repair_results, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")

    if not common.is_quiet() and not report_fmt:
        lf = " --lang zh" if eff == "zh" else ""
        render_next_steps(
            common.console,
            [(f"unpack verify {dex}{lf}", t("cli.next.verify_repaired", eff))],
            lang=eff,
        )


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
) -> None:
    """Check DEX integrity and quality metrics.

    Validates magic, checksum, SHA-1, file size, section bounds.
    Reports NOP-only methods from function extraction packers.
    """
    eff = common.apply_lang(lang)
    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )
    report_fmt = fmt_l in ("markdown", "md", "html", "sarif")
    pipe_mode = json_stdout or (report_fmt and (out is None or str(out) == "-"))

    if not path.exists():
        common.fail_missing("Path", path, json_stdout=json_stdout)

    paths = common.discover_dex_paths(path)
    if not paths:
        common.fail_error(t("cli.no_dex_found", eff), json_stdout=json_stdout)

    from unpack.repair.verifier import DexVerifier

    verifier = DexVerifier()

    def _as_dict(name: str, result: Any) -> dict[str, Any]:
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
        with common.spinner(t("cli.spinner.verify", eff, name=p.name), show_time=False):
            result = verifier.verify(p)
        all_results.append(_as_dict(p.name, result))

    if report_fmt and out is not None:
        from unpack.core.reporter import ReportGenerator, Reporter

        audit = Reporter().build_audit_report(path, verify_results=all_results, lang=eff)
        out.write_text(ReportGenerator.render(audit, fmt_l, lang=eff))
        common.console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
    else:
        print_verify_summary(common.console, all_results, lang=eff)

    if output_json:
        output_json.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")

    failed = [r for r in all_results if not r["valid"]]
    if not common.is_quiet() and not report_fmt and failed:
        lf = " --lang zh" if eff == "zh" else ""
        render_next_steps(
            common.console,
            [(f"unpack repair {path}{lf}", t("cli.next.repair_failing", eff, count=len(failed)))],
            lang=eff,
        )


def export(
    dex_dir: Annotated[Path, typer.Argument(help="Directory containing dumped DEX files")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory")] = Path("./fart_export"),
    format: Annotated[str, typer.Option("--format", "-f", help="Export format: fart")] = "fart",
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save export summary as JSON (use - for stdout)"),
    ] = None,
) -> None:
    """Export dumped DEX files in alternative formats (e.g., FART bin/txt)."""
    json_stdout = output_json is not None and str(output_json) == "-"

    if format != "fart":
        common.fail_error(f"Unknown format: {format}", json_stdout=json_stdout, hint="Supported formats: fart")

    if not dex_dir.exists():
        common.fail_missing("Directory", dex_dir, json_stdout=json_stdout)

    dex_files = sorted(dex_dir.glob("*.dex"))
    if not dex_files:
        common.fail_error(f"No DEX files found in {dex_dir}", json_stdout=json_stdout)

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
        common.console,
        [("DEX File", {}), ("Methods", {"justify": "right"}), ("Output", {})],
        rows,
        title="FART Export",
    )
    common.console.print(f"  [{C_OK}]✓[/] Exported {total_methods:,} methods in FART format to [path]{safe(output)}[/]")

    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")


def repack(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[Path, typer.Argument(help="Directory with dumped/repaired DEX files")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory")] = Path("./repacked"),
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save result as JSON (use - for stdout)"),
    ] = None,
) -> None:
    """Repack dumped DEX into an analyzable APK."""
    pipe_mode = output_json is not None and str(output_json) == "-"

    if not apk.exists():
        common.fail_missing("APK", apk, json_stdout=pipe_mode)
    if not dex_dir.exists():
        common.fail_missing("DEX directory", dex_dir, json_stdout=pipe_mode)

    from unpack.repack.repacker import Repacker

    repacker = Repacker()
    with common.spinner(f"Repacking {apk.name}...", enabled=not pipe_mode):
        result = repacker.repack(apk, dex_dir, output)

    if not result.success:
        if pipe_mode:
            print(json.dumps({"success": False, "error": result.error}, indent=2, ensure_ascii=False))
            raise typer.Exit(common.EXIT_ERROR)
        render_error(common.console, "Repack failed", detail=result.error)
        raise typer.Exit(common.EXIT_ERROR)

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
        common.console,
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
        common.console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")

    if not common.is_quiet():
        render_next_steps(common.console, [(f"jadx-gui {result.output_path}", "open repacked APK in JADX")])


def reassemble(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[Path, typer.Argument(help="Directory with dumped DEX files")],
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save class mapping summary as JSON (use - for stdout)"),
    ] = None,
) -> None:
    """Map dumped DEX classes back to original APK DEX numbering."""
    from unpack.repair.reassemble import ClassMapper, DexClassLister

    json_stdout = output_json is not None and str(output_json) == "-"

    if not apk.exists():
        common.fail_missing("APK", apk, json_stdout=json_stdout)
    if not dex_dir.exists():
        common.fail_missing("Path", dex_dir, json_stdout=json_stdout)

    lister = DexClassLister()
    mapper = ClassMapper()

    with common.spinner("Reading original APK classes...", enabled=not json_stdout):
        original = lister.list_from_apk(apk)
    if not original:
        common.fail_error("No classes*.dex found in APK.", json_stdout=json_stdout)

    dex_paths = common.discover_dex_paths(dex_dir)
    if not dex_paths:
        common.fail_error(f"No DEX files found in: {dex_dir}", json_stdout=json_stdout)

    dumped: dict[str, list[str]] = {}
    with common.spinner(f"Reading {len(dex_paths)} dumped DEX file(s)...", enabled=not json_stdout):
        for p in dex_paths:
            try:
                dumped[p.name] = lister.list_from_file(p)
            except Exception as exc:
                logger.debug("Failed to list classes from %s: %s", p, exc)
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
        common.console,
        [("Original DEX", {}), ("Classes Mapped", {"justify": "right"})],
        rows,
        title="DEX Class Reassembly",
    )
    common.console.print(f"  [{C_OK}]{classes_mapped:,}[/] mapped, [{C_WARN}]{classes_unmapped:,}[/] unmapped")

    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]Saved to {safe(output_json)}[/]")
