"""Post-unpack DEX analysis commands: ``vmp`` and ``xref``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Optional

import typer

from unpack.cli import common
from unpack.cli.format import (
    C_DIM,
    C_OK,
    print_vmp_summary,
    print_xref_summary,
    safe,
)
from unpack.i18n import t


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
) -> None:
    """Classify methods as normal / NOP / VMP-stub."""
    eff = common.apply_lang(lang)
    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )
    report_fmt = fmt_l in ("markdown", "md", "html", "sarif")
    pipe_mode = json_stdout or (report_fmt and (out is None or str(out) == "-"))

    if not dex_dir.exists():
        common.fail_missing("Path", dex_dir, json_stdout=json_stdout)

    paths = common.discover_dex_paths(dex_dir)
    if not paths:
        common.fail_error(t("cli.no_dex_found", eff), json_stdout=json_stdout)

    from unpack.analysis.vmp import VmpDetector

    detector = VmpDetector()
    all_vmp_methods: list[dict[str, Any]] = []
    all_call_graph: list[dict[str, Any]] = []
    per_dex: list[dict[str, Any]] = []
    total = normal = nop = vmp_total = 0

    with common.spinner(t("cli.spinner.vmp", eff, count=len(paths)), enabled=not pipe_mode):
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
        common.console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
    else:
        print_vmp_summary(
            common.console,
            per_dex,
            {"total_methods": total, "normal_count": normal, "nop_count": nop, "vmp_count": vmp_total},
            vmp_methods=all_vmp_methods,
            lang=eff,
        )

    if output_json:
        output_json.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")


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
) -> None:
    """Build a cross-reference index: strings, method calls, fields, reflection."""
    from unpack.analysis.xref import XrefBuilder

    eff = common.apply_lang(lang)
    fmt_l = fmt.strip().lower()
    json_stdout = (output_json is not None and str(output_json) == "-") or (
        fmt_l == "json" and out is None
    )
    report_fmt = fmt_l in ("markdown", "md", "html", "sarif")
    pipe_mode = json_stdout or (report_fmt and (out is None or str(out) == "-"))

    if not dex_dir.exists():
        common.fail_missing("Path", dex_dir, json_stdout=json_stdout)

    paths = common.discover_dex_paths(dex_dir)
    if not paths:
        common.fail_error(t("cli.no_dex_found", eff), json_stdout=json_stdout)

    builder = XrefBuilder()
    with common.spinner(t("cli.spinner.xref", eff, count=len(paths)), enabled=not pipe_mode):
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
        common.console.print(f"  [{C_OK}]✓[/] {safe(t('cli.report_written', eff, path=out))}")
    else:
        print_xref_summary(common.console, merged, file_count=len(paths), search=search, lang=eff)

    if output_json:
        output_json.write_text(json.dumps(merged.to_dict(), indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    elif fmt_l == "json" and out is not None:
        out.write_text(json.dumps(merged.to_dict(), indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=out))}[/]")
