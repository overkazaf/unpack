"""Commercial audit report command: ``report``."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Optional

import typer

from unpack.cli import common
from unpack.cli.format import C_INFO, C_OK, C_WARN, render_kv_card, safe
from unpack.i18n import t


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
) -> None:
    """Generate a commercial audit report (HTML5 / Markdown / SARIF 2.1.0 / JSON)."""
    eff = common.apply_lang(lang)
    fmt_l = fmt.strip().lower()
    if fmt_l not in ("html", "markdown", "md", "sarif", "json"):
        common.fail_error(
            f"Unsupported format: {fmt}",
            hint="Use --format html | markdown | sarif | json",
        )

    to_stdout = out is None or str(out) == "-"
    if not target.exists():
        common.fail_missing("Target", target, json_stdout=(fmt_l == "json" and to_stdout))
    if apk is not None and not apk.exists():
        common.fail_missing("APK", apk, json_stdout=(fmt_l == "json" and to_stdout))

    from unpack.core.reporter import ReportGenerator, Reporter

    reporter = Reporter()
    scan_data: Any = None
    inspect_data: Any = None
    quality_data: Any = None
    verify_list: list[dict[str, Any]] = []
    vmp_data: dict[str, Any] | None = None
    xref_data: Any = None

    source_apk = apk if apk is not None else (target if target.is_file() and target.suffix.lower() == ".apk" else None)

    with common.spinner(t("cli.spinner.evidence", eff), enabled=not to_stdout):
        if source_apk is not None:
            from unpack.core.scanner import PackerScanner

            scan_data = PackerScanner().scan(source_apk, verbose=True)
            inspect_data = common.inspect_apk_dict(source_apk)

        if target.is_dir() or target.suffix.lower() in (".dex", ".cdex"):
            dex_paths = common.discover_dex_paths(target)
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
        common.console,
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
