"""Domain renderers for DEX quality, verify, repair, inspect, VMP, and XRef."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from unpack.cli.format.components import render_kv_card, render_table
from unpack.cli.format.theme import (
    C_ACCENT,
    C_DIM,
    C_FAIL,
    C_INFO,
    C_OK,
    C_WARN,
    confidence_bar,
    eff_lang,
    format_bytes,
    render_severity_badge,
    safe,
)
from unpack.i18n import t


def print_report(console: Console, report: Any, *, lang: str | None = None) -> None:
    """Render DEX quality report card and optional per-DEX table."""
    eff = eff_lang(lang)
    cov = float(report.code_coverage)
    sc = float(report.score)
    cov_color = C_OK if cov > 0.8 else C_WARN if cov > 0.5 else C_FAIL
    sc_color = C_OK if sc > 0.8 else C_WARN if sc > 0.5 else C_FAIL

    rows: list[tuple[str, str]] = [
        (t("fmt.dex_files", eff), f"[{C_INFO}]{report.dex_count}[/]"),
        (t("fmt.col.classes", eff), f"[{C_INFO}]{report.total_classes:,}[/]"),
        (t("fmt.col.methods", eff), f"[{C_INFO}]{report.total_methods:,}[/]"),
        (t("fmt.with_code", eff), f"[{C_OK}]{report.methods_with_code:,}[/]"),
    ]
    if report.nop_methods > 0:
        rows.append(
            (
                t("fmt.nop_only", eff),
                f"[{C_FAIL}]{report.nop_methods:,}[/] [{C_DIM}]{safe(t('fmt.still_encrypted', eff))}[/]",
            )
        )
    rows.append((t("fmt.coverage", eff), f"{confidence_bar(cov)}  [{cov_color}]{cov:.1%}[/]"))
    rows.append((t("fmt.col.score", eff), f"{confidence_bar(sc)}  [{sc_color}]{sc:.1%}[/]"))

    render_kv_card(
        console,
        t("fmt.title.quality_report", eff),
        rows,
        border_style=C_INFO,
        title_style=f"bold {C_INFO}",
    )

    per_dex = getattr(report, "per_dex", None) or []
    if per_dex:
        dex_rows = [
            [
                safe(d.get("file", "")),
                format_bytes(d.get("file_size")),
                f"{int(d.get('classes', 0)):,}",
                f"{int(d.get('methods', 0)):,}",
                f"{int(d.get('methods_with_code', 0)):,}",
                f"[{C_WARN if d.get('nop_methods', 0) else C_DIM}]{int(d.get('nop_methods', 0)):,}[/]",
            ]
            for d in per_dex[:20]
        ]
        caption = (
            t("fmt.showing_n_of", eff, shown=20, total=len(per_dex))
            if len(per_dex) > 20
            else None
        )
        render_table(
            console,
            [
                (t("fmt.col.dex_file", eff), {}),
                (t("fmt.col.size", eff), {"justify": "right"}),
                (t("fmt.col.classes", eff), {"justify": "right"}),
                (t("fmt.col.methods", eff), {"justify": "right"}),
                (t("fmt.col.code", eff), {"justify": "right"}),
                (t("fmt.col.nop", eff), {"justify": "right"}),
            ],
            dex_rows,
            title=t("fmt.title.per_dex", eff),
            caption=caption,
        )


def print_verify_result(console: Console, name: str, result: Any) -> None:
    """Render single-file verification status (backward-compatible helper)."""
    if result.valid:
        console.print(f"  [{C_OK}]✓[/] {safe(name)} [{C_OK}]PASS[/]")
    else:
        console.print(f"  [{C_FAIL}]✗[/] {safe(name)} [{C_FAIL}]FAIL[/]")
        for issue in result.issues:
            console.print(f"    [{C_WARN}]▸[/] {safe(issue)}")


def print_verify_summary(
    console: Console,
    items: list[dict[str, Any]],
    *,
    lang: str | None = None,
) -> None:
    """Render tabular summary for one or more DEX verification results."""
    eff = eff_lang(lang)
    rows: list[list[str]] = []
    passed = 0
    for item in items:
        ok = bool(item.get("valid"))
        if ok:
            passed += 1
        stats = item.get("stats") or {}
        status = f"[{C_OK}]PASS[/]" if ok else f"[{C_FAIL}]FAIL[/]"
        issues = item.get("issues") or []
        detail = f"[{C_DIM}]ok[/]" if not issues else f"[{C_WARN}]{safe('; '.join(issues[:2]))}[/]"
        if len(issues) > 2:
            detail += f" [{C_DIM}](+{len(issues) - 2} more)[/]"
        rows.append(
            [
                safe(item.get("file", "")),
                status,
                format_bytes(stats.get("file_size")),
                f"{int(stats.get('class_count', 0)):,}",
                f"{int(stats.get('method_count', 0)):,}",
                detail,
            ]
        )

    render_table(
        console,
        [
            (t("fmt.col.dex_file", eff), {}),
            (t("fmt.col.status", eff), {"width": 6}),
            (t("fmt.col.size", eff), {"justify": "right"}),
            (t("fmt.col.classes", eff), {"justify": "right"}),
            (t("fmt.col.methods", eff), {"justify": "right"}),
            (t("fmt.col.issues", eff), {}),
        ],
        rows,
        title=t("fmt.title.dex_verify", eff, passed=passed, total=len(items)),
    )


def print_repair_summary(
    console: Console,
    items: list[dict[str, Any]],
    *,
    lang: str | None = None,
) -> None:
    """Render tabular summary for DEX repair results (with optional health delta)."""
    eff = eff_lang(lang)
    rows: list[list[str]] = []
    ok_count = 0
    for item in items:
        ok = bool(item.get("success"))
        if ok:
            ok_count += 1
        status = f"[{C_OK}]OK[/]" if ok else f"[{C_FAIL}]FAIL[/]"
        actions = ", ".join(item.get("actions") or []) or "—"
        nop = int(item.get("nop_methods") or 0)
        nop_cell = f"[{C_WARN}]{nop:,}[/]" if nop else f"[{C_DIM}]0[/]"
        delta = item.get("health_delta")
        delta_cell = (
            f"[{C_OK}]+{delta:.0%}[/]"
            if isinstance(delta, (int, float)) and delta > 0
            else f"[{C_DIM}]—[/]"
        )
        rows.append([safe(item.get("file", "")), status, safe(actions), nop_cell, delta_cell])

    render_table(
        console,
        [
            (t("fmt.col.dex_file", eff), {}),
            (t("fmt.col.status", eff), {"width": 6}),
            (t("fmt.col.actions", eff), {}),
            (t("fmt.col.nop", eff), {"justify": "right"}),
            (t("fmt.col.delta", eff), {"justify": "right"}),
        ],
        rows,
        title=t("fmt.title.dex_repair", eff, ok=ok_count, total=len(items)),
    )


def print_inspect_apk(
    console: Console,
    data: dict[str, Any],
    *,
    show_permissions: bool = False,
    lang: str | None = None,
) -> None:
    """Render deep APK static inspection report."""
    eff = eff_lang(lang)
    manifest = data.get("manifest") or {}
    signing = data.get("signing") or {}
    perms = data.get("permissions") or []
    components = data.get("components") or {}
    native_libs = data.get("native_libs") or []
    dex_files = data.get("dex_files") or []
    findings = data.get("findings") or []

    grade = str(data.get("risk_grade") or "—")
    risk = data.get("risk_score")
    risk_str = f"{grade} ({risk}/100)" if risk is not None else grade

    pkg_val = manifest.get("package") or manifest.get("package_name") or "—"
    rows: list[tuple[str, str]] = [
        (t("fmt.file", eff), f"[path]{safe(data.get('file', ''))}[/]  [{C_DIM}]({format_bytes(data.get('size_bytes'))})[/]"),
        ("SHA-256", f"[{C_DIM}]{safe(data.get('sha256') or '—')}[/]"),
        (t("fmt.package", eff), f"[{C_INFO}]{safe(pkg_val)}[/]"),
        (t("fmt.version", eff), f"{safe(manifest.get('version_name') or '—')} [{C_DIM}](code {safe(manifest.get('version_code') or '—')})[/]"),
        ("SDK", f"min {safe(manifest.get('min_sdk') or '—')} · target {safe(manifest.get('target_sdk') or '—')}"),
        ("Application", f"[{C_INFO}]{safe(manifest.get('application_class') or '—')}[/]"),
        (
            t("fmt.flags", eff),
            f"debuggable={safe(manifest.get('debuggable'))} · "
            f"backup={safe(manifest.get('allow_backup'))} · "
            f"cleartext={safe(manifest.get('uses_cleartext_traffic'))}",
        ),
        (t("fmt.risk_grade", eff), f"[{C_WARN if grade in ('D', 'F') else C_OK if grade in ('A', 'B') else C_INFO}]{safe(risk_str)}[/]"),
    ]
    if signing:
        schemes = ", ".join(signing.get("schemes") or []) or "unknown"
        certs = signing.get("certificates") or []
        cert_subj = certs[0].get("subject") if certs and isinstance(certs[0], dict) else None
        subj = signing.get("subject") or cert_subj or "—"
        rows.append((t("fmt.signing", eff), f"{safe(schemes)}  [{C_DIM}]{safe(subj)}[/]"))
    render_kv_card(console, t("fmt.title.apk_overview", eff), rows, border_style=C_INFO)

    if findings:
        f_rows = [
            [
                render_severity_badge(str(f.get("severity") or "info")),
                safe(f.get("rule_id") or ""),
                safe(f.get("title") or ""),
            ]
            for f in findings[:15]
        ]
        render_table(
            console,
            [
                (t("fmt.col.sev", eff), {"width": 6}),
                (t("fmt.col.rule", eff), {}),
                (t("fmt.col.finding", eff), {}),
            ],
            f_rows,
            title=t("fmt.title.findings", eff, count=len(findings)),
        )

    if show_permissions and perms:
        p_rows = []
        for p in perms[:40]:
            if isinstance(p, dict):
                is_dang = bool(p.get("dangerous") or p.get("protection_level") == "dangerous")
                prot = str(p.get("protection_level") or "normal")
                if is_dang:
                    tier = f"[{C_WARN}]DANGEROUS[/]"
                elif prot == "signature":
                    tier = f"[{C_INFO}]SIGNATURE[/]"
                else:
                    tier = f"[{C_DIM}]{safe(prot)}[/]"
                p_rows.append([tier, safe(p.get("name", ""))])
            else:
                p_rows.append([f"[{C_DIM}]perm[/]", safe(p)])
        render_table(
            console,
            [(t("fmt.col.tier", eff), {"width": 10}), (t("fmt.col.permission", eff), {})],
            p_rows,
            title=t("fmt.title.permissions", eff, count=len(perms)),
            caption=t("fmt.showing_n_of", eff, shown=40, total=len(perms)) if len(perms) > 40 else None,
        )

    if isinstance(components, dict) and any(components.values()):
        comp_rows = []
        for ctype in ("activities", "services", "receivers", "providers"):
            entries = components.get(ctype) or []
            exported = sum(1 for e in entries if isinstance(e, dict) and e.get("exported"))
            comp_rows.append([ctype.capitalize(), f"{len(entries):,}", f"[{C_WARN if exported else C_DIM}]{exported:,}[/]"])
        render_table(
            console,
            [
                (t("fmt.col.comp_type", eff), {}),
                (t("fmt.col.total", eff), {"justify": "right"}),
                (t("fmt.col.exported", eff), {"justify": "right"}),
            ],
            comp_rows,
            title=t("fmt.title.components", eff),
        )

    if native_libs:
        lib_rows = []
        for lib in native_libs[:20]:
            flags = []
            if lib.get("is_pie") is True or lib.get("pie") is True:
                flags.append("PIE")
            if lib.get("has_nx") is True or lib.get("nx") is True:
                flags.append("NX")
            relro = lib.get("relro")
            if relro and str(relro).lower() != "none":
                flags.append(f"RELRO:{relro}")
            if lib.get("has_canary") is True or lib.get("canary") is True:
                flags.append("CANARY")
            lib_rows.append(
                [
                    safe(lib.get("name") or lib.get("path") or ""),
                    safe(lib.get("abi") or "—"),
                    format_bytes(lib.get("size") or lib.get("size_bytes")),
                    safe(", ".join(flags) or "—"),
                ]
            )
        render_table(
            console,
            [
                (t("fmt.col.native_lib", eff), {}),
                (t("fmt.col.abi", eff), {}),
                (t("fmt.col.size", eff), {"justify": "right"}),
                (t("fmt.col.elf_flags", eff), {}),
            ],
            lib_rows,
            title=t("fmt.title.native_libs", eff, count=len(native_libs)),
            caption=t("fmt.showing_n_of", eff, shown=20, total=len(native_libs)) if len(native_libs) > 20 else None,
        )

    if dex_files:
        dex_rows = [
            [
                safe(d.get("name") or ""),
                format_bytes(d.get("size") or d.get("size_bytes")),
                f"{int(d.get('classes') or d.get('class_count') or 0):,}",
                f"{int(d.get('methods') or d.get('method_count') or 0):,}",
            ]
            for d in dex_files[:20]
        ]
        render_table(
            console,
            [
                (t("fmt.col.dex", eff), {}),
                (t("fmt.col.size", eff), {"justify": "right"}),
                (t("fmt.col.classes", eff), {"justify": "right"}),
                (t("fmt.col.methods", eff), {"justify": "right"}),
            ],
            dex_rows,
            title=t("fmt.title.embedded_dex", eff, count=len(dex_files)),
        )


def print_inspect_dex(
    console: Console,
    overview: dict[str, Any],
    *,
    classes: list[dict[str, Any]] | None = None,
    class_detail: dict[str, Any] | None = None,
    disasm: dict[str, Any] | None = None,
    lang: str | None = None,
) -> None:
    """Render static DEX inspection overview, classes, methods, or disassembly."""
    eff = eff_lang(lang)
    rows: list[tuple[str, str]] = [
        ("DEX", f"[path]{safe(overview.get('name') or overview.get('file') or 'classes.dex')}[/]"),
        (t("fmt.col.size", eff), format_bytes(overview.get("size_bytes") or overview.get("file_size"))),
        (t("fmt.version", eff), safe(overview.get("dex_version") or overview.get("version") or overview.get("magic") or "—")),
        (t("fmt.col.classes", eff), f"[{C_INFO}]{int(overview.get('class_count') or overview.get('classes') or 0):,}[/]"),
        (t("fmt.col.methods", eff), f"[{C_INFO}]{int(overview.get('method_count') or overview.get('methods') or 0):,}[/]"),
        (t("fmt.strings", eff), f"[{C_DIM}]{int(overview.get('string_count') or overview.get('strings') or 0):,}[/]"),
    ]
    nop_val = (
        overview["nop_method_count"]
        if "nop_method_count" in overview
        else overview.get("nop_methods")
    )
    if nop_val is not None:
        rows.append((t("fmt.nop_methods", eff), f"[{C_WARN if nop_val else C_DIM}]{int(nop_val):,}[/]"))
    render_kv_card(console, t("fmt.title.dex_overview", eff), rows, border_style=C_INFO)

    if classes:
        cls_rows = [
            [
                safe(c.get("java_name") or c.get("descriptor") or c.get("name") or c.get("class_name") or ""),
                f"{int(c.get('method_count') or c.get('methods') or 0):,}",
                f"[{C_WARN if c.get('nop_count', 0) else C_DIM}]{int(c.get('nop_count') or 0):,}[/]",
                safe(c.get("health") or "ok"),
            ]
            for c in classes[:40]
        ]
        render_table(
            console,
            [
                (t("fmt.col.class", eff), {}),
                (t("fmt.col.methods", eff), {"justify": "right"}),
                (t("fmt.col.nop", eff), {"justify": "right"}),
                (t("fmt.col.health", eff), {"width": 10}),
            ],
            cls_rows,
            title=t("fmt.title.classes", eff, count=len(classes)),
            caption=t("fmt.showing_n_of", eff, shown=40, total=len(classes)) if len(classes) > 40 else None,
        )

    if class_detail:
        methods = class_detail.get("methods") or []
        m_rows = [
            [
                safe(m.get("name") or ""),
                safe(m.get("signature") or m.get("descriptor") or ""),
                safe(m.get("health") or m.get("classification") or "normal"),
                f"{int(m.get('insns_size') or 0):,}",
            ]
            for m in methods[:50]
        ]
        cls_title = (
            class_detail.get("java_name")
            or class_detail.get("descriptor")
            or class_detail.get("name")
            or ""
        )
        render_table(
            console,
            [
                (t("fmt.col.method", eff), {}),
                (t("fmt.col.signature", eff), {}),
                (t("fmt.col.health", eff), {"width": 10}),
                (t("fmt.col.units", eff), {"justify": "right"}),
            ],
            m_rows,
            title=t("fmt.title.class_methods", eff, name=cls_title),
        )

    if disasm:
        insns = disasm.get("instructions") or []
        i_rows = [
            [
                f"[{C_DIM}]{int(ins.get('offset', 0)):04x}[/]",
                f"[{C_INFO}]{safe(ins.get('mnemonic') or ins.get('opcode_name') or '')}[/]",
                safe(ins.get("operands") or ins.get("detail") or ""),
            ]
            for ins in insns[:120]
        ]
        render_table(
            console,
            [
                (t("fmt.col.offset", eff), {"width": 7}),
                (t("fmt.col.opcode", eff), {"width": 22}),
                (t("fmt.col.operands", eff), {}),
            ],
            i_rows,
            title=t(
                "fmt.title.disasm",
                eff,
                cls=disasm.get("class_name", ""),
                method=disasm.get("method_name", ""),
            ),
            caption=t("fmt.showing_insns", eff, shown=min(len(insns), 120), total=len(insns)) if len(insns) > 120 else None,
        )


def print_vmp_summary(
    console: Console,
    per_dex: list[dict[str, Any]],
    totals: dict[str, int],
    *,
    vmp_methods: list[dict[str, Any]] | None = None,
    lang: str | None = None,
) -> None:
    """Render VMP method classification table and summary card."""
    eff = eff_lang(lang)
    if per_dex:
        rows = [
            [
                safe(d["file"]),
                f"[{C_OK}]{d['normal']:,}[/]",
                f"[{C_WARN if d['nop'] else C_DIM}]{d['nop']:,}[/]",
                f"[{C_FAIL if d['vmp'] else C_DIM}]{d['vmp']:,}[/]",
            ]
            for d in per_dex
        ]
        render_table(
            console,
            [
                (t("fmt.col.dex_file", eff), {}),
                (t("fmt.col.normal", eff), {"justify": "right"}),
                (t("fmt.col.nop", eff), {"justify": "right"}),
                (t("fmt.col.vmp_stub", eff), {"justify": "right"}),
            ],
            rows,
            title=t("fmt.title.vmp_per_dex", eff),
        )

    total = totals["total_methods"]
    normal = totals["normal_count"]
    nop = totals["nop_count"]
    vmp_total = totals["vmp_count"]
    vmp_color = C_FAIL if vmp_total else C_DIM
    vmp_ratio = (vmp_total / total) if total else 0.0

    card_rows = [
        (t("fmt.total", eff), f"[{C_INFO}]{total:,}[/]"),
        (t("fmt.col.normal", eff), f"[{C_OK}]{normal:,}[/]"),
        (t("fmt.col.nop", eff), f"[{C_WARN if nop else C_DIM}]{nop:,}[/]"),
        (t("fmt.col.vmp_stub", eff), f"[{vmp_color}]{vmp_total:,}[/] [{C_DIM}]({vmp_ratio:.1%})[/]"),
    ]
    render_kv_card(
        console,
        t("fmt.title.vmp_card", eff),
        card_rows,
        border_style=C_INFO,
        title_style=f"bold {C_INFO}",
    )

    if vmp_methods:
        stub_rows = [
            [
                safe(m.get("dex_file", "")),
                safe(m.get("class_name") or m.get("class") or ""),
                f"[{C_FAIL}]{safe(m.get('method_name') or m.get('method') or '')}[/]",
                safe(m.get("target", "")),
            ]
            for m in vmp_methods[:15]
        ]
        render_table(
            console,
            [
                (t("fmt.col.dex", eff), {}),
                (t("fmt.col.class", eff), {}),
                (t("fmt.col.method", eff), {}),
                (t("fmt.col.dispatcher", eff), {}),
            ],
            stub_rows,
            title=t("fmt.title.vmp_stubs", eff, count=len(vmp_methods)),
            caption=t("fmt.showing_n_of", eff, shown=15, total=len(vmp_methods)) if len(vmp_methods) > 15 else None,
        )


def print_xref_summary(
    console: Console,
    merged: Any,
    *,
    file_count: int = 1,
    search: str | None = None,
    lang: str | None = None,
) -> None:
    """Render cross-reference index summary and reflection/dynamic-loading highlights."""
    eff = eff_lang(lang)
    console.print(f"  [{C_DIM}]{safe(t('fmt.analyzed_dex', eff, count=file_count))}[/]")
    refl = merged.reflection_calls
    if search:
        q = search.lower()
        refl = [
            c for c in refl
            if q in str(c.get("target", "")).lower()
            or q in str((c.get("caller") or {}).get("class", "")).lower()
            or q in str((c.get("caller") or {}).get("method", "")).lower()
        ]

    card_rows = [
        (t("fmt.strings_ref", eff), f"[{C_INFO}]{len(merged.string_refs):,}[/]"),
        (t("fmt.methods_called", eff), f"[{C_INFO}]{len(merged.method_calls):,}[/]"),
        (t("fmt.fields_ref", eff), f"[{C_INFO}]{len(merged.field_refs):,}[/]"),
        (t("fmt.reflection_calls", eff), f"[{C_WARN if refl else C_DIM}]{len(refl):,}[/]"),
    ]
    render_kv_card(
        console,
        t("fmt.title.xref_card", eff),
        card_rows,
        border_style=C_INFO,
        title_style=f"bold {C_INFO}",
    )

    if refl:
        refl_rows = [
            [
                f"[{C_WARN}]{safe((c.get('caller') or {}).get('class', ''))}[/]",
                safe((c.get("caller") or {}).get("method", "")),
                f"[{C_ACCENT}]{safe(c.get('target', ''))}[/]",
            ]
            for c in refl[:30]
        ]
        render_table(
            console,
            [
                (t("fmt.col.caller_class", eff), {}),
                (t("fmt.col.method", eff), {}),
                (t("fmt.col.dynamic_target", eff), {}),
            ],
            refl_rows,
            title=t("fmt.title.reflection", eff, count=len(refl)),
            caption=t("fmt.showing_n_of", eff, shown=30, total=len(refl)) if len(refl) > 30 else None,
        )
