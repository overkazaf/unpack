"""GitHub-Flavored Markdown audit report renderer."""

from __future__ import annotations

from unpack.core.reporting.audit import (
    AuditReport,
    _fmt_bytes,
    _localized_exec_summary,
    _localized_recommendations,
    _localized_report_title,
    _sev_label,
)
from unpack.i18n import resolve_lang, t


def render_markdown(audit: AuditReport, lang: str = "en") -> str:
    """Render an ``AuditReport`` as GitHub-Flavored Markdown in English or Simplified Chinese."""
    eff = resolve_lang(lang)
    title_str = _localized_report_title(audit, eff)
    summary_str = _localized_exec_summary(audit, eff)
    recs = _localized_recommendations(audit, eff)

    lines: list[str] = []
    lines.append(f"# {title_str}")
    lines.append("")
    lines.append(f"> {summary_str}")
    lines.append("")
    lines.append(f"## {t('report.sec.metadata', eff)}")
    lines.append("")
    lines.append(f"| {t('report.col.field', eff)} | {t('report.col.value', eff)} |")
    lines.append("| --- | --- |")
    lines.append(f"| {t('report.meta.target', eff)} | `{audit.target}` |")
    if audit.target_sha256:
        lines.append(f"| SHA-256 | `{audit.target_sha256}` |")
    lines.append(f"| {t('report.meta.grade_risk', eff)} | **{audit.grade}** ({audit.risk_score}/100) |")
    lines.append(f"| {t('report.meta.generated', eff)} | {audit.generated_at} |")
    lines.append(f"| {t('report.meta.tool', eff)} | UNPACK v{audit.tool_version} |")
    lines.append("")

    # Findings summary
    counts = audit.severity_counts()
    lines.append(f"## {t('report.sec.findings_md', eff)}")
    lines.append("")
    lines.append(
        f"{t('report.sev.critical', eff)}: **{counts['critical']}** · "
        f"{t('report.sev.high', eff)}: **{counts['high']}** · "
        f"{t('report.sev.medium', eff)}: **{counts['medium']}** · "
        f"{t('report.sev.low', eff)}: **{counts['low']}** · "
        f"{t('report.sev.info', eff)}: **{counts['info']}**"
    )
    lines.append("")
    if audit.findings:
        lines.append(
            f"| {t('report.col.id', eff)} | {t('report.col.severity', eff)} | "
            f"{t('report.col.rule', eff)} | {t('report.col.finding', eff)} | {t('report.col.location', eff)} |"
        )
        lines.append("| --- | --- | --- | --- | --- |")
        for f in audit.findings:
            sev_txt = _sev_label(f.severity, eff)
            lines.append(
                f"| `{f.id}` | **{sev_txt}** | `{f.rule_id}` | "
                f"{f.title} | `{f.location or audit.target}` |"
            )
        lines.append("")
        for f in audit.findings:
            sev_txt = _sev_label(f.severity, eff)
            lines.append(f"### {f.id} · [{sev_txt}] {f.title}")
            lines.append("")
            if f.description:
                lines.append(f.description)
                lines.append("")
            if f.evidence:
                lines.append(f"**{t('report.evidence', eff)}:**")
                for ev in f.evidence[:15]:
                    lines.append(f"- `{ev}`")
                lines.append("")
            if f.remediation:
                lines.append(f"**{t('report.remediation', eff)}:** {f.remediation}")
                lines.append("")
    else:
        lines.append(t("report.no_findings_md", eff))
        lines.append("")

    # Packer Intelligence
    if audit.scan:
        lines.append(f"## {t('report.sec.packer', eff)}")
        lines.append("")
        packer = audit.scan.get("packer_name") or t("report.kpi.packer_none", eff)
        ver = audit.scan.get("packer_version") or "—"
        level = audit.scan.get("protection_level") or "none"
        conf = float(audit.scan.get("confidence") or 0.0)
        lines.append(f"| {t('report.col.metric', eff)} | {t('report.col.value', eff)} |")
        lines.append("| --- | --- |")
        lines.append(f"| {t('report.kv.packer', eff)} | **{packer}** |")
        lines.append(f"| {t('report.kv.version', eff)} | {ver} |")
        lines.append(f"| {t('report.kv.protection', eff)} | `{level}` |")
        lines.append(f"| {t('report.kv.confidence', eff)} | {conf:.0%} |")
        sigs = audit.scan.get("matched_signatures") or []
        if sigs:
            lines.append(f"| {t('report.kv.signatures', eff)} | {', '.join(f'`{s}`' for s in sigs)} |")
        lines.append("")
        breakdown = audit.scan.get("score_breakdown") or []
        if breakdown:
            lines.append(
                f"| {t('report.col.dimension', eff)} | {t('report.col.score', eff)} | "
                f"{t('report.col.max', eff)} | {t('report.col.status', eff)} |"
            )
            lines.append("| --- | ---: | ---: | --- |")
            for b in breakdown:
                st = "HIT" if b.get("matched") else "—"
                lines.append(
                    f"| {b.get('dimension', '')} | {float(b.get('score', 0)):.1f} "
                    f"| {float(b.get('max', 0)):.1f} | {st} |"
                )
            lines.append("")

    # APK Inspection
    if audit.inspect:
        manifest = audit.inspect.get("manifest") or {}
        lines.append(f"## {t('report.sec.apk_md', eff)}")
        lines.append("")
        if manifest:
            lines.append(f"| {t('report.col.attribute', eff)} | {t('report.col.value', eff)} |")
            lines.append("| --- | --- |")
            pkg_val = manifest.get("package") or manifest.get("package_name")
            if pkg_val:
                lines.append(f"| {t('report.kv.package', eff)} | `{pkg_val}` |")
            for key, label_key in (
                ("version_name", "report.kv.version_name"),
                ("version_code", "report.kv.version_code"),
                ("min_sdk", "report.kv.min_sdk"),
                ("target_sdk", "report.kv.target_sdk"),
                ("application_class", "report.kv.app_class"),
                ("debuggable", "report.kv.debuggable"),
                ("allow_backup", "report.kv.allow_backup"),
            ):
                if key in manifest and manifest[key] is not None and manifest[key] != "":
                    lines.append(f"| {t(label_key, eff)} | `{manifest[key]}` |")
            lines.append("")

        native_libs = audit.inspect.get("native_libs") or []
        if native_libs:
            lines.append(f"### {t('report.sec.native_libs', eff, count=len(native_libs))}")
            lines.append("")
            lines.append(
                f"| {t('report.col.library', eff)} | {t('report.col.abi', eff)} | "
                f"{t('report.col.size', eff)} | {t('report.col.flags', eff)} |"
            )
            lines.append("| --- | --- | ---: | --- |")
            for lib in native_libs[:25]:
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
                lines.append(
                    f"| `{lib.get('name') or lib.get('path', '')}` | {lib.get('abi', '—')} "
                    f"| {_fmt_bytes(lib.get('size') or lib.get('size_bytes'))} "
                    f"| {', '.join(flags) or '—'} |"
                )
            lines.append("")

    # DEX Quality
    if audit.quality:
        q = audit.quality
        lines.append(f"## {t('report.sec.quality_md', eff)}")
        lines.append("")
        lines.append(f"| {t('report.col.metric', eff)} | {t('report.col.value', eff)} |")
        lines.append("| --- | ---: |")
        lines.append(f"| {t('report.kv.dex_files', eff)} | {int(q.get('dex_count', 0)):,} |")
        lines.append(f"| {t('report.kv.total_classes', eff)} | {int(q.get('total_classes', 0)):,} |")
        lines.append(f"| {t('report.kv.total_methods', eff)} | {int(q.get('total_methods', 0)):,} |")
        lines.append(f"| {t('report.kv.methods_with_code', eff)} | {int(q.get('methods_with_code', 0)):,} |")
        lines.append(f"| {t('report.kv.nop_methods', eff)} | {int(q.get('nop_methods', 0)):,} |")
        lines.append(f"| {t('report.kv.code_coverage', eff)} | {float(q.get('code_coverage', 0)):.1%} |")
        lines.append(f"| {t('report.kv.quality_score', eff)} | {float(q.get('score', 0)):.1%} |")
        lines.append("")
        per_dex = q.get("per_dex") or []
        if per_dex:
            lines.append(
                f"| {t('report.col.file', eff)} | {t('report.col.size', eff)} | "
                f"{t('report.col.classes', eff)} | {t('report.col.methods', eff)} | "
                f"{t('report.col.with_code', eff)} | {t('report.col.nop', eff)} |"
            )
            lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
            for d in per_dex:
                lines.append(
                    f"| `{d.get('file', '')}` | {_fmt_bytes(d.get('file_size'))} "
                    f"| {int(d.get('classes', 0)):,} | {int(d.get('methods', 0)):,} "
                    f"| {int(d.get('methods_with_code', 0)):,} | {int(d.get('nop_methods', 0)):,} |"
                )
            lines.append("")

    # Verification
    if audit.verify_results:
        lines.append(f"## {t('report.sec.verify_md', eff)}")
        lines.append("")
        lines.append(
            f"| {t('report.col.file', eff)} | {t('report.col.status', eff)} | {t('report.col.issues', eff)} |"
        )
        lines.append("| --- | --- | --- |")
        for v in audit.verify_results:
            st = "PASS" if v.get("valid") else "FAIL"
            iss = "; ".join(v.get("issues") or []) or "—"
            lines.append(f"| `{v.get('file', '')}` | **{st}** | {iss} |")
        lines.append("")

    # VMP
    if audit.vmp:
        lines.append(f"## {t('report.sec.vmp_md', eff)}")
        lines.append("")
        lines.append(
            t(
                "report.vmp.line",
                eff,
                total=int(audit.vmp.get("total_methods", 0)),
                normal=int(audit.vmp.get("normal_count", 0)),
                nop=int(audit.vmp.get("nop_count", 0)),
                vmp=int(audit.vmp.get("vmp_count", 0)),
            )
        )
        lines.append("")

    # Xref
    if audit.xref:
        x_counts = audit.xref.get("counts") if isinstance(audit.xref.get("counts"), dict) else {}
        str_cnt = int(x_counts.get("strings")) if "strings" in x_counts else len(audit.xref.get("string_refs") or {})
        call_cnt = (
            int(x_counts.get("method_calls"))
            if "method_calls" in x_counts
            else len(audit.xref.get("method_calls") or {})
        )
        field_cnt = (
            int(x_counts.get("field_refs"))
            if "field_refs" in x_counts
            else len(audit.xref.get("field_refs") or {})
        )
        refl_cnt = (
            int(x_counts.get("reflection_calls"))
            if "reflection_calls" in x_counts
            else len(audit.xref.get("reflection_calls") or [])
        )
        lines.append(f"## {t('report.sec.xref_md', eff)}")
        lines.append("")
        lines.append(
            t(
                "report.xref.line",
                eff,
                strings=str_cnt,
                calls=call_cnt,
                fields=field_cnt,
                refl=refl_cnt,
            )
        )
        lines.append("")

    # Recommendations
    lines.append(f"## {t('report.sec.recs_md', eff)}")
    lines.append("")
    for rec in recs:
        lines.append(f"- {rec}")
    lines.append("")

    return "\n".join(lines)


__all__ = ["render_markdown"]
