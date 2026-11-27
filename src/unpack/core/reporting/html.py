"""Self-contained, offline, print-ready commercial HTML5 audit report renderer."""

from __future__ import annotations

import html
import math
from typing import Any

from unpack.core.reporting.audit import (
    AuditReport,
    _fmt_bytes,
    _localized_exec_summary,
    _localized_recommendations,
    _localized_report_title,
    _sev_label,
)
from unpack.i18n import resolve_lang, t


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _svg_risk_gauge(risk_score: int, grade: str) -> str:
    """Render an inline SVG ring gauge for the overall risk score."""
    score = max(0, min(100, int(risk_score)))
    radius = 40
    circ = 2 * math.pi * radius
    dash = circ * (score / 100.0)
    color = (
        "#10b981" if score <= 15 else
        "#38bdf8" if score <= 35 else
        "#f59e0b" if score <= 55 else
        "#f97316" if score <= 75 else
        "#ef4444"
    )
    return (
        f'<svg class="gauge" viewBox="0 0 100 100" width="96" height="96" aria-label="Risk Score {score}">'
        f'<circle cx="50" cy="50" r="{radius}" fill="none" stroke="var(--border)" stroke-width="8" />'
        f'<circle cx="50" cy="50" r="{radius}" fill="none" stroke="{color}" stroke-width="8" '
        f'stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}" '
        f'transform="rotate(-90 50 50)" />'
        f'<text x="50" y="47" text-anchor="middle" font-size="24" font-weight="700" fill="var(--text)">{_esc(grade)}</text>'
        f'<text x="50" y="65" text-anchor="middle" font-size="11" fill="var(--muted)">{score}/100</text>'
        f"</svg>"
    )


def _svg_method_donut(normal: int, nop: int, vmp: int, empty: int, *, lang: str = "en") -> str:
    """Render an inline SVG donut chart for method health composition."""
    total = normal + nop + vmp + empty
    if total <= 0:
        return ""
    eff = resolve_lang(lang)
    radius = 38
    circ = 2 * math.pi * radius
    segments = [
        (t("report.donut.normal", eff), normal, "#10b981"),
        (t("report.donut.nop", eff), nop, "#f59e0b"),
        (t("report.donut.vmp", eff), vmp, "#ef4444"),
        (t("report.donut.empty", eff), empty, "#64748b"),
    ]
    arcs: list[str] = []
    offset = 0.0
    legend: list[str] = []
    for label, count, color in segments:
        if count <= 0:
            continue
        frac = count / total
        seg_len = circ * frac
        arcs.append(
            f'<circle cx="50" cy="50" r="{radius}" fill="none" stroke="{color}" stroke-width="11" '
            f'stroke-dasharray="{seg_len:.2f} {circ:.2f}" stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 50 50)" />'
        )
        offset += seg_len
        legend.append(
            f'<div class="legend-item"><span class="dot" style="background:{color}"></span>'
            f'<span>{_esc(label)}</span><strong>{count:,}</strong>'
            f'<span class="muted">({frac:.1%})</span></div>'
        )
    center_lbl = _esc(t("report.donut.center", eff))
    return (
        '<div class="donut-wrap">'
        '<svg viewBox="0 0 100 100" width="128" height="128" aria-label="Method Composition">'
        f'<circle cx="50" cy="50" r="{radius}" fill="none" stroke="var(--border)" stroke-width="11" />'
        + "".join(arcs)
        + f'<text x="50" y="48" text-anchor="middle" font-size="13" font-weight="700" fill="var(--text)">{total:,}</text>'
        + f'<text x="50" y="61" text-anchor="middle" font-size="8.5" fill="var(--muted)">{center_lbl}</text>'
        + "</svg>"
        + f'<div class="legend">{"".join(legend)}</div>'
        + "</div>"
    )


def render_html(audit: AuditReport, lang: str = "en") -> str:
    """Render a self-contained, offline, print-ready commercial HTML5 audit report."""
    eff = resolve_lang(lang)
    html_lang = "zh-CN" if eff == "zh" else "en"
    title_str = _localized_report_title(audit, eff)
    summary_str = _localized_exec_summary(audit, eff)
    recs = _localized_recommendations(audit, eff)

    counts = audit.severity_counts()
    packer_label = t("report.kpi.packer_none", eff)
    protection_label = "none"
    confidence_pct = "—"
    if audit.scan and audit.scan.get("packer_name"):
        packer_label = str(audit.scan["packer_name"])
        if audit.scan.get("packer_version"):
            packer_label += f" ({audit.scan['packer_version']})"
        protection_label = str(audit.scan.get("protection_level") or "unknown")
        confidence_pct = f"{float(audit.scan.get('confidence') or 0.0):.0%}"

    coverage_str = "—"
    dex_count_str = "—"
    methods_str = "—"
    if audit.quality:
        coverage_str = f"{float(audit.quality.get('code_coverage') or 0.0):.1%}"
        dex_count_str = f"{int(audit.quality.get('dex_count') or 0):,}"
        methods_str = f"{int(audit.quality.get('total_methods') or 0):,}"
    elif audit.inspect and audit.inspect.get("dex_files"):
        dex_count_str = f"{len(audit.inspect['dex_files']):,}"

    # Findings HTML cards
    if audit.findings:
        finding_cards: list[str] = []
        ev_lbl = _esc(t("report.evidence", eff))
        rem_lbl = _esc(t("report.remediation", eff))
        loc_lbl = _esc(t("report.location", eff))
        for f in audit.findings:
            ev_html = ""
            if f.evidence:
                ev_items = "".join(f"<li><code>{_esc(e)}</code></li>" for e in f.evidence[:20])
                ev_html = f'<div class="finding-sub"><strong>{ev_lbl}</strong><ul>{ev_items}</ul></div>'
            rem_html = ""
            if f.remediation:
                rem_html = f'<div class="finding-sub"><strong>{rem_lbl}</strong><p>{_esc(f.remediation)}</p></div>'
            sev_badge = _sev_label(f.severity, eff)
            finding_cards.append(
                f'<article class="finding-card" data-severity="{_esc(f.severity)}" '
                f'data-search="{_esc((f.title + " " + f.rule_id + " " + f.category + " " + f.description).lower())}">'
                f'<div class="finding-head">'
                f'<span class="badge sev-{_esc(f.severity)}">{_esc(sev_badge)}</span>'
                f'<code class="rule-id">{_esc(f.rule_id)}</code>'
                f'<span class="finding-title">{_esc(f.title)}</span>'
                f'<span class="chip">{_esc(f.category)}</span>'
                f"</div>"
                f'<p class="finding-desc">{_esc(f.description)}</p>'
                f'<div class="finding-meta">{loc_lbl}: <code>{_esc(f.location or audit.target)}</code> · ID: <code>{_esc(f.id)}</code></div>'
                f"{ev_html}{rem_html}"
                f"</article>"
            )
        findings_section_body = "".join(finding_cards)
    else:
        findings_section_body = f'<p class="empty">{_esc(t("report.no_findings_html", eff))}</p>'

    # Packer breakdown section
    packer_html = ""
    if audit.scan:
        bd_rows = ""
        for b in audit.scan.get("score_breakdown") or []:
            score = float(b.get("score") or 0.0)
            mx = float(b.get("max") or 1.0)
            pct = max(0.0, min(100.0, (score / mx * 100.0) if mx > 0 else 0.0))
            hit_cls = "badge sev-low" if b.get("matched") else "badge sev-info"
            hit_txt = "HIT" if b.get("matched") else "—"
            bd_rows += (
                f"<tr><td>{_esc(b.get('dimension', ''))}</td>"
                f'<td><div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%"></div></div></td>'
                f'<td class="num">{score:.1f} / {mx:.1f}</td>'
                f'<td><span class="{hit_cls}">{hit_txt}</span></td></tr>'
            )
        sigs = audit.scan.get("matched_signatures") or []
        sigs_html = (
            '<div class="tag-row">'
            + "".join(f'<code class="tag">{_esc(s)}</code>' for s in sigs)
            + "</div>"
            if sigs
            else f'<p class="muted">{_esc(t("report.no_sigs", eff))}</p>'
        )
        bd_table = (
            f'<table class="data-table"><thead><tr><th>{_esc(t("report.col.dimension", eff))}</th>'
            f'<th>{_esc(t("report.col.weight", eff))}</th>'
            f'<th class="num">{_esc(t("report.col.score", eff))}</th>'
            f'<th>{_esc(t("report.col.status", eff))}</th></tr></thead>'
            f"<tbody>{bd_rows}</tbody></table>"
            if bd_rows
            else ""
        )
        packer_html = (
            f'<section class="panel"><h2>{_esc(t("report.sec.packer", eff))}</h2>'
            f'<div class="kv-grid">'
            f'<div><span class="k">{_esc(t("report.kv.packer", eff))}</span><span class="v">{_esc(packer_label)}</span></div>'
            f'<div><span class="k">{_esc(t("report.kv.protection", eff))}</span><span class="v"><code>{_esc(protection_label)}</code></span></div>'
            f'<div><span class="k">{_esc(t("report.kv.confidence", eff))}</span><span class="v">{_esc(confidence_pct)}</span></div>'
            f'<div><span class="k">{_esc(t("report.kv.app_class", eff))}</span><span class="v"><code>{_esc(audit.scan.get("app_class") or "—")}</code></span></div>'
            f"</div>{sigs_html}{bd_table}</section>"
        )

    # APK static inspection section
    inspect_html = ""
    if audit.inspect:
        manifest = audit.inspect.get("manifest") or {}
        signing = audit.inspect.get("signing") or {}
        perms = audit.inspect.get("permissions") or []
        native_libs = audit.inspect.get("native_libs") or []
        dangerous_perms = [
            p
            for p in perms
            if isinstance(p, dict) and (p.get("dangerous") or p.get("protection_level") == "dangerous")
        ]

        manifest_kv = ""
        if manifest:
            pkg_name = manifest.get("package") or manifest.get("package_name") or "—"
            perms_val = t("report.kv.perms_val", eff, total=len(perms), dangerous=len(dangerous_perms))
            manifest_kv = (
                '<div class="kv-grid">'
                f'<div><span class="k">{_esc(t("report.kv.package", eff))}</span><span class="v"><code>{_esc(pkg_name)}</code></span></div>'
                f'<div><span class="k">{_esc(t("report.kv.version", eff))}</span><span class="v">{_esc(manifest.get("version_name") or "—")} ({_esc(manifest.get("version_code") or "—")})</span></div>'
                f'<div><span class="k">{_esc(t("report.kv.sdk_pair", eff))}</span><span class="v">{_esc(manifest.get("min_sdk") or "—")} / {_esc(manifest.get("target_sdk") or "—")}</span></div>'
                f'<div><span class="k">{_esc(t("report.kv.debug_backup", eff))}</span><span class="v">{_esc(manifest.get("debuggable"))} / {_esc(manifest.get("allow_backup"))}</span></div>'
                f'<div><span class="k">{_esc(t("report.kv.signing", eff))}</span><span class="v">{_esc(", ".join(signing.get("schemes") or []) or "—")}</span></div>'
                f'<div><span class="k">{_esc(t("report.kv.permissions", eff))}</span><span class="v">{_esc(perms_val)}</span></div>'
                "</div>"
            )

        lib_table = ""
        if native_libs:
            lib_rows = ""
            for lib in native_libs[:30]:
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
                lib_rows += (
                    f"<tr><td><code>{_esc(lib.get('name') or lib.get('path', ''))}</code></td>"
                    f"<td>{_esc(lib.get('abi') or '—')}</td>"
                    f'<td class="num">{_esc(_fmt_bytes(lib.get("size") or lib.get("size_bytes")))}</td>'
                    f"<td>{_esc(', '.join(flags) or '—')}</td></tr>"
                )
            lib_table = (
                f'<h3>{_esc(t("report.sec.native_libs", eff, count=len(native_libs)))}</h3>'
                f'<table class="data-table"><thead><tr><th>{_esc(t("report.col.library", eff))}</th>'
                f'<th>{_esc(t("report.col.abi", eff))}</th>'
                f'<th class="num">{_esc(t("report.col.size", eff))}</th>'
                f'<th>{_esc(t("report.col.elf_mitigations", eff))}</th></tr></thead>'
                f"<tbody>{lib_rows}</tbody></table>"
            )
        inspect_html = f'<section class="panel"><h2>{_esc(t("report.sec.apk_html", eff))}</h2>{manifest_kv}{lib_table}</section>'

    # DEX Quality + Method Composition Donut
    quality_html = ""
    if audit.quality or audit.vmp:
        donut_svg = ""
        if audit.vmp and int(audit.vmp.get("total_methods") or 0) > 0:
            donut_svg = _svg_method_donut(
                int(audit.vmp.get("normal_count") or 0),
                int(audit.vmp.get("nop_count") or 0),
                int(audit.vmp.get("vmp_count") or 0),
                0,
                lang=eff,
            )
        elif audit.quality and int(audit.quality.get("total_methods") or 0) > 0:
            with_code = int(audit.quality.get("methods_with_code") or 0)
            nop = int(audit.quality.get("nop_methods") or 0)
            empty = int(audit.quality.get("empty_methods") or 0)
            donut_svg = _svg_method_donut(max(0, with_code - nop), nop, 0, empty, lang=eff)

        per_dex_html = ""
        if audit.quality and audit.quality.get("per_dex"):
            rows = ""
            for d in audit.quality["per_dex"]:
                m_total = int(d.get("methods") or 0)
                m_code = int(d.get("methods_with_code") or 0)
                m_nop = int(d.get("nop_methods") or 0)
                cov = (m_code / m_total) if m_total else 0.0
                rows += (
                    f"<tr><td><code>{_esc(d.get('file', ''))}</code></td>"
                    f'<td class="num">{_esc(_fmt_bytes(d.get("file_size")))}</td>'
                    f'<td class="num">{int(d.get("classes") or 0):,}</td>'
                    f'<td class="num">{m_total:,}</td>'
                    f'<td class="num">{m_code:,}</td>'
                    f'<td class="num">{m_nop:,}</td>'
                    f'<td class="num">{cov:.1%}</td></tr>'
                )
            dex_search_ph = _esc(t("report.search.dex", eff))
            per_dex_html = (
                f'<div class="table-toolbar"><input id="dexSearch" class="search-input" '
                f'type="search" placeholder="{dex_search_ph}" aria-label="{dex_search_ph}" /></div>'
                f'<table class="data-table" id="dexTable"><thead><tr><th>{_esc(t("report.col.dex_file", eff))}</th>'
                f'<th class="num">{_esc(t("report.col.size", eff))}</th>'
                f'<th class="num">{_esc(t("report.col.classes", eff))}</th>'
                f'<th class="num">{_esc(t("report.col.methods", eff))}</th>'
                f'<th class="num">{_esc(t("report.col.with_code", eff))}</th>'
                f'<th class="num">{_esc(t("report.col.nop", eff))}</th>'
                f'<th class="num">{_esc(t("report.col.coverage", eff))}</th>'
                f"</tr></thead><tbody>{rows}</tbody></table>"
            )
        quality_html = (
            f'<section class="panel"><h2>{_esc(t("report.sec.quality_html", eff))}</h2>'
            f"{donut_svg}{per_dex_html}</section>"
        )

    # Verification & Repair section
    verify_html = ""
    if audit.verify_results or audit.repair_results:
        v_rows = ""
        no_issues_txt = t("report.verify.no_issues", eff)
        for v in audit.verify_results:
            ok = bool(v.get("valid"))
            badge = '<span class="badge sev-pass">PASS</span>' if ok else '<span class="badge sev-high">FAIL</span>'
            issues = "; ".join(str(x) for x in (v.get("issues") or [])) or no_issues_txt
            v_rows += (
                f"<tr><td><code>{_esc(v.get('file', ''))}</code></td>"
                f"<td>{badge}</td><td>{_esc(issues)}</td></tr>"
            )
        r_rows = ""
        for r in audit.repair_results:
            rep = r.get("repair") if isinstance(r.get("repair"), dict) else r
            ok = bool(rep.get("success", r.get("success", True)))
            badge = '<span class="badge sev-pass">OK</span>' if ok else '<span class="badge sev-high">FAIL</span>'
            actions = ", ".join(str(x) for x in (rep.get("actions") or r.get("actions") or [])) or "—"
            nop_cnt = int(
                rep.get("nop_method_count")
                or rep.get("nop_methods")
                or r.get("nop_methods")
                or r.get("nop_method_count")
                or 0
            )
            fname = r.get("file") or rep.get("file") or ""
            r_rows += (
                f"<tr><td><code>{_esc(fname)}</code></td>"
                f"<td>{badge}</td><td>{_esc(actions)}</td>"
                f'<td class="num">{nop_cnt:,}</td></tr>'
            )
        v_block = (
            f'<h3>{_esc(t("report.sec.integrity_sub", eff))}</h3><table class="data-table">'
            f'<thead><tr><th>{_esc(t("report.col.file", eff))}</th>'
            f'<th>{_esc(t("report.col.status", eff))}</th>'
            f'<th>{_esc(t("report.col.details", eff))}</th></tr></thead>'
            f"<tbody>{v_rows}</tbody></table>"
            if v_rows
            else ""
        )
        r_block = (
            f'<h3>{_esc(t("report.sec.repair_sub", eff))}</h3><table class="data-table">'
            f'<thead><tr><th>{_esc(t("report.col.file", eff))}</th>'
            f'<th>{_esc(t("report.col.status", eff))}</th>'
            f'<th>{_esc(t("report.col.actions", eff))}</th>'
            f'<th class="num">{_esc(t("report.col.nop", eff))}</th></tr></thead>'
            f"<tbody>{r_rows}</tbody></table>"
            if r_rows
            else ""
        )
        verify_html = f'<section class="panel"><h2>{_esc(t("report.sec.verify_html", eff))}</h2>{v_block}{r_block}</section>'

    # Recommendations section
    rec_items = "".join(f"<li>{_esc(rec)}</li>" for rec in recs)
    rec_html = f'<section class="panel"><h2>{_esc(t("report.sec.recs_html", eff))}</h2><ol class="rec-list">{rec_items}</ol></section>'

    sha_pill = (
        f'<span class="meta-pill">SHA-256: <code>{_esc(audit.target_sha256[:16])}…</code></span>'
        if audit.target_sha256
        else ""
    )

    finding_search_ph = _esc(t("report.search.findings", eff))
    return f"""<!DOCTYPE html>
<html lang="{html_lang}" data-theme="dark">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{_esc(title_str)}</title>
<style>
:root {{
  --bg: #0b0e14;
  --surface: #121720;
  --surface-2: #18202c;
  --border: #263143;
  --text: #e6edf3;
  --muted: #8b98a9;
  --accent: #38bdf8;
  --ok: #10b981;
  --warn: #f59e0b;
  --fail: #ef4444;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", Inter, Roboto, sans-serif;
}}
[data-theme="light"] {{
  --bg: #f6f8fa;
  --surface: #ffffff;
  --surface-2: #f1f5f9;
  --border: #d8dee6;
  --text: #0f172a;
  --muted: #526071;
  --accent: #0284c7;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  line-height: 1.55;
  font-size: 14px;
}}
.container {{ max-width: 1120px; margin: 0 auto; padding: 28px 24px 56px; }}
.topbar {{
  display: flex; justify-content: space-between; align-items: flex-start; gap: 20px;
  padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 24px;
}}
.brand {{ font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--accent); font-weight: 700; }}
h1 {{ margin: 4px 0 8px; font-size: 22px; font-weight: 700; letter-spacing: -0.01em; }}
h2 {{ margin: 0 0 14px; font-size: 15px; font-weight: 600; letter-spacing: 0.01em; }}
h3 {{ margin: 18px 0 10px; font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }}
.meta-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }}
.meta-pill {{
  font-size: 12px; color: var(--muted); background: var(--surface); border: 1px solid var(--border);
  padding: 3px 9px; border-radius: 6px;
}}
.top-actions {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.btn {{
  background: var(--surface); color: var(--text); border: 1px solid var(--border);
  padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 500;
}}
.btn:hover {{ border-color: var(--accent); }}
.summary-banner {{
  background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--accent);
  border-radius: 8px; padding: 14px 16px; margin-bottom: 20px; color: var(--text);
}}
.kpi-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 22px;
}}
.kpi {{
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px;
}}
.kpi-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }}
.kpi-value {{ font-size: 20px; font-weight: 700; margin-top: 4px; font-variant-numeric: tabular-nums; }}
.kpi-sub {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}
.panel {{
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 18px 20px; margin-bottom: 18px;
}}
.kv-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 14px;
}}
.kv-grid .k {{ display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }}
.kv-grid .v {{ display: block; font-size: 13px; font-weight: 500; margin-top: 2px; word-break: break-word; }}
code {{ font-family: var(--mono); font-size: 12px; background: var(--surface-2); padding: 1px 5px; border-radius: 4px; }}
.tag-row {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }}
.tag {{ border: 1px solid var(--border); padding: 2px 7px; }}
.data-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.data-table th, .data-table td {{
  padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top;
}}
.data-table th {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); font-weight: 600; }}
.data-table .num {{ text-align: right; font-variant-numeric: tabular-nums; font-family: var(--mono); }}
.bar-track {{ width: 140px; height: 7px; background: var(--surface-2); border-radius: 99px; overflow: hidden; }}
.bar-fill {{ height: 100%; background: var(--accent); border-radius: 99px; }}
.badge {{
  display: inline-block; font-size: 10px; font-weight: 700; letter-spacing: 0.06em;
  padding: 2px 7px; border-radius: 4px; font-family: var(--mono);
}}
.sev-critical {{ background: rgba(239, 68, 68, 0.22); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.45); }}
.sev-high {{ background: rgba(249, 115, 22, 0.18); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
.sev-medium {{ background: rgba(245, 158, 11, 0.16); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); }}
.sev-low {{ background: rgba(56, 189, 248, 0.14); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }}
.sev-info {{ background: var(--surface-2); color: var(--muted); border: 1px solid var(--border); }}
.sev-pass {{ background: rgba(16, 185, 129, 0.16); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35); }}
.toolbar {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; margin-bottom: 14px; }}
.pill-group {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.pill {{
  background: var(--surface-2); color: var(--muted); border: 1px solid var(--border);
  padding: 4px 10px; border-radius: 99px; font-size: 12px; cursor: pointer;
}}
.pill.active {{ background: var(--accent); color: #06131f; border-color: var(--accent); font-weight: 600; }}
.search-input {{
  background: var(--surface-2); color: var(--text); border: 1px solid var(--border);
  padding: 6px 10px; border-radius: 6px; font-size: 12px; min-width: 220px;
}}
.finding-card {{
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
  padding: 13px 15px; margin-bottom: 10px;
}}
.finding-head {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 6px; }}
.finding-title {{ font-weight: 600; }}
.rule-id {{ color: var(--muted); }}
.chip {{
  margin-left: auto; font-size: 11px; color: var(--muted);
  border: 1px solid var(--border); padding: 1px 7px; border-radius: 99px;
}}
.finding-desc {{ margin: 4px 0 8px; color: var(--text); }}
.finding-meta {{ font-size: 12px; color: var(--muted); }}
.finding-sub {{ margin-top: 8px; font-size: 12.5px; }}
.finding-sub ul {{ margin: 4px 0 0; padding-left: 18px; }}
.finding-sub p {{ margin: 4px 0 0; color: var(--muted); }}
.donut-wrap {{ display: flex; flex-wrap: wrap; align-items: center; gap: 24px; margin-bottom: 16px; }}
.legend {{ display: flex; flex-direction: column; gap: 6px; }}
.legend-item {{ display: flex; align-items: center; gap: 8px; font-size: 13px; }}
.dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
.muted {{ color: var(--muted); }}
.empty {{ color: var(--muted); font-style: italic; }}
.table-toolbar {{ margin-bottom: 10px; display: flex; justify-content: flex-end; }}
.rec-list {{ margin: 0; padding-left: 20px; }}
.rec-list li {{ margin-bottom: 6px; }}
footer {{ margin-top: 28px; text-align: center; font-size: 12px; color: var(--muted); }}
@media print {{
  body {{ background: #ffffff; color: #0f172a; }}
  .btn, .toolbar, .table-toolbar {{ display: none !important; }}
  .panel, .kpi, .finding-card {{ break-inside: avoid; background: #ffffff; border-color: #cbd5e1; }}
}}
</style>
</head>
<body>
<div class="container">
  <header class="topbar">
    <div>
      <div class="brand">{_esc(t("report.brand", eff))}</div>
      <h1>{_esc(title_str)}</h1>
      <div class="meta-row">
        <span class="meta-pill">{_esc(t("report.meta.target", eff))}: <code>{_esc(audit.target)}</code></span>
        {sha_pill}
        <span class="meta-pill">{_esc(t("report.meta.generated", eff))}: {_esc(audit.generated_at)}</span>
        <span class="meta-pill">UNPACK v{_esc(audit.tool_version)}</span>
      </div>
    </div>
    <div class="top-actions">
      {_svg_risk_gauge(audit.risk_score, audit.grade)}
      <button class="btn" id="themeToggle" type="button">{_esc(t("report.btn.theme", eff))}</button>
      <button class="btn" id="printReport" type="button">{_esc(t("report.btn.print", eff))}</button>
    </div>
  </header>

  <div class="summary-banner">{_esc(summary_str)}</div>

  <section class="kpi-grid">
    <div class="kpi"><div class="kpi-label">{_esc(t("report.kpi.packer", eff))}</div><div class="kpi-value">{_esc(packer_label)}</div><div class="kpi-sub">{_esc(t("report.kpi.packer_sub", eff, level=protection_label, conf=confidence_pct))}</div></div>
    <div class="kpi"><div class="kpi-label">{_esc(t("report.kpi.coverage", eff))}</div><div class="kpi-value">{_esc(coverage_str)}</div><div class="kpi-sub">{_esc(t("report.kpi.dex_sub", eff, count=dex_count_str))}</div></div>
    <div class="kpi"><div class="kpi-label">{_esc(t("report.kpi.methods", eff))}</div><div class="kpi-value">{_esc(methods_str)}</div><div class="kpi-sub">{_esc(t("report.kpi.risk_sub", eff, score=audit.risk_score))}</div></div>
    <div class="kpi"><div class="kpi-label">{_esc(t("report.kpi.findings", eff))}</div><div class="kpi-value">{len(audit.findings)}</div><div class="kpi-sub">{_esc(t("report.kpi.findings_sub", eff, high=counts['critical'] + counts['high'], med=counts['medium']))}</div></div>
  </section>

  <section class="panel">
    <h2>{_esc(t("report.sec.findings_explorer", eff, count=len(audit.findings)))}</h2>
    <div class="toolbar">
      <div class="pill-group" id="sevFilters">
        <button class="pill active" data-sev="all" type="button">{_esc(t("report.pill.all", eff, count=len(audit.findings)))}</button>
        <button class="pill" data-sev="critical" type="button">{_esc(t("report.sev.critical", eff))} ({counts['critical']})</button>
        <button class="pill" data-sev="high" type="button">{_esc(t("report.sev.high", eff))} ({counts['high']})</button>
        <button class="pill" data-sev="medium" type="button">{_esc(t("report.sev.medium", eff))} ({counts['medium']})</button>
        <button class="pill" data-sev="low" type="button">{_esc(t("report.sev.low", eff))} ({counts['low']})</button>
        <button class="pill" data-sev="info" type="button">{_esc(t("report.sev.info", eff))} ({counts['info']})</button>
      </div>
      <input id="findingSearch" class="search-input" type="search" placeholder="{finding_search_ph}" aria-label="{finding_search_ph}" />
    </div>
    <div id="findingsList">{findings_section_body}</div>
  </section>

  {packer_html}
  {inspect_html}
  {quality_html}
  {verify_html}
  {rec_html}

  <footer>{_esc(t("report.footer", eff, version=audit.tool_version, schema=audit.schema_version))}</footer>
</div>
<script>
(function() {{
  var root = document.documentElement;
  var toggle = document.getElementById("themeToggle");
  if (toggle) {{
    toggle.addEventListener("click", function() {{
      root.setAttribute("data-theme", root.getAttribute("data-theme") === "dark" ? "light" : "dark");
    }});
  }}
  var printBtn = document.getElementById("printReport");
  if (printBtn) {{
    printBtn.addEventListener("click", function() {{ window.print(); }});
  }}
  var activeSev = "all";
  var searchEl = document.getElementById("findingSearch");
  var cards = Array.prototype.slice.call(document.querySelectorAll(".finding-card"));
  function applyFilters() {{
    var q = (searchEl ? searchEl.value : "").trim().toLowerCase();
    cards.forEach(function(card) {{
      var sevOk = activeSev === "all" || card.getAttribute("data-severity") === activeSev;
      var qOk = !q || (card.getAttribute("data-search") || "").indexOf(q) !== -1;
      card.style.display = (sevOk && qOk) ? "" : "none";
    }});
  }}
  var pills = document.querySelectorAll("#sevFilters .pill");
  pills.forEach(function(btn) {{
    btn.addEventListener("click", function() {{
      pills.forEach(function(b) {{ b.classList.remove("active"); }});
      btn.classList.add("active");
      activeSev = btn.getAttribute("data-sev") || "all";
      applyFilters();
    }});
  }});
  if (searchEl) searchEl.addEventListener("input", applyFilters);
  var dexSearch = document.getElementById("dexSearch");
  var dexTable = document.getElementById("dexTable");
  if (dexSearch && dexTable) {{
    dexSearch.addEventListener("input", function() {{
      var q = dexSearch.value.trim().toLowerCase();
      Array.prototype.slice.call(dexTable.querySelectorAll("tbody tr")).forEach(function(tr) {{
        tr.style.display = !q || tr.textContent.toLowerCase().indexOf(q) !== -1 ? "" : "none";
      }});
    }});
  }}
}})();
</script>
</body>
</html>
"""


__all__ = ["render_html"]
