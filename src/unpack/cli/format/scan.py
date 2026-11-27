"""Domain renderers for packer scan results and environment diagnostics."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console

from unpack.cli.format.components import render_header, render_kv_card, render_table
from unpack.cli.format.theme import (
    C_ACCENT,
    C_DIM,
    C_FAIL,
    C_INFO,
    C_LABEL,
    C_OK,
    C_WARN,
    confidence_bar,
    eff_lang,
    render_severity_badge,
    safe,
)
from unpack.i18n import t


def print_scan_result(
    console: Console,
    result: Any,
    apk_path: Path | None = None,
    *,
    lang: str | None = None,
) -> None:
    """Render primary packer detection summary card.

    Preserves status tokens ``DETECTED``, ``POSSIBLE``, and ``NO PACKER``
    in English mode for backward compatibility with scripts and tests.
    """
    eff = eff_lang(lang)
    if result.packer_name:
        level_val = getattr(result.protection_level, "value", str(result.protection_level))
        level_color = {
            "none": C_OK,
            "dex_encryption": C_WARN,
            "function_extraction": C_WARN,
            "vmp": C_FAIL,
            "dex2c": C_FAIL,
            "unknown": C_DIM,
        }.get(level_val, C_DIM)

        rows: list[tuple[str, str]] = []
        if apk_path:
            rows.append((t("fmt.target", eff), f"[path]{safe(apk_path.name)}[/]"))
        packer_display = f"[{C_ACCENT} bold]{safe(result.packer_name)}[/]"
        if getattr(result, "packer_version", None):
            packer_display += f"  [{C_INFO}]{safe(result.packer_version)}[/]"
        rows.append((t("fmt.packer", eff), packer_display))
        rows.append((t("fmt.protection", eff), f"[{level_color} bold]{safe(level_val)}[/]"))
        rows.append((t("fmt.confidence", eff), f"{confidence_bar(result.confidence)}  {result.confidence:.0%}"))

        if getattr(result, "risk_score", None) is not None:
            r_score = int(result.risk_score)
            r_color = C_FAIL if r_score >= 60 else C_WARN if r_score >= 30 else C_OK
            rows.append((t("fmt.risk_score", eff), f"[{r_color}]{r_score}/100[/]"))

        if result.matched_signatures:
            sigs = f" [{C_DIM}]·[/] ".join(
                f"[{C_INFO}]{safe(s)}[/]" for s in result.matched_signatures
            )
            rows.append((t("fmt.signatures", eff), sigs))

        rec_engine = getattr(result, "recommended_engine", None)
        rec_flags = getattr(result, "recommended_flags", None) or []
        if rec_engine:
            strat = f"[{C_OK}]{safe(rec_engine)}[/]"
            if rec_flags:
                strat += f" [{C_DIM}]({safe(' '.join(rec_flags))})[/]"
            rows.append((t("fmt.strategy", eff), strat))

        if result.confidence >= 0.2:
            title = t("fmt.detected", eff)
            border = C_OK
            title_style = f"bold {C_OK}"
        else:
            title = t("fmt.possible", eff)
            border = C_WARN
            title_style = f"bold {C_WARN}"

        render_kv_card(console, title, rows, border_style=border, title_style=title_style)
    else:
        rows = []
        if apk_path:
            rows.append((t("fmt.target", eff), f"[path]{safe(apk_path.name)}[/]"))
        status_txt = result.details or t("fmt.no_packer_default", eff)
        if eff == "zh" and status_txt == "No known packer detected":
            status_txt = t("fmt.no_packer_default", "zh")
        rows.append((t("fmt.status", eff), f"[{C_DIM}]{safe(status_txt)}[/]"))
        render_kv_card(console, t("fmt.no_packer", eff), rows, border_style=C_DIM, title_style=C_DIM)


def print_verbose(console: Console, result: Any, *, lang: str | None = None) -> None:
    """Render detailed scan breakdown: confidence weights, evidence, SOs, DEXs, candidates."""
    eff = eff_lang(lang)
    if result.score_breakdown:
        rows: list[list[str]] = []
        for b in result.score_breakdown:
            mx = float(b.get("max") or 0.0)
            sc = float(b.get("score") or 0.0)
            ratio = (sc / mx) if mx > 0 else 0.0
            hit = f"[{C_OK}]HIT[/]" if b.get("matched") else f"[{C_DIM}]—[/]"
            rows.append(
                [
                    hit,
                    safe(b.get("dimension", "")),
                    confidence_bar(ratio, width=10),
                    f"[{C_INFO}]{sc:.1f}[/][{C_DIM}]/{mx:.1f}[/]",
                ]
            )
        total = sum(float(b.get("score") or 0.0) for b in result.score_breakdown)
        total_max = sum(float(b.get("max") or 0.0) for b in result.score_breakdown)
        rows.append(
            [
                "",
                f"[{C_LABEL}]{safe(t('fmt.total', eff))}[/]",
                confidence_bar(total / total_max if total_max else 0.0, width=10),
                f"[{C_LABEL}]{total:.1f}[/][{C_DIM}]/{total_max:.1f}[/]",
            ]
        )
        render_table(
            console,
            [
                (t("fmt.col.hit", eff), {"width": 4}),
                (t("fmt.col.dimension", eff), {}),
                (t("fmt.col.weight", eff), {"width": 12}),
                (t("fmt.col.score", eff), {"justify": "right"}),
            ],
            rows,
            title=t("fmt.title.confidence", eff),
        )

    evidence = getattr(result, "evidence", None) or []
    if evidence:
        ev_rows: list[list[str]] = []
        for item in evidence[:20]:
            d = item.to_dict() if hasattr(item, "to_dict") else (item if isinstance(item, dict) else {})
            ev_rows.append(
                [
                    safe(d.get("dimension", "")),
                    f"[{C_INFO}]{safe(d.get('indicator') or d.get('matched_value') or '')}[/]",
                    f"{float(d.get('weight', 0)):.1f}",
                    safe(d.get("reason") or d.get("detail") or ""),
                ]
            )
        render_table(
            console,
            [
                (t("fmt.col.dimension", eff), {}),
                (t("fmt.col.indicator", eff), {}),
                (t("fmt.col.weight", eff), {"justify": "right"}),
                (t("fmt.col.detail", eff), {}),
            ],
            ev_rows,
            title=t("fmt.title.evidence", eff, count=len(evidence)),
        )

    if result.all_so_files:
        so_rows: list[list[str]] = []
        suspicious_kw = (
            "secure", "protect", "shield", "safe", "guard", "crypt",
            "hook", "jiagu", "shell", "sec", "vmp", "dex",
        )
        for so in result.all_so_files[:30]:
            name = so.rsplit("/", 1)[-1]
            is_susp = any(k in name.lower() for k in suspicious_kw)
            badge = f"[{C_WARN}]SUSPECT[/]" if is_susp else f"[{C_DIM}]lib[/]"
            style = C_WARN if is_susp else C_DIM
            so_rows.append([badge, f"[{style}]{safe(so)}[/]"])
        caption = (
            t("fmt.showing_n_of", eff, shown=30, total=len(result.all_so_files))
            if len(result.all_so_files) > 30
            else None
        )
        render_table(
            console,
            [(t("fmt.col.flag", eff), {"width": 9}), (t("fmt.col.library_path", eff), {})],
            so_rows,
            title=t("fmt.title.native_libs", eff, count=len(result.all_so_files)),
            caption=caption,
        )

    if result.all_dex_info:
        dex_rows: list[list[str]] = []
        for d in result.all_dex_info:
            size_kb = float(d.get("size_kb") or 0.0)
            classes = int(d.get("classes") or 0)
            tiny = size_kb < 50 and classes < 10
            flag = f"[{C_WARN}]STUB?[/]" if tiny else f"[{C_DIM}]ok[/]"
            dex_rows.append(
                [
                    safe(d.get("name", "")),
                    f"{size_kb:.0f} KB",
                    f"{classes:,}",
                    flag,
                ]
            )
        render_table(
            console,
            [
                (t("fmt.col.dex", eff), {}),
                (t("fmt.col.size", eff), {"justify": "right"}),
                (t("fmt.col.classes", eff), {"justify": "right"}),
                (t("fmt.col.note", eff), {"width": 8}),
            ],
            dex_rows,
            title=t("fmt.title.dex_files", eff, count=len(result.all_dex_info)),
        )

    if result.suspicious_assets:
        asset_rows = [[f"[{C_WARN}]▸[/]", f"[{C_WARN}]{safe(a)}[/]"] for a in result.suspicious_assets[:20]]
        render_table(
            console,
            [("", {"width": 2}), (t("fmt.col.asset_path", eff), {})],
            asset_rows,
            title=t("fmt.title.suspicious_assets", eff, count=len(result.suspicious_assets)),
        )

    if result.app_class:
        console.print(f"  [{C_LABEL}]{safe(t('fmt.app_class', eff))}[/] [{C_INFO}]{safe(result.app_class)}[/]")

    anomalies = getattr(result, "heuristic_anomalies", None) or []
    if anomalies:
        for a in anomalies:
            console.print(f"  [{C_WARN}]![/] {safe(a)}")

    if result.all_candidates and len(result.all_candidates) > 1:
        cand_rows = [
            [
                safe(c.get("name", "")),
                f"{float(c.get('score', 0)):.1f}",
                safe(", ".join(c.get("signatures") or [])),
            ]
            for c in result.all_candidates
        ]
        render_table(
            console,
            [
                (t("fmt.col.candidate", eff), {}),
                (t("fmt.col.score", eff), {"justify": "right"}),
                (t("fmt.col.signatures", eff), {}),
            ],
            cand_rows,
            title=t("fmt.title.all_candidates", eff),
        )


def print_doctor_report(
    console: Console,
    report: dict[str, Any],
    *,
    lang: str | None = None,
) -> None:
    """Render environment & device diagnostics."""
    eff = eff_lang(lang)
    overall = str(report.get("overall_status") or "ok")
    render_header(
        console,
        t("fmt.title.doctor", eff),
        subtitle=f"v{report.get('unpack_version', '?')} · Python {report.get('python_version', '?')}",
        meta=t("fmt.doctor.status_meta", eff, status=overall.upper()),
    )

    checks = report.get("checks") or []
    if checks:
        rows: list[list[str]] = []
        hints: list[str] = []
        for chk in checks:
            st = str(chk.get("status") or "info").lower()
            rows.append(
                [
                    render_severity_badge(st),
                    safe(chk.get("category", "")),
                    safe(chk.get("name", "")),
                    safe(chk.get("version") or "—"),
                    safe(chk.get("summary") or chk.get("message") or ""),
                ]
            )
            rem = chk.get("remediation") or chk.get("hint")
            if rem and st in ("warn", "fail") and rem not in hints:
                hints.append(str(rem))
        render_table(
            console,
            [
                (t("fmt.col.status", eff), {"width": 6}),
                (t("fmt.col.category", eff), {}),
                (t("fmt.col.check", eff), {}),
                (t("fmt.col.version", eff), {}),
                (t("fmt.col.details", eff), {}),
            ],
            rows,
            title=t("fmt.title.env_checks", eff),
        )
        if hints:
            console.print(f"\n[{C_LABEL}]{safe(t('fmt.title.remediation', eff))}[/]")
            for h in hints:
                console.print(f"  [{C_INFO}]▸[/] {safe(h)}")

    devices = report.get("devices") or []
    if devices:
        yes_str = t("fmt.yes", eff)
        no_str = t("fmt.no", eff)
        ready_str = t("fmt.ready", eff)
        dev_rows = [
            [
                safe(d.get("serial", "")),
                safe(d.get("model") or "—"),
                safe(d.get("android_version") or d.get("api_level") or "—"),
                f"[{C_OK}]{safe(yes_str)}[/]" if d.get("rooted") or d.get("root") else f"[{C_DIM}]{safe(no_str)}[/]",
                f"[{C_OK}]{safe(ready_str)}[/]" if (d.get("frida_server_running") or d.get("frida_server")) else f"[{C_DIM}]—[/]",
            ]
            for d in devices
        ]
        render_table(
            console,
            [
                (t("fmt.col.serial", eff), {}),
                (t("fmt.col.model", eff), {}),
                (t("fmt.col.android", eff), {}),
                (t("fmt.col.root", eff), {"width": 6}),
                (t("fmt.col.frida", eff), {"width": 7}),
            ],
            dev_rows,
            title=t("fmt.title.adb_devices", eff, count=len(devices)),
        )
    else:
        console.print(f"\n  [{C_DIM}]{safe(t('fmt.doctor.no_devices', eff))}[/]")

    engines = report.get("engines") or []
    if engines:
        eng_ready = t("fmt.engine_ready", eff)
        eng_unavail = t("fmt.engine_unavail", eff)
        eng_rows = [
            [
                f"[{C_LABEL}]{safe(e.get('name', ''))}[/]",
                f"[{C_OK}]{safe(eng_ready)}[/]" if e.get("available") else f"[{C_WARN}]{safe(eng_unavail)}[/]",
                safe(e.get("reason") or t("fmt.ready", eff)),
            ]
            for e in engines
        ]
        render_table(
            console,
            [
                (t("fmt.col.engine", eff), {"width": 10}),
                (t("fmt.col.state", eff), {"width": 13}),
                (t("fmt.col.notes", eff), {}),
            ],
            eng_rows,
            title=t("fmt.title.engines", eff),
        )
