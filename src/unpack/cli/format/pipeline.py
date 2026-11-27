"""Domain renderer for the visual Pipeline Execution Blueprint."""

from __future__ import annotations

from typing import Any

from rich.console import Console

from unpack.cli.format.components import (
    render_header,
    render_kv_card,
    render_next_steps,
    render_table,
)
from unpack.cli.format.theme import (
    C_ACCENT,
    C_DIM,
    C_FAIL,
    C_INFO,
    C_LABEL,
    C_OK,
    C_WARN,
    eff_lang,
    safe,
)
from unpack.i18n import t


def render_pipeline_blueprint(
    console: Console,
    plan: dict[str, Any],
    *,
    lang: str | None = None,
) -> None:
    """Render a rich visual Pipeline Execution Blueprint with live preflight & remediation."""
    eff = eff_lang(lang)
    console.print()
    render_header(
        console,
        t("pipe.title", eff),
        subtitle=t("pipe.subtitle", eff),
        meta=plan.get("mode_label") or plan.get("mode") or "",
    )

    # 1. Strategy Summary Card
    packer_name = plan.get("packer_name") or t("fmt.no_packer", eff)
    if plan.get("packer_version"):
        packer_name = f"{packer_name} ({plan['packer_version']})"
    conf = plan.get("confidence")
    if plan.get("packer_name") and conf is not None:
        packer_display = f"[{C_ACCENT} bold]{safe(packer_name)}[/]  [{C_DIM}]({float(conf):.0%})[/]"
    else:
        packer_display = f"[{C_DIM}]{safe(packer_name)}[/]"

    prot = str(plan.get("protection_level") or "none")
    rec_flags = " ".join(plan.get("recommended_flags") or []) or "—"
    ready_ok = bool(plan.get("can_execute"))
    ready_txt = (
        f"[{C_OK} bold]{safe(t('pipe.state.ready', eff))}[/]"
        if ready_ok
        else f"[{C_WARN} bold]{safe(t('pipe.state.blocked', eff))}[/]"
    )

    summary_rows: list[tuple[str, str]] = [
        (t("pipe.kv.target", eff), f"[path]{safe(plan.get('target', ''))}[/]"),
        (t("pipe.kv.mode", eff), f"[{C_INFO}]{safe(plan.get('mode_label', ''))}[/]"),
        (t("pipe.kv.packer", eff), packer_display),
        (t("pipe.kv.protection", eff), f"[{C_WARN if prot in ('vmp', 'dex2c', 'function_extraction') else C_INFO}]{safe(prot)}[/]"),
        (t("pipe.kv.rec_engine", eff), f"[{C_OK}]{safe(plan.get('recommended_engine') or 'offline')}[/]"),
        (t("pipe.kv.rec_flags", eff), f"[{C_INFO}]{safe(rec_flags)}[/]"),
        (t("pipe.kv.why", eff), safe(plan.get("strategy_reason") or "")),
        (t("pipe.kv.readiness", eff), ready_txt),
    ]
    render_kv_card(
        console,
        t("pipe.card.summary", eff),
        summary_rows,
        border_style=C_OK if ready_ok else C_WARN,
        title_style=f"bold {C_OK if ready_ok else C_WARN}",
    )

    # 2. Live Preflight Checks Table
    preflight = plan.get("preflight_checks") or []
    blocked_items: list[dict[str, Any]] = []
    if preflight:
        pf_rows: list[list[str]] = []
        for item in preflight:
            st = str(item.get("status") or "pass").lower()
            if st == "block":
                badge = f"[{C_FAIL} bold]{safe(t('pipe.state.blocked', eff))}[/]"
                blocked_items.append(item)
            elif st == "warn":
                badge = f"[{C_WARN} bold]{safe(t('pipe.state.warn', eff))}[/]"
            else:
                badge = f"[{C_OK} bold]{safe(t('pipe.state.ready', eff))}[/]"
            pf_rows.append(
                [
                    badge,
                    f"[{C_LABEL}]{safe(item.get('name', ''))}[/]",
                    safe(item.get("detail", "")),
                    f"[{C_DIM}]{safe(item.get('remediation') or '—')}[/]",
                ]
            )
        render_table(
            console,
            [
                (t("pipe.preflight.col.status", eff), {"width": 9}),
                (t("pipe.preflight.col.check", eff), {}),
                (t("pipe.preflight.col.detail", eff), {}),
                (t("pipe.preflight.col.fix", eff), {}),
            ],
            pf_rows,
            title=t("pipe.preflight.title", eff),
        )

    # 3. Stage-by-Stage Execution Blueprint Table
    stages = plan.get("stages") or []
    active_cnt = sum(1 for s in stages if s.get("will_run"))
    if stages:
        st_rows: list[list[str]] = []
        for s in stages:
            rd = str(s.get("readiness") or "ready").lower()
            if not s.get("will_run") or rd == "skipped":
                rd_badge = f"[{C_DIM}]{safe(t('pipe.state.skipped', eff))}[/]"
            elif rd == "blocked":
                rd_badge = f"[{C_FAIL} bold]{safe(t('pipe.state.blocked', eff))}[/]"
            elif rd == "warn":
                rd_badge = f"[{C_WARN} bold]{safe(t('pipe.state.warn', eff))}[/]"
            else:
                rd_badge = f"[{C_OK} bold]{safe(t('pipe.state.ready', eff))}[/]"

            purpose = str(s.get("what_it_does") or "")
            if s.get("skip_reason"):
                purpose = f"{purpose} [{s['skip_reason']}]"
            io_str = f"{s.get('inputs', '—')} → {s.get('outputs', '—')}"
            st_rows.append(
                [
                    str(s.get("order", "")),
                    f"[{C_LABEL}]{safe(s.get('title', ''))}[/]",
                    rd_badge,
                    safe(purpose),
                    f"[{C_INFO}]{safe(io_str)}[/]",
                    f"[{C_DIM}]{safe(s.get('prerequisites', ''))}[/]",
                ]
            )
        render_table(
            console,
            [
                (t("pipe.col.step", eff), {"width": 3, "justify": "right"}),
                (t("pipe.col.stage", eff), {}),
                (t("pipe.col.state", eff), {"width": 9}),
                (t("pipe.col.purpose", eff), {}),
                (t("pipe.col.io", eff), {}),
                (t("pipe.col.prereq", eff), {}),
            ],
            st_rows,
            title=t("pipe.stages.title", eff, active=active_cnt, total=len(stages)),
        )

    # 4. Remediation Callout if blocked
    if blocked_items:
        console.print(f"\n[{C_WARN} bold]⚠ {safe(t('pipe.remediation.header', eff))}[/]")
        for b in blocked_items:
            if b.get("remediation"):
                console.print(f"  [{C_WARN}]▸[/] [{C_LABEL}]{safe(b.get('name', ''))}:[/] {safe(b['remediation'])}")
        if plan.get("offline_alternative_cmd"):
            console.print(f"\n  [{C_INFO}]{safe(t('pipe.remediation.offline_tip', eff))}[/]")
            console.print(f"    [{C_INFO}]$[/] [cmd]{safe(plan['offline_alternative_cmd'])}[/]")

    # 5. Copyable commands
    cmd_steps: list[tuple[str, str]] = []
    if plan.get("recommended_cmd"):
        cmd_steps.append((plan["recommended_cmd"], t("pipe.cmd.recommended", eff)))
    if plan.get("offline_alternative_cmd") and plan.get("offline_alternative_cmd") != plan.get("recommended_cmd"):
        cmd_steps.append((plan["offline_alternative_cmd"], t("pipe.cmd.offline_alt", eff)))
    if cmd_steps:
        render_next_steps(console, cmd_steps, lang=eff)
