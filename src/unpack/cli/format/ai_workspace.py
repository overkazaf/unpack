"""Domain renderers for AI model configuration, analysis, and persistent workspaces."""

from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from unpack.cli.format.components import render_error, render_kv_card, render_table
from unpack.cli.format.theme import (
    C_ACCENT,
    C_DIM,
    C_INFO,
    C_LABEL,
    C_OK,
    C_WARN,
    eff_lang,
    format_bytes,
    render_severity_badge,
    safe,
)
from unpack.i18n import t


def print_ai_config(
    console: Console,
    config_pub: dict[str, Any],
    presets: list[dict[str, Any]] | None = None,
    *,
    lang: str | None = None,
) -> None:
    """Render public AI provider configuration (never displays raw API keys) and presets."""
    eff = eff_lang(lang)
    enabled = bool(config_pub.get("enabled", True))
    configured = bool(config_pub.get("configured", False))
    if not enabled:
        status_str = f"[{C_DIM}]{safe(t('ai.state.disabled', eff))}[/]"
        border = C_DIM
    elif configured:
        status_str = f"[{C_OK} bold]{safe(t('ai.state.ready', eff))}[/]"
        border = C_OK
    else:
        status_str = f"[{C_WARN} bold]{safe(t('ai.state.unconfigured', eff))}[/]"
        border = C_WARN

    if config_pub.get("has_api_key"):
        key_str = f"[{C_OK}]{safe(t('ai.key.set', eff, masked=config_pub.get('api_key_masked') or '***'))}[/]"
    elif not config_pub.get("requires_api_key"):
        key_str = f"[{C_DIM}]{safe(t('ai.key.not_required', eff))}[/]"
    else:
        key_str = f"[{C_WARN}]{safe(t('ai.key.missing', eff))}[/]"

    params_str = (
        f"temp={config_pub.get('temperature', 0.2)} · "
        f"max_tokens={config_pub.get('max_tokens', 2048)} · "
        f"timeout={config_pub.get('timeout_seconds', 60)}s"
    )
    rows: list[tuple[str, str]] = [
        (t("ai.kv.status", eff), status_str),
        (t("ai.kv.provider", eff), f"[{C_INFO} bold]{safe(config_pub.get('provider') or '—')}[/] [{C_DIM}]({safe(config_pub.get('protocol') or 'openai')})[/]"),
        (t("ai.kv.model", eff), f"[{C_ACCENT}]{safe(config_pub.get('model') or '—')}[/]"),
        (t("ai.kv.base_url", eff), f"[path]{safe(config_pub.get('base_url') or '—')}[/]"),
        (t("ai.kv.api_key", eff), key_str),
        (t("ai.kv.params", eff), f"[{C_DIM}]{safe(params_str)}[/]"),
    ]
    render_kv_card(
        console,
        t("ai.title.config", eff),
        rows,
        border_style=border,
        title_style=f"bold {border if border != C_DIM else C_INFO}",
    )

    if presets:
        yes_s = t("fmt.yes", eff)
        no_s = t("fmt.no", eff)
        p_rows = []
        active_id = str(config_pub.get("provider") or "").lower()
        for p in presets:
            pid = str(p.get("id") or "")
            marker = f"[{C_OK}]●[/] " if pid == active_id else "  "
            label = p.get("label_zh") if eff == "zh" and p.get("label_zh") else p.get("label", pid)
            req = f"[{C_WARN}]{safe(yes_s)}[/]" if p.get("requires_api_key") else f"[{C_OK}]{safe(no_s)}[/]"
            p_rows.append(
                [
                    f"{marker}[{C_LABEL}]{safe(pid)}[/]",
                    safe(label),
                    f"[{C_INFO}]{safe(p.get('default_model') or '—')}[/]",
                    req,
                    f"[{C_DIM}]{safe(p.get('base_url') or '—')}[/]",
                ]
            )
        render_table(
            console,
            [
                (t("ai.col.id", eff), {}),
                (t("ai.col.name", eff), {}),
                (t("ai.col.default_model", eff), {}),
                (t("ai.col.key_req", eff), {"width": 10}),
                (t("ai.col.base_url", eff), {}),
            ],
            p_rows,
            title=t("ai.title.presets", eff),
        )


def print_ai_test_result(
    console: Console,
    result: dict[str, Any],
    *,
    lang: str | None = None,
) -> None:
    """Render AI connectivity test result card or actionable error."""
    eff = eff_lang(lang)
    if result.get("ok"):
        rows = [
            (t("ai.kv.status", eff), f"[{C_OK} bold]✓ {safe(t('ai.test.ok', eff))}[/]"),
            (t("ai.kv.provider", eff), f"[{C_INFO}]{safe(result.get('provider') or '—')}[/]"),
            (t("ai.kv.model", eff), f"[{C_ACCENT}]{safe(result.get('model') or '—')}[/]"),
            (t("ai.kv.latency", eff), f"{int(result.get('latency_ms') or 0)} ms"),
            (t("ai.kv.reply", eff), safe(result.get("reply_preview") or "")),
        ]
        render_kv_card(console, t("ai.title.test", eff), rows, border_style=C_OK, title_style=f"bold {C_OK}")
    else:
        render_error(
            console,
            f"{t('ai.test.fail', eff)} ({result.get('provider') or '?'}/{result.get('model') or '?'})",
            detail=result.get("error") or None,
            hint=result.get("hint") or t("ai.config_hint", eff),
            lang=eff,
        )


def print_ai_analysis(
    console: Console,
    result_dict: dict[str, Any],
    *,
    saved_workspace: str | None = None,
    lang: str | None = None,
) -> None:
    """Render AI reverse-engineering analysis metadata card and Rich Markdown panel."""
    eff = eff_lang(lang)
    usage = result_dict.get("usage") or {}
    usage_parts = [f"{k}={v}" for k, v in usage.items() if v is not None]
    rows: list[tuple[str, str]] = [
        (t("ai.kv.module", eff), f"[{C_INFO}]{safe(result_dict.get('module') or '')}[/]"),
        (
            t("ai.kv.provider", eff),
            f"[{C_LABEL}]{safe(result_dict.get('provider') or '')}[/] · [{C_ACCENT}]{safe(result_dict.get('model') or '')}[/]",
        ),
        (t("ai.kv.latency", eff), f"{int(result_dict.get('latency_ms') or 0)} ms"),
    ]
    if usage_parts:
        rows.append((t("ai.kv.usage", eff), f"[{C_DIM}]{safe(', '.join(usage_parts))}[/]"))
    if saved_workspace:
        rows.append((t("ai.kv.saved_ws", eff), f"[{C_OK}]{safe(saved_workspace)}[/]"))

    render_kv_card(
        console,
        result_dict.get("title") or t("ai.title.analysis", eff),
        rows,
        border_style=C_INFO,
        title_style=f"bold {C_INFO}",
    )

    md_body = str(result_dict.get("markdown") or "").strip()
    if md_body:
        console.print(
            Panel(
                Markdown(md_body),
                border_style=C_DIM,
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )


def print_workspace_list(
    console: Console,
    workspaces: list[dict[str, Any]],
    *,
    lang: str | None = None,
) -> None:
    """Render tabular list of persistent UNPACK Studio workspaces."""
    eff = eff_lang(lang)
    rows: list[list[str]] = []
    for ws in workspaces:
        pin = f"[{C_WARN}]★[/] " if ws.get("pinned") else ""
        tags = ", ".join(ws.get("tags") or []) or "—"
        updated = str(ws.get("updated_at") or "")[:19].replace("T", " ")
        rows.append(
            [
                f"[{C_INFO}]{safe(ws.get('id', ''))}[/]",
                f"{pin}[{C_LABEL}]{safe(ws.get('name', ''))}[/]",
                f"{int(ws.get('sample_count', 0)):,}",
                f"{int(ws.get('pipeline_run_count', 0)):,}",
                f"{int(ws.get('ai_analysis_count', 0)):,}",
                f"[{C_DIM}]{safe(tags)}[/]",
                f"[{C_DIM}]{safe(updated)}[/]",
            ]
        )
    render_table(
        console,
        [
            (t("ws.col.id", eff), {}),
            (t("ws.col.name", eff), {}),
            (t("ws.col.samples", eff), {"justify": "right"}),
            (t("ws.col.runs", eff), {"justify": "right"}),
            (t("ws.col.ai", eff), {"justify": "right"}),
            (t("ws.col.tags", eff), {}),
            (t("ws.col.updated", eff), {}),
        ],
        rows,
        title=t("ws.title.list", eff, count=len(workspaces)),
    )


def print_workspace_detail(
    console: Console,
    ws: dict[str, Any],
    samples: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    analyses: list[dict[str, Any]],
    *,
    lang: str | None = None,
) -> None:
    """Render detailed review of a saved workspace: metadata, samples, runs, and AI analyses."""
    eff = eff_lang(lang)
    tags = ", ".join(ws.get("tags") or []) or "—"
    updated = str(ws.get("updated_at") or "")[:19].replace("T", " ")
    render_kv_card(
        console,
        t("ws.title.detail", eff),
        [
            (t("ws.kv.id", eff), f"[{C_INFO}]{safe(ws.get('id', ''))}[/]"),
            (t("ws.kv.name", eff), f"[{C_LABEL}]{safe(ws.get('name', ''))}[/]"),
            (t("ws.kv.desc", eff), safe(ws.get("description") or "—")),
            (t("ws.kv.tags", eff), f"[{C_DIM}]{safe(tags)}[/]"),
            (
                t("ws.kv.counts", eff),
                t(
                    "ws.counts_val",
                    eff,
                    samples=len(samples),
                    runs=len(runs),
                    ai=len(analyses),
                ),
            ),
            (t("ws.kv.updated", eff), f"[{C_DIM}]{safe(updated)}[/]"),
        ],
        border_style=C_INFO,
        title_style=f"bold {C_INFO}",
    )

    if samples:
        s_rows = []
        for s in samples[:30]:
            scan = s.get("scan_result") or {}
            packer = scan.get("packer_name") or "—"
            s_rows.append(
                [
                    f"[{C_INFO}]{safe(s.get('sample_id', ''))}[/]",
                    f"[path]{safe(s.get('filename', ''))}[/]",
                    safe(s.get("kind") or "apk"),
                    format_bytes(s.get("size_bytes")),
                    safe(packer),
                    f"{len(s.get('ai_analyses') or [])}",
                ]
            )
        render_table(
            console,
            [
                (t("ws.col.sample_id", eff), {}),
                (t("ws.col.file", eff), {}),
                (t("ws.col.kind", eff), {"width": 6}),
                (t("ws.col.size", eff), {"justify": "right"}),
                (t("ws.col.packer", eff), {}),
                (t("ws.col.ai", eff), {"justify": "right"}),
            ],
            s_rows,
            title=t("ws.title.samples", eff, count=len(samples)),
        )
    else:
        console.print(f"  [{C_DIM}]{safe(t('ws.empty_samples', eff))}[/]")

    if runs:
        r_rows = [
            [
                f"[{C_INFO}]{safe(r.get('id', ''))}[/]",
                safe(r.get("stage") or r.get("name") or "pipeline"),
                render_severity_badge("pass" if r.get("status") in ("completed", "done", "ok") else "fail" if r.get("status") == "failed" else "info"),
                safe(r.get("summary") or r.get("error") or "—"),
            ]
            for r in runs[:20]
        ]
        render_table(
            console,
            [
                (t("ws.col.run_id", eff), {}),
                (t("ws.col.stage", eff), {}),
                (t("ws.col.status", eff), {"width": 7}),
                (t("ws.col.summary", eff), {}),
            ],
            r_rows,
            title=t("ws.title.runs", eff, count=len(runs)),
        )

    if analyses:
        a_rows = [
            [
                f"[{C_INFO}]{safe(a.get('module', ''))}[/]",
                f"[{C_ACCENT}]{safe(a.get('model') or a.get('provider') or '—')}[/]",
                safe(a.get("title") or a.get("summary") or "—"),
                f"[{C_DIM}]{safe(str(a.get('created_at') or '')[:19].replace('T', ' '))}[/]",
            ]
            for a in analyses[:20]
        ]
        render_table(
            console,
            [
                (t("ws.col.module", eff), {"width": 12}),
                (t("ws.col.model", eff), {}),
                (t("ws.col.title", eff), {}),
                (t("ws.col.updated", eff), {}),
            ],
            a_rows,
            title=t("ws.title.analyses", eff, count=len(analyses)),
        )
