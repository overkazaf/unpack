"""Bilingual commercial audit report generation service."""

from __future__ import annotations

from typing import Any

from unpack.studio.schemas import normalize_lang

MIME_MAP: dict[str, tuple[str, str]] = {
    "html": ("text/html; charset=utf-8", "html"),
    "markdown": ("text/markdown; charset=utf-8", "md"),
    "json": ("application/json; charset=utf-8", "json"),
    "sarif": ("application/sarif+json; charset=utf-8", "sarif.json"),
}


def render_commercial_report(
    *,
    sample: dict[str, Any],
    fmt: str,
    title: str | None = None,
    lang: str = "en",
) -> tuple[str, str, str]:
    """Render a bilingual audit report via ``unpack.core.reporter``.

    Returns ``(content_str, mimetype, filename_ext)``.
    """
    from unpack.core.reporter import ReportGenerator, Reporter

    norm_fmt = fmt.lower().strip()
    if norm_fmt == "md":
        norm_fmt = "markdown"
    if norm_fmt not in MIME_MAP:
        raise ValueError(f"Unsupported report format: {fmt!r}")

    norm_lang = normalize_lang(lang)
    is_zh = norm_lang == "zh"
    default_title = (
        f"UNPACK 安全审计报告 — {sample['name']}"
        if is_zh
        else f"UNPACK Security Audit — {sample['name']}"
    )
    report_title = title or default_title

    audit = Reporter().build_audit_report(
        target=sample["name"],
        scan=sample.get("scan_result"),
        inspect=sample.get("inspect_result"),
        quality=sample.get("quality_report"),
        verify_results=sample.get("verify_results"),
        repair_results=sample.get("repair_diffs"),
        vmp=sample.get("vmp_result"),
        xref=sample.get("xref_result"),
        title=report_title,
        lang=norm_lang,
    )
    content = ReportGenerator.render(audit, norm_fmt, lang=norm_lang)
    mime, ext = MIME_MAP[norm_fmt]
    return content, mime, ext
