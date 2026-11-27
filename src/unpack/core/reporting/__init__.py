"""Modular quality evaluation and multi-format audit reporting package."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from unpack.core.reporting.audit import (
    AUDIT_SCHEMA_VERSION,
    SARIF_LEVEL_MAP,
    SARIF_SECURITY_SEVERITY,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    AuditFinding,
    AuditReport,
    build_audit_report,
    render_json,
)
from unpack.core.reporting.html import render_html
from unpack.core.reporting.markdown import render_markdown
from unpack.core.reporting.quality import (
    DEX_MAGIC,
    HEADER_SIZE,
    NOP_INSN,
    QualityReport,
    analyze_dex_file,
    evaluate_quality,
    scan_class_methods,
)
from unpack.core.reporting.sarif import render_sarif, render_sarif_json
from unpack.i18n import resolve_lang


class Reporter:
    """Facade combining DEX quality evaluation and commercial audit aggregation."""

    def evaluate(self, output_dir: Path, scan_result=None) -> QualityReport:
        return evaluate_quality(output_dir, scan_result=scan_result)

    def _analyze_dex(self, dex_path: Path) -> dict:
        return analyze_dex_file(dex_path)

    def _scan_class_methods(self, data: bytes, offset: int, stats: dict) -> None:
        scan_class_methods(data, offset, stats)

    def build_audit_report(
        self,
        target: str | Path,
        *,
        scan: Any = None,
        inspect: Any = None,
        quality: Any = None,
        verify_results: list[Any] | None = None,
        repair_results: list[Any] | None = None,
        vmp: Any = None,
        xref: Any = None,
        title: str | None = None,
        lang: str = "en",
    ) -> AuditReport:
        return build_audit_report(
            target,
            scan=scan,
            inspect=inspect,
            quality=quality,
            verify_results=verify_results,
            repair_results=repair_results,
            vmp=vmp,
            xref=xref,
            title=title,
            lang=lang,
        )


class ReportGenerator:
    """Unified multi-format report renderer (HTML, Markdown, SARIF 2.1.0, JSON)."""

    SUPPORTED_FORMATS = ("html", "markdown", "md", "sarif", "json")

    @classmethod
    def render(cls, audit: AuditReport, fmt: str, lang: str = "en") -> str:
        norm = fmt.strip().lower()
        eff_lang = resolve_lang(lang)
        if norm == "html":
            return render_html(audit, lang=eff_lang)
        if norm in ("markdown", "md"):
            return render_markdown(audit, lang=eff_lang)
        if norm == "sarif":
            return render_sarif_json(audit)
        if norm == "json":
            return render_json(audit)
        raise ValueError(
            f"Unsupported report format {fmt!r}. Supported: {', '.join(cls.SUPPORTED_FORMATS)}"
        )


__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "DEX_MAGIC",
    "HEADER_SIZE",
    "NOP_INSN",
    "SEVERITY_ORDER",
    "SEVERITY_WEIGHTS",
    "SARIF_LEVEL_MAP",
    "SARIF_SECURITY_SEVERITY",
    "QualityReport",
    "AuditFinding",
    "AuditReport",
    "Reporter",
    "ReportGenerator",
    "build_audit_report",
    "evaluate_quality",
    "render_html",
    "render_json",
    "render_markdown",
    "render_sarif",
    "render_sarif_json",
]
