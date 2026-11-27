"""Quality evaluation and commercial audit report generation for UNPACK.

Backward-compatible facade re-exporting all symbols from
``unpack.core.reporting``. Intentionally free of Rich/TTY dependencies so it
can be used equally from the CLI, UNPACK Studio, and CI/CD pipelines.
"""

from __future__ import annotations

from unpack.core.reporting import (
    AUDIT_SCHEMA_VERSION,
    DEX_MAGIC,
    HEADER_SIZE,
    NOP_INSN,
    SARIF_LEVEL_MAP,
    SARIF_SECURITY_SEVERITY,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    AuditFinding,
    AuditReport,
    QualityReport,
    ReportGenerator,
    Reporter,
    build_audit_report,
    evaluate_quality,
    render_html,
    render_json,
    render_markdown,
    render_sarif,
    render_sarif_json,
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
