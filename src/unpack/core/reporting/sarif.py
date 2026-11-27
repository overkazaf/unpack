"""OASIS SARIF 2.1.0 report renderer."""

from __future__ import annotations

import json
from typing import Any

from unpack.core.reporting.audit import (
    SARIF_LEVEL_MAP,
    SARIF_SECURITY_SEVERITY,
    AuditReport,
)


def render_sarif(audit: AuditReport) -> dict[str, Any]:
    """Render an ``AuditReport`` as an OASIS SARIF 2.1.0 dictionary."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in audit.findings:
        sev = finding.severity.lower()
        level = SARIF_LEVEL_MAP.get(sev, "note")
        sec_sev = SARIF_SECURITY_SEVERITY.get(sev, "1.0")

        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id.replace("-", "_"),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "defaultConfiguration": {"level": level},
                "help": {
                    "text": finding.remediation or finding.description or finding.title,
                },
                "properties": {
                    "tags": ["security", "android", finding.category],
                    "security-severity": sec_sev,
                },
            }

        result_entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": level,
            "message": {
                "text": (
                    f"{finding.title}: {finding.description}"
                    if finding.description
                    else finding.title
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location or audit.target,
                        }
                    }
                }
            ],
            "properties": {
                "findingId": finding.id,
                "severity": sev,
                "category": finding.category,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            },
        }
        results.append(result_entry)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "UNPACK",
                        "version": audit.tool_version,
                        "informationUri": "https://github.com/overkazaf/unpack",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": audit.generated_at,
                    }
                ],
                "results": results,
                "properties": {
                    "target": audit.target,
                    "targetSha256": audit.target_sha256,
                    "grade": audit.grade,
                    "riskScore": audit.risk_score,
                },
            }
        ],
    }


def render_sarif_json(audit: AuditReport) -> str:
    """Render an ``AuditReport`` as a formatted SARIF 2.1.0 JSON string."""
    return json.dumps(render_sarif(audit), indent=2, ensure_ascii=False)


__all__ = ["render_sarif", "render_sarif_json"]
