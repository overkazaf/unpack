from __future__ import annotations

import json

import pytest

from unpack.core.reporter import (
    AuditFinding,
    AuditReport,
    QualityReport,
    ReportGenerator,
    Reporter,
    render_html,
    render_json,
    render_markdown,
    render_sarif,
    render_sarif_json,
)
from unpack.core.scanner import ProtectionLevel, ScanResult


class TestBuildAuditReport:
    def test_accepts_dataclasses_and_synthesizes_findings(self):
        scan = ScanResult(
            packer_name="网易易盾",
            packer_version="v2",
            confidence=0.82,
            protection_level=ProtectionLevel.FUNCTION_EXTRACTION,
            matched_signatures=["so:libnesec.so"],
            score_breakdown=[
                {"dimension": "SO Files", "score": 3.0, "max": 3.0, "matched": True},
            ],
        )
        quality = QualityReport(
            dex_count=2,
            total_classes=120,
            total_methods=500,
            methods_with_code=350,
            nop_methods=120,
            empty_methods=150,
            code_coverage=0.7,
            score=0.532,
            per_dex=[
                {"file": "classes.dex", "file_size": 100_000, "classes": 100, "methods": 400, "methods_with_code": 300, "nop_methods": 120},
                {"file": "classes2.dex", "file_size": 20_000, "classes": 20, "methods": 100, "methods_with_code": 50, "nop_methods": 0},
            ],
        )
        verify_results = [
            {"file": "classes.dex", "valid": True, "issues": [], "stats": {}},
            {"file": "classes2.dex", "valid": False, "issues": ["checksum mismatch"], "stats": {}},
        ]
        vmp = {
            "total_methods": 500,
            "normal_count": 370,
            "nop_count": 120,
            "vmp_count": 10,
            "vmp_methods": [{"class": "Lcom/foo/Bar;", "method": "secret"}],
            "call_graph": [],
        }
        xref = {
            "string_refs": {"https://api.example.com": []},
            "method_calls": {},
            "field_refs": {},
            "reflection_calls": [
                {"caller": {"class": "Lcom/foo/Bar;", "method": "load"}, "target": "Ljava/lang/Class;->forName"}
            ],
        }

        audit = Reporter().build_audit_report(
            "demo.apk",
            scan=scan,
            quality=quality,
            verify_results=verify_results,
            vmp=vmp,
            xref=xref,
        )

        assert isinstance(audit, AuditReport)
        assert audit.target == "demo.apk"
        assert audit.risk_score > 0
        assert audit.grade in ("A", "B", "C", "D", "F")
        rule_ids = {f.rule_id for f in audit.findings}
        assert "UNPACK-PACKER-002" in rule_ids
        assert "UNPACK-DEX-001" in rule_ids
        assert "UNPACK-DEX-002" in rule_ids
        assert "UNPACK-VERIFY-001" in rule_ids
        assert "UNPACK-VMP-001" in rule_ids
        assert "UNPACK-XREF-001" in rule_ids
        assert len(audit.recommendations) >= 3

    def test_accepts_plain_dicts_like_web_job_payloads(self):
        inspect_dict = {
            "file": "app.apk",
            "sha256": "deadbeef" * 8,
            "manifest": {
                "package_name": "com.test.app",
                "debuggable": True,
                "allow_backup": True,
                "uses_cleartext_traffic": True,
            },
            "signing": {"schemes": ["v1"], "is_debug_cert": True, "subject": "CN=Android Debug"},
            "findings": [
                {
                    "rule_id": "CUSTOM-001",
                    "severity": "critical",
                    "category": "apk_security",
                    "title": "Hardcoded private key",
                    "description": "Private key bundled in assets.",
                    "evidence": ["assets/key.pem"],
                    "remediation": "Remove embedded private key.",
                }
            ],
            "risk_score": 82,
        }
        audit = Reporter().build_audit_report("app.apk", inspect=inspect_dict)
        assert audit.target_sha256 == "deadbeef" * 8
        assert audit.risk_score >= 82
        assert audit.grade == "F"
        rule_ids = {f.rule_id for f in audit.findings}
        assert {"CUSTOM-001", "UNPACK-APK-001", "UNPACK-APK-002", "UNPACK-APK-003", "UNPACK-APK-005"} <= rule_ids

    def test_clean_target_gets_grade_a(self):
        audit = Reporter().build_audit_report("clean.apk")
        assert audit.risk_score == 0
        assert audit.grade == "A"
        assert audit.findings == []
        assert audit.recommendations


class TestRenderers:
    def _sample_audit(self) -> AuditReport:
        return Reporter().build_audit_report(
            "sample<script>alert(1)</script>.apk",
            scan={
                "packer_name": "360加固保",
                "packer_version": "v3",
                "confidence": 0.9,
                "protection_level": "vmp",
                "matched_signatures": ["so:libjiagu.so", "<img src=x onerror=alert(1)>"],
                "score_breakdown": [{"dimension": "SO Files", "score": 3.0, "max": 3.0, "matched": True}],
            },
            quality={
                "dex_count": 1,
                "total_classes": 10,
                "total_methods": 50,
                "methods_with_code": 45,
                "nop_methods": 5,
                "empty_methods": 5,
                "code_coverage": 0.9,
                "score": 0.81,
                "per_dex": [
                    {"file": "classes.dex", "file_size": 4096, "classes": 10, "methods": 50, "methods_with_code": 45, "nop_methods": 5}
                ],
            },
        )

    def test_render_html_offline_self_contained_and_xss_safe(self):
        audit = self._sample_audit()
        out = render_html(audit)
        assert out.startswith("<!DOCTYPE html>")
        # Zero external CDN links
        assert "https://fonts.googleapis.com" not in out
        assert "cdn.jsdelivr.net" not in out
        # Inline SVG visualizations present
        assert "<svg " in out
        assert "@media print" in out
        # Untrusted HTML strictly escaped
        assert "<script>alert(1)</script>" not in out
        assert "<img src=x onerror=alert(1)>" not in out
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out

    def test_render_markdown_contains_tables_and_sections(self):
        audit = self._sample_audit()
        md = render_markdown(audit)
        assert md.startswith("# ")
        assert "## Security & Unpacking Findings" in md
        assert "## Packer Intelligence" in md
        assert "## DEX Quality & Coverage" in md
        assert "## Recommendations" in md

    def test_render_sarif_valid_2_1_0_schema(self):
        audit = self._sample_audit()
        sarif = render_sarif(audit)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "UNPACK"
        assert len(run["tool"]["driver"]["rules"]) >= 1
        assert len(run["results"]) == len(audit.findings)
        for res in run["results"]:
            assert res["level"] in ("error", "warning", "note")
            assert res["ruleId"]
            assert res["locations"]
        # JSON round-trip
        parsed = json.loads(render_sarif_json(audit))
        assert parsed["version"] == "2.1.0"

    def test_report_generator_dispatch_and_validation(self):
        audit = self._sample_audit()
        assert ReportGenerator.render(audit, "html").startswith("<!DOCTYPE html>")
        assert "# " in ReportGenerator.render(audit, "markdown")
        assert "# " in ReportGenerator.render(audit, "md")
        assert json.loads(ReportGenerator.render(audit, "sarif"))["version"] == "2.1.0"
        assert json.loads(ReportGenerator.render(audit, "json"))["target"] == audit.target
        with pytest.raises(ValueError, match="Unsupported report format"):
            ReportGenerator.render(audit, "docx")

    def test_render_json_roundtrip(self):
        audit = self._sample_audit()
        parsed = json.loads(render_json(audit))
        assert parsed["grade"] == audit.grade
        assert parsed["risk_score"] == audit.risk_score
        assert len(parsed["findings"]) == len(audit.findings)
