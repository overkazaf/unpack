from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from unpack.cli_format import (
    C_ACCENT,
    C_DIM,
    C_FAIL,
    C_HEADER,
    C_INFO,
    C_LABEL,
    C_OK,
    C_WARN,
    UNPACK_THEME,
    confidence_bar,
    create_console,
    format_bytes,
    print_doctor_report,
    print_inspect_apk,
    print_inspect_dex,
    print_repair_summary,
    print_report,
    print_scan_result,
    print_verbose,
    print_verify_result,
    print_verify_summary,
    print_vmp_summary,
    print_xref_summary,
    render_error,
    render_header,
    render_kv_card,
    render_next_steps,
    render_pipeline_step,
    render_severity_badge,
    render_table,
    render_tree,
    safe,
)
from unpack.core.reporter import QualityReport
from unpack.core.scanner import ProtectionLevel, ScanResult


def _recording_console(no_color: bool = True) -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    con = Console(
        file=buf,
        theme=UNPACK_THEME,
        no_color=no_color,
        highlight=False,
        width=120,
    )
    return con, buf


class TestConsoleAndSafety:
    def test_no_color_env_respected(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        con = create_console()
        assert con.no_color is True

    def test_no_color_flag_overrides(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        con = create_console(no_color=True)
        assert con.no_color is True

    def test_safe_escapes_java_array_and_markup(self):
        # Bracketed Rich tags must be escaped, and Java array descriptors must render verbatim
        assert safe("[bold red]evil[/]") == r"\[bold red]evil\[/]"
        assert safe(None) == ""
        con, buf = _recording_console(no_color=False)
        con.print(safe("[Ljava/lang/String;"))
        con.print(safe("[bold red]evil[/]"))
        out = buf.getvalue()
        assert "[Ljava/lang/String;" in out
        assert "[bold red]evil[/]" in out

    def test_format_bytes(self):
        assert format_bytes(None) == "—"
        assert format_bytes(512) == "512 B"
        assert format_bytes(2048) == "2.0 KB"
        assert format_bytes(3 * 1024 * 1024) == "3.0 MB"

    def test_confidence_bar_clamps_bounds(self):
        bar_lo = confidence_bar(-0.5, width=10)
        bar_hi = confidence_bar(1.8, width=10)
        assert "░" * 10 in bar_lo
        assert "█" * 10 in bar_hi

    def test_constants_exported(self):
        for c in (C_OK, C_FAIL, C_WARN, C_INFO, C_DIM, C_ACCENT, C_HEADER, C_LABEL):
            assert isinstance(c, str) and c


class TestComponents:
    def test_layout_components_render_cleanly(self):
        con, buf = _recording_console()
        render_header(con, "UNPACK", subtitle="Workbench", meta="v0.1.0")
        render_kv_card(con, "Summary", [("Target", "[Ljava/lang/Object;")])
        render_table(con, [("Col A", {}), ("Col B", {"justify": "right"})], [["foo", "42"]], title="Metrics")
        render_tree(con, "com.example", [{"label": "MainActivity", "meta": "2 methods", "children": []}])
        render_pipeline_step(con, 1, 4, "Scanning", detail="app.apk")
        render_error(con, "Something failed", detail="bad header", hint="run unpack repair")
        render_next_steps(con, [("unpack verify ./out", "check integrity")])

        out = buf.getvalue()
        assert "UNPACK" in out
        assert "Metrics" in out
        assert "MainActivity" in out
        assert "Step 1/4" in out
        assert "Something failed" in out
        assert "run unpack repair" in out
        assert "unpack verify ./out" in out

    def test_severity_badges(self):
        for sev in ("critical", "high", "medium", "low", "info", "pass", "fail"):
            badge = render_severity_badge(sev)
            assert badge


class TestDomainRenderers:
    def test_print_scan_detected_and_verbose_with_untrusted_markup(self):
        con, buf = _recording_console()
        res = ScanResult(
            packer_name="360加固保 [test]",
            packer_version="v3",
            confidence=0.85,
            protection_level=ProtectionLevel.FUNCTION_EXTRACTION,
            matched_signatures=["so:libjiagu.so", "app:[com.stub.StubApp]"],
            score_breakdown=[
                {"dimension": "SO Files", "score": 3.0, "max": 3.0, "matched": True},
                {"dimension": "App Class", "score": 4.0, "max": 4.0, "matched": True},
            ],
            all_so_files=["lib/arm64-v8a/libjiagu.so", "lib/arm64-v8a/libfoo.so"],
            all_dex_info=[{"name": "classes.dex", "size_kb": 12.0, "classes": 3}],
            suspicious_assets=["assets/jiagu_data.bin"],
            app_class="com.stub.StubApp",
            all_candidates=[
                {"name": "360加固保", "score": 7.0, "signatures": ["libjiagu.so"]},
                {"name": "Other", "score": 1.0, "signatures": ["x"]},
            ],
        )
        print_scan_result(con, res, Path("sample[1].apk"))
        print_verbose(con, res)
        out = buf.getvalue()
        assert "DETECTED" in out
        assert "360加固保 [test]" in out
        assert "Confidence Breakdown" in out
        assert "Native Libraries" in out
        assert "All Candidates" in out

    def test_print_scan_possible_and_no_packer(self):
        con, buf = _recording_console()
        possible = ScanResult(packer_name="腾讯乐固", confidence=0.15, protection_level=ProtectionLevel.DEX_ENCRYPTION)
        print_scan_result(con, possible, Path("weak.apk"))
        none_res = ScanResult(details="No known packer detected")
        print_scan_result(con, none_res, Path("clean.apk"))
        out = buf.getvalue()
        assert "POSSIBLE" in out
        assert "NO PACKER" in out

    def test_print_report_and_verify_and_repair(self):
        con, buf = _recording_console()
        qr = QualityReport(
            dex_count=1,
            total_classes=12,
            total_methods=100,
            methods_with_code=90,
            nop_methods=5,
            code_coverage=0.9,
            score=0.855,
            per_dex=[{"file": "classes.dex", "file_size": 4096, "classes": 12, "methods": 100, "methods_with_code": 90, "nop_methods": 5}],
        )
        print_report(con, qr)
        print_verify_result(con, "a.dex", SimpleNamespace(valid=True, issues=[]))
        print_verify_result(con, "b.dex", SimpleNamespace(valid=False, issues=["checksum mismatch"]))
        print_verify_summary(
            con,
            [
                {"file": "a.dex", "valid": True, "issues": [], "stats": {"file_size": 256, "class_count": 1, "method_count": 2}},
                {"file": "b.dex", "valid": False, "issues": ["bad magic"], "stats": {"file_size": 128}},
            ],
        )
        print_repair_summary(
            con,
            [{"file": "b.dex", "success": True, "actions": ["fixed checksum"], "nop_methods": 2, "health_delta": 0.4}],
        )
        out = buf.getvalue()
        assert "QUALITY REPORT" in out
        assert "PASS" in out
        assert "FAIL" in out
        assert "repaired" in out

    def test_print_doctor_inspect_vmp_xref(self):
        con, buf = _recording_console()
        print_doctor_report(
            con,
            {
                "overall_status": "warn",
                "python_version": "3.12.5",
                "unpack_version": "0.1.0",
                "checks": [
                    {"name": "typer", "category": "python", "status": "pass", "version": "0.27", "summary": "ok"},
                    {"name": "lief", "category": "python", "status": "warn", "version": None, "summary": "missing", "remediation": "pip install lief"},
                ],
                "devices": [],
                "engines": [{"name": "memory", "available": False, "reason": "no device"}],
            },
        )
        print_inspect_apk(
            con,
            {
                "file": "app.apk",
                "sha256": "abc123",
                "size_bytes": 102400,
                "manifest": {"package_name": "com.example", "version_name": "1.0", "min_sdk": 24, "target_sdk": 34},
                "signing": {"schemes": ["v2"], "subject": "CN=Example"},
                "permissions": [{"name": "android.permission.INTERNET", "dangerous": False}],
                "components": {"activities": [{"name": "Main", "exported": True}]},
                "native_libs": [{"name": "libfoo.so", "abi": "arm64-v8a", "size_bytes": 4096, "pie": True, "nx": True}],
                "dex_files": [{"name": "classes.dex", "size_bytes": 8192, "classes": 5, "methods": 20}],
                "findings": [{"severity": "medium", "rule_id": "R1", "title": "Backup enabled"}],
                "risk_score": 25,
                "risk_grade": "B",
            },
            show_permissions=True,
        )
        print_inspect_dex(
            con,
            {"name": "classes.dex", "size_bytes": 256, "version": "dex035", "class_count": 1, "method_count": 2, "string_count": 5},
            classes=[{"name": "Lcom/example/A;", "method_count": 2, "nop_count": 0, "health": "ok"}],
            class_detail={"name": "Lcom/example/A;", "methods": [{"name": "run", "signature": "()V", "health": "normal", "insns_size": 4}]},
            disasm={"class_name": "Lcom/example/A;", "method_name": "run", "instructions": [{"offset": 0, "mnemonic": "return-void", "operands": ""}]},
        )
        print_vmp_summary(
            con,
            [{"file": "classes.dex", "normal": 10, "nop": 1, "vmp": 2}],
            {"total_methods": 13, "normal_count": 10, "nop_count": 1, "vmp_count": 2},
            vmp_methods=[{"dex_file": "classes.dex", "class": "Lcom/A;", "method": "m", "target": "Lvm/Exec;->run"}],
        )
        print_xref_summary(
            con,
            SimpleNamespace(
                string_refs={"hello": []},
                method_calls={"a": []},
                field_refs={},
                reflection_calls=[{"caller": {"class": "Lcom/A;", "method": "f"}, "target": "Ljava/lang/Class;->forName"}],
            ),
            file_count=1,
            search="forName",
        )
        out = buf.getvalue()
        assert "UNPACK Doctor" in out
        assert "APK OVERVIEW" in out
        assert "DEX OVERVIEW" in out
        assert "VMP CLASSIFICATION" in out
        assert "XREF SUMMARY" in out
