"""Tests for Multi-language (i18n zh/en), Bilingual CLI & Reports,
Interactive Onboarding Wizard (`guide`/`wizard`), and Deep Pipeline Blueprint (`dump --explain`, `pipeline`).
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unpack.cli import EXIT_NOT_FOUND, EXIT_OK, app, build_pipeline_plan
from unpack.core.reporter import ReportGenerator, Reporter, render_html, render_markdown
from unpack.i18n import SUPPORTED_LANGS, get_lang, resolve_lang, set_lang, t, use_lang

runner = CliRunner()


def _make_apk(path: Path, dex_bytes: bytes, *, packed: bool = True) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("AndroidManifest.xml", b"manifest")
        if packed:
            zf.writestr("lib/arm64-v8a/libjiagu.so", b"\x7fELF" + b"\x00" * 64)
            zf.writestr("assets/jiagu_data.bin", b"packed-payload")
    return path


class TestI18nEngine:
    def test_resolve_lang_precedence_and_safe_default(self, monkeypatch):
        monkeypatch.delenv("UNPACK_LANG", raising=False)
        monkeypatch.setenv("LANG", "zh_CN.UTF-8")
        # Default must stay "en" for backward compatibility unless explicitly asked
        assert resolve_lang(None) == "en"
        assert resolve_lang("en") == "en"
        assert resolve_lang("zh") == "zh"
        assert resolve_lang("zh-CN") == "zh"
        assert resolve_lang("zh_Hans") == "zh"
        assert resolve_lang("en-US") == "en"
        assert resolve_lang("auto") == "zh"
        assert resolve_lang("unknown-xx") == "en"

        monkeypatch.setenv("UNPACK_LANG", "zh")
        assert resolve_lang(None) == "zh"
        assert resolve_lang("en") == "en"  # explicit overrides env

    def test_context_state_and_use_lang(self, monkeypatch):
        monkeypatch.delenv("UNPACK_LANG", raising=False)
        set_lang(None)
        assert get_lang() == "en"
        assert set_lang("zh") == "zh"
        assert get_lang() == "zh"
        with use_lang("en") as active:
            assert active == "en"
            assert get_lang() == "en"
        assert get_lang() == "zh"
        set_lang(None)
        assert get_lang() == "en"

    def test_translation_lookup_and_formatting(self):
        assert "en" in SUPPORTED_LANGS and "zh" in SUPPORTED_LANGS
        assert t("fmt.title.doctor", "en") == "UNPACK Doctor"
        assert t("fmt.title.doctor", "zh") == "UNPACK 环境诊断"
        assert t("fmt.step_prefix", "zh", step=2, total=5) == "步骤 2/5"
        # Unknown key falls back safely to key string
        assert t("nonexistent.key.xyz", "zh") == "nonexistent.key.xyz"


class TestBilingualReports:
    def _sample_audit(self):
        return Reporter().build_audit_report(
            "demo_bank.apk",
            scan={
                "packer_name": "360加固保",
                "packer_version": "v3",
                "confidence": 0.92,
                "protection_level": "vmp",
                "matched_signatures": ["so:libjiagu.so"],
                "score_breakdown": [{"dimension": "SO Files", "score": 3.0, "max": 3.0, "matched": True}],
            },
            inspect={
                "file": "demo_bank.apk",
                "sha256": "abcd1234" * 8,
                "manifest": {
                    "package": "com.demo.bank",
                    "version_name": "4.2.0",
                    "version_code": "420",
                    "min_sdk": 24,
                    "target_sdk": 34,
                    "debuggable": True,
                    "allow_backup": False,
                },
                "signing": {"schemes": ["v1", "v2"]},
                "permissions": [{"name": "android.permission.CAMERA", "protection_level": "dangerous"}],
                "native_libs": [{"name": "libjiagu.so", "abi": "arm64-v8a", "size_bytes": 12288, "is_pie": True, "has_nx": True}],
                "findings": [],
                "risk_score": 58,
            },
            quality={
                "dex_count": 1,
                "total_classes": 20,
                "total_methods": 100,
                "methods_with_code": 88,
                "nop_methods": 12,
                "empty_methods": 12,
                "code_coverage": 0.88,
                "score": 0.774,
                "per_dex": [
                    {"file": "classes.dex", "file_size": 16384, "classes": 20, "methods": 100, "methods_with_code": 88, "nop_methods": 12}
                ],
            },
        )

    def test_html_report_zh_and_en(self):
        audit = self._sample_audit()

        html_en = ReportGenerator.render(audit, "html", lang="en")
        assert '<html lang="en"' in html_en
        assert "Findings Explorer" in html_en
        assert "Toggle Theme" in html_en
        assert "Print / PDF" in html_en

        html_zh = ReportGenerator.render(audit, "html", lang="zh")
        assert '<html lang="zh-CN"' in html_zh
        assert "UNPACK 安全与脱壳审计报告" in html_zh
        assert "风险发现浏览器" in html_zh
        assert "加固情报分析" in html_zh
        assert "APK 静态安全画像" in html_zh
        assert "DEX 质量与方法健康度" in html_zh
        assert "切换明暗主题" in html_zh
        assert "打印 / 导出 PDF" in html_zh
        assert "自动化移动安全与脱壳评估报告" in html_zh

    def test_markdown_report_zh_and_en(self):
        audit = self._sample_audit()
        md_en = render_markdown(audit, lang="en")
        assert "## Security & Unpacking Findings" in md_en
        assert "## Packer Intelligence" in md_en

        md_zh = render_markdown(audit, lang="zh")
        assert "# UNPACK 安全与脱壳审计报告" in md_zh
        assert "## 评估元信息" in md_zh
        assert "## 安全与脱壳风险发现" in md_zh
        assert "## 加固情报分析" in md_zh
        assert "## DEX 质量与代码覆盖率" in md_zh
        assert "## 整改与后续建议" in md_zh

    def test_cli_report_command_bilingual(self, synthetic_dex_bytes, tmp_path):
        apk = _make_apk(tmp_path / "target.apk", synthetic_dex_bytes)
        html_zh = tmp_path / "audit_zh.html"
        res = runner.invoke(app, ["report", str(apk), "-F", "html", "-o", str(html_zh), "--lang", "zh"])
        assert res.exit_code == EXIT_OK
        content = html_zh.read_text()
        assert '<html lang="zh-CN"' in content
        assert "风险发现浏览器" in content
        assert "审计报告已生成" in res.output

        # Global --lang zh before subcommand also works
        res_md = runner.invoke(app, ["--lang", "zh", "report", str(apk), "-F", "markdown"])
        assert res_md.exit_code == EXIT_OK
        assert "## 评估元信息" in res_md.stdout

        # Subsequent default call remains English (no state leak)
        res_en = runner.invoke(app, ["report", str(apk), "-F", "markdown"])
        assert res_en.exit_code == EXIT_OK
        assert "## Assessment Metadata" in res_en.stdout


class TestBilingualCliCommands:
    def test_global_lang_help_and_doctor(self):
        res_zh = runner.invoke(app, ["--lang", "zh"])
        assert res_zh.exit_code == EXIT_OK
        assert "新手引导" in res_zh.output
        assert "快速开始" in res_zh.output

        res_doc_zh = runner.invoke(app, ["doctor", "--no-devices", "--lang", "zh"])
        assert res_doc_zh.exit_code == EXIT_OK
        assert "UNPACK 环境诊断" in res_doc_zh.output
        assert "运行环境检查" in res_doc_zh.output

        # Default remains English
        res_doc_en = runner.invoke(app, ["doctor", "--no-devices"])
        assert res_doc_en.exit_code == EXIT_OK
        assert "UNPACK Doctor" in res_doc_en.output
        assert "Environment Checks" in res_doc_en.output

    def test_scan_and_inspect_in_chinese(self, synthetic_dex_bytes, tmp_path):
        apk = _make_apk(tmp_path / "packed.apk", synthetic_dex_bytes, packed=True)
        res_scan = runner.invoke(app, ["--lang", "zh", "scan", str(apk)])
        assert res_scan.exit_code == EXIT_OK
        assert "检测到加固" in res_scan.output or "疑似加固" in res_scan.output
        assert "推荐下一步" in res_scan.output

        res_insp = runner.invoke(app, ["inspect", str(apk), "--lang", "zh"])
        assert res_insp.exit_code == EXIT_OK
        assert "APK 静态概览" in res_insp.output


class TestGuidedWizard:
    @pytest.mark.parametrize("scenario", ["audit", "dex", "repair", "pipeline", "web"])
    def test_guide_non_interactive_all_scenarios_en_and_zh(self, scenario, synthetic_dex_bytes, tmp_path):
        apk = _make_apk(tmp_path / "sample.apk", synthetic_dex_bytes)
        res_en = runner.invoke(
            app,
            ["guide", "--scenario", scenario, "--target", str(apk), "--non-interactive", "--no-devices"],
        )
        assert res_en.exit_code == EXIT_OK
        assert "UNPACK Guided Onboarding Wizard" in res_en.output
        assert "Step 1/5" in res_en.output
        assert "Step 4/5" in res_en.output
        assert "Copyable CLI Command(s):" in res_en.output

        res_zh = runner.invoke(
            app,
            ["wizard", "--scenario", scenario, "--target", str(apk), "--non-interactive", "--no-devices", "--lang", "zh"],
        )
        assert res_zh.exit_code == EXIT_OK
        assert "UNPACK 交互式新手引导向导" in res_zh.output
        assert "步骤 1/5" in res_zh.output
        assert "步骤 4/5" in res_zh.output
        assert "可直接复制运行的命令" in res_zh.output

    def test_guide_interactive_prompts_and_immediate_execution(self, synthetic_dex_bytes, tmp_path):
        apk = _make_apk(tmp_path / "bank.apk", synthetic_dex_bytes)
        # Interactive stdin: goal=1 (audit), target=<apk>, execute=y
        res = runner.invoke(
            app,
            ["guide", "--no-devices", "--lang", "zh"],
            input=f"1\n{apk}\ny\n",
        )
        assert res.exit_code == EXIT_OK
        assert "APK 静态概览" in res.output
        assert "引导工作流执行完成" in res.output

    def test_guide_non_interactive_execute_repair_on_dex(self, tmp_dex_dir):
        res = runner.invoke(
            app,
            ["guide", "-s", "repair", "-t", str(tmp_dex_dir), "--non-interactive", "--execute", "--no-devices"],
        )
        assert res.exit_code == EXIT_OK
        assert "DEX Repair" in res.output
        assert "DEX Verification" in res.output


class TestDeepPipelineBlueprintAndRunner:
    def test_dump_explain_and_dry_run_do_not_touch_device(self, synthetic_dex_bytes, tmp_path):
        apk = _make_apk(tmp_path / "jiagu_app.apk", synthetic_dex_bytes, packed=True)
        out_dir = tmp_path / "should_not_exist"

        res_en = runner.invoke(app, ["dump", str(apk), "-o", str(out_dir), "--explain", "--no-devices"])
        assert res_en.exit_code == EXIT_OK
        assert "PIPELINE EXECUTION BLUEPRINT" in res_en.output
        assert "Live Preflight Checks" in res_en.output
        assert "Stage-by-Stage Execution Blueprint" in res_en.output
        assert not out_dir.exists()

        res_zh = runner.invoke(app, ["dump", str(apk), "--dry-run", "--deep", "--no-devices", "--lang", "zh"])
        assert res_zh.exit_code == EXIT_OK
        assert "管线执行蓝图" in res_zh.output
        assert "实时前置条件检查" in res_zh.output
        assert "分阶段执行蓝图" in res_zh.output

    def test_pipeline_blueprint_json_and_offline_execution(self, synthetic_dex_bytes, tmp_path):
        apk = _make_apk(tmp_path / "clean_app.apk", synthetic_dex_bytes, packed=False)
        out_dir = tmp_path / "offline_out"
        html_out = tmp_path / "offline_audit.html"

        # 1. Blueprint JSON
        res_json = runner.invoke(app, ["pipeline", str(apk), "--no-devices", "--json", "-"])
        assert res_json.exit_code == EXIT_OK
        plan = json.loads(res_json.stdout)
        assert plan["mode"] == "offline"  # auto-selected offline because no packer
        assert plan["can_execute"] is True
        assert len(plan["stages"]) >= 6
        assert any(s["id"] == "extract_dex" for s in plan["stages"])

        # 2. Execute Offline Pipeline end-to-end in Chinese (zero device!)
        res_exec = runner.invoke(
            app,
            [
                "pipeline",
                str(apk),
                "--mode",
                "offline",
                "-o",
                str(out_dir),
                "--report-html",
                str(html_out),
                "--execute",
                "--no-devices",
                "--lang",
                "zh",
            ],
        )
        assert res_exec.exit_code == EXIT_OK
        assert "离线审计与修复管线执行完成" in res_exec.output
        assert (out_dir / "classes.dex").exists()
        assert (out_dir / "report.json").exists()
        assert html_out.exists()
        html_content = html_out.read_text()
        assert '<html lang="zh-CN"' in html_content
        assert "UNPACK 安全与脱壳审计报告" in html_content

    def test_build_pipeline_plan_missing_apk_and_blocked_device_remediation(self, synthetic_dex_bytes, tmp_path):
        res_missing = runner.invoke(app, ["pipeline", str(tmp_path / "missing.apk"), "--json", "-"])
        assert res_missing.exit_code == EXIT_NOT_FOUND
        assert "error" in json.loads(res_missing.stdout)

        apk = _make_apk(tmp_path / "packed.apk", synthetic_dex_bytes, packed=True)
        plan = build_pipeline_plan(apk, mode="standard", check_devices=False, lang="zh")
        assert plan["mode"] == "standard"
        assert plan["can_execute"] is False
        assert any(c["status"] == "block" and c["id"] == "device" for c in plan["preflight_checks"])
        assert "--mode offline" in plan["offline_alternative_cmd"]
