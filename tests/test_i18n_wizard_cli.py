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

    def test_en_zh_catalog_parity_and_placeholders(self):
        import string

        from unpack._i18n_en import CATALOG_EN
        from unpack._i18n_zh import CATALOG_ZH
        from unpack.i18n import TRANSLATIONS

        assert TRANSLATIONS["en"] is CATALOG_EN
        assert TRANSLATIONS["zh"] is CATALOG_ZH
        en_keys = set(CATALOG_EN.keys())
        zh_keys = set(CATALOG_ZH.keys())
        assert en_keys == zh_keys, f"Mismatch EN-ZH: {en_keys ^ zh_keys}"
        assert len(en_keys) >= 500

        formatter = string.Formatter()
        for key in sorted(en_keys):
            en_val = CATALOG_EN[key]
            zh_val = CATALOG_ZH[key]
            assert isinstance(en_val, str) and en_val.strip(), f"Empty EN value for {key}"
            assert isinstance(zh_val, str) and zh_val.strip(), f"Empty ZH value for {key}"
            en_fields = {fname for _, fname, _, _ in formatter.parse(en_val) if fname is not None}
            zh_fields = {fname for _, fname, _, _ in formatter.parse(zh_val) if fname is not None}
            assert en_fields == zh_fields, f"Placeholder mismatch for {key}: EN={en_fields} vs ZH={zh_fields}"


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
    def test_global_lang_help_and_doctor(self, monkeypatch):
        monkeypatch.delenv("UNPACK_LANG", raising=False)
        res_zh = runner.invoke(app, ["--lang", "zh"])
        assert res_zh.exit_code == EXIT_OK
        assert "新手引导" in res_zh.output
        assert "快速开始" in res_zh.output

        # `--lang zh --help`, `-L zh --help`, `--help --lang zh`, and `UNPACK_LANG=zh --help`
        for argv in (["--lang", "zh", "--help"], ["-L", "zh", "--help"], ["--help", "--lang", "zh"]):
            res_help_zh = runner.invoke(app, argv)
            assert res_help_zh.exit_code == EXIT_OK
            assert "新手引导" in res_help_zh.output
            assert "快速开始" in res_help_zh.output

        monkeypatch.setenv("UNPACK_LANG", "zh")
        res_env_help = runner.invoke(app, ["--help"])
        assert res_env_help.exit_code == EXIT_OK
        assert "新手引导" in res_env_help.output

        # Explicit `--lang en --help` overrides UNPACK_LANG=zh and prints English Typer help
        res_help_en_override = runner.invoke(app, ["--lang", "en", "--help"])
        assert res_help_en_override.exit_code == EXIT_OK
        assert "Android APK unpacker" in res_help_en_override.output
        assert "新手引导" not in res_help_en_override.output

        monkeypatch.delenv("UNPACK_LANG", raising=False)
        # Default `--help` remains English
        res_help_default = runner.invoke(app, ["--help"])
        assert res_help_default.exit_code == EXIT_OK
        assert "Android APK unpacker" in res_help_default.output

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


class _FakeHTTPResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestAICommandGroup:
    def _clear_ai_env(self, monkeypatch, home: Path) -> None:
        monkeypatch.setenv("UNPACK_HOME", str(home))
        for k in (
            "UNPACK_AI_PROVIDER",
            "UNPACK_AI_BASE_URL",
            "UNPACK_AI_API_KEY",
            "UNPACK_AI_MODEL",
            "UNPACK_AI_ENABLED",
        ):
            monkeypatch.delenv(k, raising=False)

    def test_ai_show_and_config_masking_and_clear_key(self, monkeypatch, tmp_path):
        self._clear_ai_env(monkeypatch, tmp_path / "unpack_home")
        raw_secret = "sk-proj-supersecretkey9876"

        # 1. Configure DeepSeek with secret key
        res_cfg = runner.invoke(
            app,
            [
                "ai",
                "config",
                "--provider",
                "deepseek",
                "--model",
                "deepseek-chat",
                "--api-key",
                raw_secret,
                "--temperature",
                "0.3",
                "--timeout",
                "45",
                "--lang",
                "zh",
            ],
        )
        assert res_cfg.exit_code == EXIT_OK
        assert raw_secret not in res_cfg.output
        assert "sk-***9876" in res_cfg.output
        assert "AI 模型配置已安全保存" in res_cfg.output

        # 2. ai show --json - never exposes raw key and includes presets
        res_show_json = runner.invoke(app, ["ai", "show", "--json", "-"])
        assert res_show_json.exit_code == EXIT_OK
        assert raw_secret not in res_show_json.stdout
        data = json.loads(res_show_json.stdout)
        assert data["config"]["provider"] == "deepseek"
        assert data["config"]["has_api_key"] is True
        assert data["config"]["api_key_masked"] == "sk-***9876"
        assert data["config"]["configured"] is True
        assert len(data["presets"]) >= 7

        # 3. ai show table in English and Chinese
        res_show_en = runner.invoke(app, ["ai", "show", "--lang", "en"])
        assert res_show_en.exit_code == EXIT_OK
        assert "AI MODEL CONFIGURATION" in res_show_en.output
        assert "Supported Provider Presets" in res_show_en.output
        assert raw_secret not in res_show_en.output

        # 4. Updating temperature without --api-key preserves stored key
        res_keep = runner.invoke(app, ["ai", "config", "--temperature", "0.1", "--json", "-"])
        assert res_keep.exit_code == EXIT_OK
        assert json.loads(res_keep.stdout)["has_api_key"] is True

        # 5. --clear-key clears stored key
        res_clear = runner.invoke(app, ["ai", "config", "--clear-key", "--json", "-"])
        assert res_clear.exit_code == EXIT_OK
        cleared = json.loads(res_clear.stdout)
        assert cleared["has_api_key"] is False
        assert cleared["configured"] is False

    def test_ai_test_connectivity_success_and_failure(self, monkeypatch, tmp_path):
        self._clear_ai_env(monkeypatch, tmp_path / "unpack_home")

        # Unconfigured fails cleanly with bilingual error & hint
        res_fail = runner.invoke(app, ["ai", "test", "--lang", "zh"])
        assert res_fail.exit_code != EXIT_OK
        assert "连接测试失败" in res_fail.output

        # Configure Ollama (no key required) and mock urlopen
        runner.invoke(app, ["ai", "config", "--provider", "ollama", "--model", "qwen2.5-coder:7b"])

        def _fake_urlopen(req, timeout=None):
            return _FakeHTTPResponse(
                {
                    "choices": [{"message": {"content": "OK — ready"}}],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16},
                }
            )

        monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

        res_ok_zh = runner.invoke(app, ["ai", "test", "--lang", "zh"])
        assert res_ok_zh.exit_code == EXIT_OK
        assert "连接测试通过" in res_ok_zh.output
        assert "OK — ready" in res_ok_zh.output

        res_ok_json = runner.invoke(app, ["ai", "test", "--json", "-"])
        assert res_ok_json.exit_code == EXIT_OK
        parsed = json.loads(res_ok_json.stdout)
        assert parsed["ok"] is True
        assert parsed["provider"] == "ollama"

    def test_ai_analyze_modules_and_save_workspace(self, monkeypatch, synthetic_dex_bytes, tmp_path):
        self._clear_ai_env(monkeypatch, tmp_path / "unpack_home")
        runner.invoke(app, ["ai", "config", "--provider", "ollama", "--model", "qwen2.5-coder:7b"])

        def _fake_urlopen(req, timeout=None):
            return _FakeHTTPResponse(
                {
                    "choices": [
                        {
                            "message": {
                                "content": "## Summary\nDetected 360 packer; recommend memory dump and VMP triage."
                            }
                        }
                    ],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 30, "total_tokens": 130},
                }
            )

        monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

        apk = _make_apk(tmp_path / "bank_packed.apk", synthetic_dex_bytes, packed=True)

        # Create workspace first
        ws_res = runner.invoke(app, ["workspace", "create", "Audit Case #1", "--json", "-"])
        assert ws_res.exit_code == EXIT_OK
        ws_id = json.loads(ws_res.stdout)["id"]

        # 1. scan module + --save-workspace
        res_scan = runner.invoke(
            app,
            ["ai", "analyze", str(apk), "--module", "scan", "--save-workspace", ws_id, "--lang", "zh"],
        )
        assert res_scan.exit_code == EXIT_OK
        assert "加壳识别与脱壳策略 AI 分析" in res_scan.output
        assert "已归档至工作间" in res_scan.output

        # 2. security module JSON
        res_sec = runner.invoke(app, ["ai", "analyze", str(apk), "--module", "security", "--json", "-"])
        assert res_sec.exit_code == EXIT_OK
        sec_data = json.loads(res_sec.stdout)
        assert sec_data["module"] == "security"
        assert "markdown" in sec_data

        # 3. vmp module on APK
        res_vmp = runner.invoke(app, ["ai", "analyze", str(apk), "--module", "vmp", "--json", "-"])
        assert res_vmp.exit_code == EXIT_OK
        assert json.loads(res_vmp.stdout)["module"] == "vmp_native"

        # 4. method module on rich DEX containing real Dalvik bytecode
        from test_dex_inspector import _build_rich_dex

        dex_file = tmp_path / "rich.dex"
        dex_file.write_bytes(_build_rich_dex())

        res_meth = runner.invoke(
            app,
            [
                "ai",
                "analyze",
                str(dex_file),
                "--module",
                "method",
                "--method",
                "com.acme.app.Main::run",
                "--lang",
                "en",
            ],
        )
        assert res_meth.exit_code == EXIT_OK
        assert "AI Method Reconstruction" in res_meth.output

        # Verify workspace show now lists saved sample & AI analysis!
        ws_show = runner.invoke(app, ["workspace", "show", ws_id, "--json", "-"])
        assert ws_show.exit_code == EXIT_OK
        snap = json.loads(ws_show.stdout)
        assert len(snap["samples"]) == 1
        assert snap["samples"][0]["filename"] == "bank_packed.apk"
        assert len(snap["ai_analyses"]) == 1
        assert snap["ai_analyses"][0]["module"] == "scan"


class TestWorkspaceCommandGroup:
    def test_workspace_crud_export_import_bilingual(self, monkeypatch, tmp_path):
        monkeypatch.setenv("UNPACK_HOME", str(tmp_path / "unpack_home"))

        # 1. List initially includes default workspace
        res_list_zh = runner.invoke(app, ["workspace", "list", "--lang", "zh"])
        assert res_list_zh.exit_code == EXIT_OK
        assert "已保存的工作间列表" in res_list_zh.output
        assert "default" in res_list_zh.output

        # 2. Create a new workspace
        res_create = runner.invoke(
            app,
            ["workspace", "create", "Q4 Banking Audit", "--desc", "Packer review", "--tags", "bank,vmp", "--json", "-"],
        )
        assert res_create.exit_code == EXIT_OK
        created = json.loads(res_create.stdout)
        ws_id = created["id"]
        assert created["name"] == "Q4 Banking Audit"
        assert "bank" in created["tags"]

        # 3. Show workspace in English and Chinese
        res_show_en = runner.invoke(app, ["workspace", "show", ws_id, "--lang", "en"])
        assert res_show_en.exit_code == EXIT_OK
        assert "WORKSPACE OVERVIEW" in res_show_en.output
        assert "Q4 Banking Audit" in res_show_en.output

        res_show_zh = runner.invoke(app, ["workspace", "show", ws_id, "--lang", "zh"])
        assert res_show_zh.exit_code == EXIT_OK
        assert "工作间详情概览" in res_show_zh.output

        # 4. Export to JSON file
        export_path = tmp_path / "ws_export.json"
        res_exp = runner.invoke(app, ["workspace", "export", ws_id, "-o", str(export_path), "--lang", "zh"])
        assert res_exp.exit_code == EXIT_OK
        assert export_path.exists()
        bundle = json.loads(export_path.read_text())
        assert bundle["workspace"]["id"] == ws_id

        # 5. Import into a fresh workspace
        res_imp = runner.invoke(
            app,
            ["workspace", "import", str(export_path), "--name", "Restored Audit", "--json", "-"],
        )
        assert res_imp.exit_code == EXIT_OK
        restored = json.loads(res_imp.stdout)
        assert restored["name"] == "Restored Audit"
        assert restored["id"] != ws_id

        # 6. Delete original workspace & verify missing returns EXIT_NOT_FOUND
        res_del = runner.invoke(app, ["workspace", "delete", ws_id, "--lang", "en"])
        assert res_del.exit_code == EXIT_OK
        assert f"Deleted workspace `{ws_id}`" in res_del.output

        res_missing = runner.invoke(app, ["workspace", "show", ws_id, "--json", "-"])
        assert res_missing.exit_code == EXIT_NOT_FOUND
        assert "error" in json.loads(res_missing.stdout)

