"""Unit tests for unpack.core.ai_engine."""

from __future__ import annotations

import io
import json
import os
import stat
import urllib.error
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from unpack.core.ai_engine import (
    PROVIDER_PRESETS,
    AIAnalysisResult,
    AIAnalyzer,
    AIConfig,
    AIConfigStore,
    is_masked_api_key,
    list_provider_presets,
    mask_api_key,
    test_connection,
)
from unpack.core.errors import ErrorCode, UnpackError


class _FakeHTTPResponse:
    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self._body = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None


# ---------------------------------------------------------------------------
# Presets & Config Store Tests
# ---------------------------------------------------------------------------


def test_provider_presets_complete() -> None:
    expected = {
        "openai": ("https://api.openai.com/v1", "gpt-4o-mini", True),
        "anthropic": ("https://api.anthropic.com/v1", "claude-3-5-sonnet-latest", True),
        "gemini": ("https://generativelanguage.googleapis.com/v1beta", "gemini-2.5-flash", True),
        "deepseek": ("https://api.deepseek.com/v1", "deepseek-chat", True),
        "qwen": ("https://dashscope.aliyuncs.com/compatible-mode/v1", "qwen-plus", True),
        "ollama": ("http://127.0.0.1:11434/v1", "qwen2.5-coder:7b", False),
        "custom": ("", "", False),
    }
    for pid, (base_url, model, req_key) in expected.items():
        assert pid in PROVIDER_PRESETS
        p = PROVIDER_PRESETS[pid]
        assert p["base_url"] == base_url
        assert p["default_model"] == model
        assert p["requires_api_key"] is req_key

    presets_list = list_provider_presets()
    assert len(presets_list) == 7
    json.dumps(presets_list)


def test_mask_api_key_and_public_dict() -> None:
    assert mask_api_key("") == ""
    assert mask_api_key("abcd") == "***"
    assert mask_api_key("sk-proj-secret12345678") == "sk-***5678"
    assert mask_api_key("AIzaSyD1234567890abcd") == "AIz***abcd"
    assert is_masked_api_key("sk-***5678") is True
    assert is_masked_api_key("sk-real-secret-value") is False

    cfg = AIConfig(
        provider="openai",
        api_key="sk-supersecret9876",
        extra_headers={"X-Custom": "ok", "X-Auth-Token": "tok-abcdef1234"},
    )
    pub = cfg.to_public_dict()
    assert "api_key" not in pub
    assert pub["has_api_key"] is True
    assert pub["api_key_masked"] == "sk-***9876"
    assert "sk-supersecret9876" not in json.dumps(pub)
    assert pub["extra_headers"]["X-Custom"] == "ok"
    assert "tok-abcdef1234" not in pub["extra_headers"]["X-Auth-Token"]
    assert cfg.to_dict() == pub


def test_config_store_save_mask_preserve_clear_and_permissions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in (
        "UNPACK_AI_PROVIDER",
        "UNPACK_AI_BASE_URL",
        "UNPACK_AI_API_KEY",
        "UNPACK_AI_MODEL",
        "UNPACK_AI_ENABLED",
    ):
        monkeypatch.delenv(key, raising=False)

    store = AIConfigStore(base_dir=tmp_path)
    saved = store.save(
        {
            "provider": "openai",
            "api_key": "sk-secret-key-1234",
            "model": "gpt-4o",
        }
    )
    assert saved.api_key == "sk-secret-key-1234"
    assert saved.model == "gpt-4o"
    assert store.config_path.exists()

    if os.name == "posix":
        mode = stat.S_IMODE(store.config_path.stat().st_mode)
        assert mode == 0o600

    # Updating with empty api_key preserves stored secret
    updated1 = store.save({"provider": "openai", "api_key": "", "temperature": 0.4})
    assert updated1.api_key == "sk-secret-key-1234"
    assert updated1.temperature == 0.4

    # Updating with masked api_key preserves stored secret
    updated2 = store.save({"provider": "openai", "api_key": "sk-***1234", "model": "gpt-4o-mini"})
    assert updated2.api_key == "sk-secret-key-1234"
    assert updated2.model == "gpt-4o-mini"

    # Switching provider automatically updates preset base_url & model when omitted
    switched = store.save({"provider": "deepseek"})
    assert switched.provider == "deepseek"
    assert switched.base_url == "https://api.deepseek.com/v1"
    assert switched.model == "deepseek-chat"
    assert switched.api_key == "sk-secret-key-1234"

    # Explicit clear_api_key=True clears secret
    cleared = store.save({"provider": "deepseek"}, clear_api_key=True)
    assert cleared.api_key == ""
    assert cleared.is_configured() is False

    # Reload from fresh AIConfigStore instance
    reloaded = AIConfigStore(base_dir=tmp_path).load()
    assert reloaded.provider == "deepseek"
    assert reloaded.api_key == ""


def test_config_store_env_fallback_and_corrupt_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("UNPACK_HOME", str(tmp_path))
    monkeypatch.setenv("UNPACK_AI_PROVIDER", "qwen")
    monkeypatch.setenv("UNPACK_AI_API_KEY", "sk-env-9999")
    monkeypatch.setenv("UNPACK_AI_MODEL", "qwen-max")
    monkeypatch.delenv("UNPACK_AI_BASE_URL", raising=False)

    # Corrupt file on disk should fall back gracefully
    (tmp_path / "ai_config.json").write_text("{not json", encoding="utf-8")

    store = AIConfigStore()
    cfg = store.load()
    assert cfg.provider == "qwen"
    assert cfg.base_url == "https://dashscope.aliyuncs.com/compatible-mode/v1"
    assert cfg.model == "qwen-max"
    assert cfg.api_key == "sk-env-9999"
    assert cfg.is_configured() is True


# ---------------------------------------------------------------------------
# Protocol Adapter Tests (Mocked urllib.request.urlopen)
# ---------------------------------------------------------------------------


def test_openai_protocol_adapter() -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeHTTPResponse:
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _FakeHTTPResponse(
            {
                "choices": [{"message": {"content": "## 结论\n检测到 360 加固，建议使用 Frida。"}}],
                "usage": {"prompt_tokens": 111, "completion_tokens": 44, "total_tokens": 155},
            }
        )

    cfg = AIConfig(provider="openai", api_key="sk-test-openai-0001", model="gpt-4o-mini")
    analyzer = AIAnalyzer(cfg)
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        res = analyzer.analyze_scan(
            {"packer_name": "360 Jiagu", "protection_level": "dex_encryption", "confidence": 0.92},
            lang="zh",
        )

    assert isinstance(res, AIAnalysisResult)
    assert captured["url"] == "https://api.openai.com/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer sk-test-openai-0001"
    assert captured["body"]["model"] == "gpt-4o-mini"
    assert len(captured["body"]["messages"]) == 2
    assert "360 加固" in res.markdown
    assert res.usage == {"prompt_tokens": 111, "completion_tokens": 44, "total_tokens": 155}
    d = res.to_dict()
    for field in (
        "id", "module", "provider", "model", "lang", "title",
        "summary", "markdown", "latency_ms", "usage", "created_at",
    ):
        assert field in d
    assert d["module"] == "scan"
    assert d["lang"] == "zh"


def test_anthropic_protocol_adapter() -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeHTTPResponse:
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeHTTPResponse(
            {
                "content": [{"type": "text", "text": "## Behavior Summary\nLoads encrypted payload."}],
                "usage": {"input_tokens": 80, "output_tokens": 35},
            }
        )

    cfg = AIConfig(provider="anthropic", api_key="sk-ant-12345678", model="claude-3-5-sonnet-latest")
    analyzer = AIAnalyzer(cfg)
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        res = analyzer.analyze_method(
            {
                "class_name": "Lcom/demo/Loader;",
                "method_name": "attachBaseContext",
                "instructions": [
                    {"offset": "0x0000", "mnemonic": "const-string", "operand": '"libjiagu.so"'},
                    {"offset": "0x0004", "mnemonic": "invoke-static", "operand": "Ljava/lang/System;->loadLibrary"},
                ],
            },
            class_name="Lcom/demo/Loader;",
            lang="en",
        )

    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["x-api-key"] == "sk-ant-12345678"
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    assert "system" in captured["body"]
    assert captured["body"]["messages"][0]["role"] == "user"
    assert res.provider == "anthropic"
    assert res.module == "method"
    assert res.lang == "en"
    assert res.usage == {"prompt_tokens": 80, "completion_tokens": 35, "total_tokens": 115}
    assert "Loads encrypted payload" in res.markdown


def test_gemini_protocol_adapter() -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeHTTPResponse:
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeHTTPResponse(
            {
                "candidates": [
                    {"content": {"parts": [{"text": "## VMP Triage\nHigh virtualization ratio detected."}]}}
                ],
                "usageMetadata": {
                    "promptTokenCount": 200,
                    "candidatesTokenCount": 90,
                    "totalTokenCount": 290,
                },
            }
        )

    cfg = AIConfig(provider="gemini", api_key="AIzaSyTestKey12345", model="gemini-2.5-flash")
    analyzer = AIAnalyzer(cfg)
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        res = analyzer.analyze_vmp_native(
            vmp={"dex": "classes.dex", "total_methods": 100, "vmp_count": 40, "vmp_ratio": 0.4},
            native_libs=[{"name": "libvmp.so", "abi": "arm64-v8a", "security_indicators": ["vmp"]}],
            xref={"iocs": {"urls": ["https://evil.example"], "ips": ["1.2.3.4"]}},
            lang="en",
        )

    assert captured["url"] == "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    assert captured["headers"]["x-goog-api-key"] == "AIzaSyTestKey12345"
    assert "system_instruction" in captured["body"]
    assert "contents" in captured["body"]
    assert res.module == "vmp_native"
    assert res.usage == {"prompt_tokens": 200, "completion_tokens": 90, "total_tokens": 290}


def test_ollama_local_adapter_without_api_key() -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeHTTPResponse:
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeHTTPResponse(
            {
                "choices": [{"message": {"content": "## Executive Security Posture\nGrade D — disable debuggable."}}],
                "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
            }
        )

    cfg = AIConfig(provider="ollama")
    assert cfg.api_key == ""
    assert cfg.is_configured() is True

    analyzer = AIAnalyzer(cfg)
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        res = analyzer.analyze_security(
            {
                "file": "demo.apk",
                "risk_score": 70,
                "risk_grade": "D",
                "manifest": {"debuggable": True, "allow_backup": True},
                "findings": [{"id": "APK-DEBUGGABLE", "severity": "high", "title": "Debuggable"}],
            },
            lang="en",
        )

    assert captured["url"] == "http://127.0.0.1:11434/v1/chat/completions"
    assert "authorization" not in captured["headers"]
    assert captured["body"]["model"] == "qwen2.5-coder:7b"
    assert res.module == "security"


def test_pipeline_issue_analyzer_bilingual() -> None:
    prompts_seen: list[tuple[str, str]] = []

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeHTTPResponse:
        body = json.loads(req.data.decode("utf-8"))
        prompts_seen.append((body["messages"][0]["content"], body["messages"][1]["content"]))
        return _FakeHTTPResponse(
            {"choices": [{"message": {"content": "Run `adb devices` and restart frida-server."}}]}
        )

    cfg = AIConfig(provider="ollama")
    analyzer = AIAnalyzer(cfg)
    stage = {"name": "dump", "engine": "frida", "status": "failed"}
    doctor = {"overall_status": "warn", "devices": [], "engines": [{"name": "frida", "available": False}]}

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        res_zh = analyzer.analyze_pipeline_issue(stage, "Failed to spawn process", doctor=doctor, lang="zh")
        res_en = analyzer.analyze_pipeline_issue(stage, "Failed to spawn process", doctor=doctor, lang="en")

    assert res_zh.module == "pipeline_issue"
    assert res_zh.lang == "zh"
    assert "流水线" in res_zh.title
    assert res_en.lang == "en"
    assert "Pipeline" in res_en.title
    assert "根因定位" in prompts_seen[0][0]
    assert "Root Cause Diagnosis" in prompts_seen[1][0]


# ---------------------------------------------------------------------------
# Connectivity Test & Error Handling Tests
# ---------------------------------------------------------------------------


def test_test_connection_success_and_failures() -> None:
    cfg_ok = AIConfig(provider="openai", api_key="sk-probe-12345678")
    with patch(
        "urllib.request.urlopen",
        return_value=_FakeHTTPResponse({"choices": [{"message": {"content": "OK"}}]}),
    ):
        out = test_connection(cfg_ok)
    assert out["ok"] is True
    assert out["provider"] == "openai"
    assert out["reply_preview"] == "OK"
    assert out["error"] == ""

    # Unconfigured OpenAI (missing key)
    unconfigured = AIConfig(provider="openai", api_key="")
    res_unconf = test_connection(unconfigured, lang="zh")
    assert res_unconf["ok"] is False
    assert "API Key" in res_unconf["error"]
    assert res_unconf["hint"]

    # HTTP 401 should NOT leak raw API key even if upstream echoes it
    secret = "sk-leak-check-99998888"
    http_err = urllib.error.HTTPError(
        url="https://api.openai.com/v1/chat/completions",
        code=401,
        msg="Unauthorized",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(json.dumps({"error": {"message": f"Invalid key {secret}"}}).encode("utf-8")),
    )
    with patch("urllib.request.urlopen", side_effect=http_err):
        res_401 = test_connection(AIConfig(provider="openai", api_key=secret), lang="en")
    assert res_401["ok"] is False
    assert "401" in res_401["error"]
    assert secret not in res_401["error"]
    assert "Invalid or unauthorized API key" in res_401["hint"]

    # Network error on Ollama provides ollama-specific hint
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        res_ollama = test_connection(AIConfig(provider="ollama"), lang="en")
    assert res_ollama["ok"] is False
    assert "ollama serve" in res_ollama["hint"]


def test_analyzer_raises_unpack_error_when_disabled_or_unconfigured() -> None:
    disabled = AIConfig(provider="ollama", enabled=False)
    with pytest.raises(UnpackError) as exc_zh:
        AIAnalyzer(disabled).analyze_scan({"packer_name": None}, lang="zh")
    assert exc_zh.value.code == ErrorCode.ENGINE_UNAVAILABLE
    assert "禁用" in exc_zh.value.message
    assert exc_zh.value.hint

    no_key = AIConfig(provider="openai", api_key="")
    with pytest.raises(UnpackError) as exc_en:
        AIAnalyzer(no_key).analyze_scan({"packer_name": None}, lang="en")
    assert exc_en.value.code == ErrorCode.ENGINE_UNAVAILABLE
    assert "API key" in exc_en.value.message
    assert "UNPACK_AI_API_KEY" in exc_en.value.hint


# ---------------------------------------------------------------------------
# Token-Budget / Context Truncation Tests
# ---------------------------------------------------------------------------


def test_giant_apk_context_is_strictly_budgeted() -> None:
    captured_user_prompt: list[str] = []

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeHTTPResponse:
        body = json.loads(req.data.decode("utf-8"))
        captured_user_prompt.append(body["messages"][1]["content"])
        return _FakeHTTPResponse({"choices": [{"message": {"content": "Compact analysis OK"}}]})

    giant_inspect = {
        "file": "giant_game.apk",
        "sha256": "a" * 64,
        "size_bytes": 500_000_000,
        "risk_score": 88,
        "risk_grade": "F",
        "manifest": {"package": "com.giant.game", "debuggable": True},
        "permissions": [
            {"name": f"android.permission.PERM_{i}", "level": "dangerous"} for i in range(500)
        ],
        "native_libs": [
            {
                "name": f"libmod_{i}.so",
                "abi": "arm64-v8a",
                "size_bytes": 10000 + i,
                "security_indicators": ["jiagu"] if i == 0 else [],
            }
            for i in range(600)
        ],
        "findings": [
            {
                "id": f"F-{i}",
                "severity": "critical" if i == 0 else "low",
                "title": f"Finding {i}",
                "detail": "X" * 2000,
            }
            for i in range(1000)
        ],
    }

    giant_disasm = {
        "class_name": "Lcom/giant/Huge;",
        "method_name": "megaMethod",
        "instructions": [
            {"offset": f"0x{i:04x}", "mnemonic": "const-string", "operand": "A" * 500}
            for i in range(800)
        ],
    }

    analyzer = AIAnalyzer(AIConfig(provider="ollama"), max_context_chars=4000)
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        analyzer.analyze_security(giant_inspect, lang="en")
        analyzer.analyze_method(giant_disasm, lang="en")

    assert len(captured_user_prompt) == 2
    # Each prompt must stay well under max_context_chars + small prompt wrapper overhead
    for prompt in captured_user_prompt:
        assert len(prompt) < 4600
    # Highest-severity finding was preserved at the top
    assert "F-0" in captured_user_prompt[0]
    assert "omitted" in captured_user_prompt[1] or "truncated" in captured_user_prompt[1]


# ---------------------------------------------------------------------------
# P0 Regression Tests: Real Schema Mapping, SSRF Scheme Guard, Dynamic UA
# ---------------------------------------------------------------------------


def test_real_schema_fields_preserved_in_ai_context() -> None:
    """P0 regression: NativeLibInfo, PermissionInfo, and ScanResult schemas map cleanly."""
    from unpack import __version__

    captured: list[dict[str, Any]] = []

    def fake_urlopen(req: Any, timeout: float = 0) -> _FakeHTTPResponse:
        captured.append(
            {
                "headers": {k.lower(): v for k, v in req.header_items()},
                "body": json.loads(req.data.decode("utf-8")),
            }
        )
        return _FakeHTTPResponse({"choices": [{"message": {"content": "Analysis OK"}}]})

    analyzer = AIAnalyzer(AIConfig(provider="ollama"))
    scan_payload = {
        "packer_name": "360加固保",
        "protection_level": "vmp",
        "confidence": 0.95,
        "matched_signatures": ["so:lib/arm64-v8a/libjiagu_ls.so", "asset:assets/.appkey"],
    }
    inspect_payload = {
        "file": "bank.apk",
        "sha256": "f" * 64,
        "risk_score": 68,
        "risk_grade": "D",
        "manifest": {"package": "com.bank.app", "debuggable": True},
        "permissions": [
            {"name": "android.permission.READ_SMS", "protection_level": "dangerous", "risk": "high"},
            {"name": "android.permission.INTERNET", "protection_level": "normal", "risk": "low"},
        ],
        "native_libs": [
            {
                "name": "libplain.so",
                "abi": "arm64-v8a",
                "size_bytes": 9_000_000,
                "is_security_related": False,
                "vmp_indicators": [],
                "dex2c_indicators": [],
                "anti_debug_indicators": [],
                "crypto_indicators": [],
                "risk_flags": [],
            },
            {
                "name": "libjiagu_ls.so",
                "abi": "arm64-v8a",
                "size_bytes": 200_000,
                "is_security_related": True,
                "vmp_indicators": ["vmp_entry"],
                "dex2c_indicators": [],
                "anti_debug_indicators": ["ptrace"],
                "crypto_indicators": [],
                "risk_flags": ["high_entropy_packed"],
            },
            {
                "name": "libjgdtc.so",
                "abi": "arm64-v8a",
                "size_bytes": 150_000,
                "is_security_related": False,
                "dex2c_indicators": ["dtcloader"],
                "risk_flags": [],
            },
        ],
        "findings": [],
    }

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        analyzer.analyze_scan(scan_payload, inspect=inspect_payload, lang="en")
        analyzer.analyze_security(inspect_payload, lang="en")
        analyzer.analyze_vmp_native(
            vmp={"dex": "classes.dex", "total_methods": 50, "vmp_count": 5},
            native_libs=inspect_payload["native_libs"],
            lang="en",
        )

    assert len(captured) == 3
    # Dynamic User-Agent uses package __version__
    assert captured[0]["headers"]["user-agent"] == f"UNPACK-Studio/{__version__}"

    # 1. Scan context preserves matched_signatures and security native libs
    scan_prompt = captured[0]["body"]["messages"][1]["content"]
    assert "matched_signatures" in scan_prompt
    assert "so:lib/arm64-v8a/libjiagu_ls.so" in scan_prompt
    assert "libjiagu_ls.so" in scan_prompt
    assert "libjgdtc.so" in scan_prompt
    assert "libplain.so" not in scan_prompt

    # 2. Security context extracts dangerous permissions via protection_level
    sec_prompt = captured[1]["body"]["messages"][1]["content"]
    assert "android.permission.READ_SMS" in sec_prompt
    assert "android.permission.INTERNET" not in sec_prompt

    # 3. VMP/Native context sorts security-flagged SOs ahead of larger plain SOs
    vmp_prompt = captured[2]["body"]["messages"][1]["content"]
    assert vmp_prompt.index("libjiagu_ls.so") < vmp_prompt.index("libplain.so")


@pytest.mark.parametrize(
    "bad_url",
    [
        "file:///etc/passwd",
        "ftp://internal.host/v1",
        "gopher://127.0.0.1:6379/_INFO",
        "javascript:alert(1)",
        "http://",
        "not-a-url",
    ],
)
def test_ssrf_non_http_base_url_rejected(bad_url: str) -> None:
    """P0 security: non-http/https base_url must be rejected at config and call time."""
    with pytest.raises(ValueError, match="http:// and https://"):
        AIConfig(provider="custom", base_url=bad_url, model="test-model")

    with patch("urllib.request.urlopen") as mock_open:
        res = test_connection({"provider": "custom", "base_url": bad_url, "model": "test-model"}, lang="en")
        assert res["ok"] is False
        assert "http://" in res["error"] or "Unsupported" in res["error"]
        mock_open.assert_not_called()

    # Defense-in-depth: post-init mutation is also blocked before urlopen
    cfg = AIConfig(provider="ollama")
    cfg.base_url = bad_url
    with patch("urllib.request.urlopen") as mock_open:
        with pytest.raises(UnpackError) as exc_info:
            AIAnalyzer(cfg).analyze_scan({"packer_name": None}, lang="en")
        assert exc_info.value.code == ErrorCode.ENGINE_UNAVAILABLE
        mock_open.assert_not_called()
