"""Multi-provider AI configuration & reverse-engineering analyzer for UNPACK.

Zero-extra-dependency (Python stdlib ``urllib.request`` + ``json``) engine
supporting OpenAI, Anthropic Claude, Google Gemini, DeepSeek, Qwen/DashScope,
local Ollama, and custom OpenAI-compatible endpoints.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from unpack.core.errors import ErrorCode, UnpackError

DEFAULT_MAX_CONTEXT_CHARS = 12000
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_TEMPERATURE = 0.2
DEFAULT_MAX_TOKENS = 2048

# ---------------------------------------------------------------------------
# Provider Presets
# ---------------------------------------------------------------------------

PROVIDER_PRESETS: dict[str, dict[str, Any]] = {
    "openai": {
        "id": "openai",
        "label": "OpenAI",
        "label_zh": "OpenAI",
        "protocol": "openai",
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
        "models": ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "o3-mini"],
        "requires_api_key": True,
        "docs_url": "https://platform.openai.com/docs",
    },
    "anthropic": {
        "id": "anthropic",
        "label": "Anthropic Claude",
        "label_zh": "Anthropic Claude",
        "protocol": "anthropic",
        "base_url": "https://api.anthropic.com/v1",
        "default_model": "claude-3-5-sonnet-latest",
        "models": [
            "claude-3-5-sonnet-latest",
            "claude-3-7-sonnet-latest",
            "claude-3-5-haiku-latest",
        ],
        "requires_api_key": True,
        "docs_url": "https://docs.anthropic.com",
    },
    "gemini": {
        "id": "gemini",
        "label": "Google Gemini",
        "label_zh": "Google Gemini",
        "protocol": "gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "default_model": "gemini-2.5-flash",
        "models": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"],
        "requires_api_key": True,
        "docs_url": "https://ai.google.dev/gemini-api/docs",
    },
    "deepseek": {
        "id": "deepseek",
        "label": "DeepSeek",
        "label_zh": "DeepSeek 深度求索",
        "protocol": "openai",
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "requires_api_key": True,
        "docs_url": "https://api-docs.deepseek.com",
    },
    "qwen": {
        "id": "qwen",
        "label": "Qwen / DashScope",
        "label_zh": "通义千问 / DashScope",
        "protocol": "openai",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "default_model": "qwen-plus",
        "models": ["qwen-plus", "qwen-max", "qwen-turbo", "qwen2.5-coder-32b-instruct"],
        "requires_api_key": True,
        "docs_url": "https://help.aliyun.com/zh/model-studio",
    },
    "ollama": {
        "id": "ollama",
        "label": "Local Ollama",
        "label_zh": "本地 Ollama",
        "protocol": "openai",
        "base_url": "http://127.0.0.1:11434/v1",
        "default_model": "qwen2.5-coder:7b",
        "models": ["qwen2.5-coder:7b", "qwen2.5-coder:14b", "llama3.1:8b", "deepseek-r1:8b"],
        "requires_api_key": False,
        "docs_url": "https://ollama.com",
    },
    "custom": {
        "id": "custom",
        "label": "Custom OpenAI-Compatible",
        "label_zh": "自定义 OpenAI 兼容接口",
        "protocol": "openai",
        "base_url": "",
        "default_model": "",
        "models": [],
        "requires_api_key": False,
        "docs_url": "",
    },
}


def list_provider_presets() -> list[dict[str, Any]]:
    """Return provider presets as a JSON-serializable list."""
    return [dict(v, models=list(v["models"])) for v in PROVIDER_PRESETS.values()]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _resolve_unpack_home(base_dir: str | Path | None = None) -> Path:
    if base_dir is not None:
        return Path(base_dir).expanduser()
    env_home = os.environ.get("UNPACK_HOME", "").strip()
    if env_home:
        return Path(env_home).expanduser()
    return Path.home() / ".unpack"


def _normalize_lang(lang: str | None) -> str:
    val = (lang or "zh").strip().lower()
    if val.startswith("en"):
        return "en"
    return "zh"


def mask_api_key(api_key: str | None) -> str:
    """Return a masked display string for an API key (e.g. ``sk-***1234``)."""
    key = (api_key or "").strip()
    if not key:
        return ""
    if len(key) <= 4:
        return "***"
    if len(key) <= 8:
        return f"***{key[-2:]}"
    tail = key[-4:]
    dash_idx = key.find("-")
    if 1 <= dash_idx <= 6:
        prefix = key[: dash_idx + 1]
    else:
        prefix = key[:3]
    return f"{prefix}***{tail}"


def is_masked_api_key(value: str | None) -> bool:
    """Return True if ``value`` looks like a masked placeholder rather than a raw secret."""
    if not value:
        return False
    s = str(value).strip()
    return "***" in s or "•••" in s or "···" in s


def _sanitize_headers_public(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    sensitive_tokens = ("key", "token", "auth", "secret", "pass")
    for k, v in (headers or {}).items():
        lk = str(k).lower()
        if any(tok in lk for tok in sensitive_tokens):
            out[str(k)] = mask_api_key(str(v))
        else:
            out[str(k)] = str(v)
    return out


def _atomic_write_json_secure(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=2, ensure_ascii=False)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        if os.name == "posix":
            os.chmod(path, 0o600)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _parse_bool_env(raw: str | None, default: bool = True) -> bool:
    if raw is None or raw.strip() == "":
        return default
    low = raw.strip().lower()
    if low in {"0", "false", "no", "off"}:
        return False
    if low in {"1", "true", "yes", "on"}:
        return True
    return default


def _get_preset(provider: str) -> dict[str, Any]:
    return PROVIDER_PRESETS.get((provider or "").strip().lower(), PROVIDER_PRESETS["custom"])


# ---------------------------------------------------------------------------
# AIConfig & AIConfigStore
# ---------------------------------------------------------------------------


@dataclass
class AIConfig:
    """Configuration for the UNPACK AI provider."""

    enabled: bool = True
    provider: str = "openai"
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.provider = (self.provider or "openai").strip().lower()
        if self.provider not in PROVIDER_PRESETS:
            self.provider = "custom"
        preset = _get_preset(self.provider)
        if not self.base_url and preset["base_url"]:
            self.base_url = preset["base_url"]
        self.base_url = self.base_url.strip().rstrip("/")
        if not self.model and preset["default_model"]:
            self.model = preset["default_model"]
        self.model = self.model.strip()
        self.api_key = (self.api_key or "").strip()
        self.temperature = max(0.0, min(2.0, float(self.temperature)))
        self.max_tokens = max(32, min(32768, int(self.max_tokens)))
        self.timeout_seconds = max(3.0, min(300.0, float(self.timeout_seconds)))
        if not isinstance(self.extra_headers, dict):
            self.extra_headers = {}
        else:
            self.extra_headers = {str(k): str(v) for k, v in self.extra_headers.items() if str(k).strip()}

    @property
    def protocol(self) -> str:
        return str(_get_preset(self.provider)["protocol"])

    @property
    def requires_api_key(self) -> bool:
        return bool(_get_preset(self.provider)["requires_api_key"])

    def is_configured(self) -> bool:
        if not self.enabled:
            return False
        if not self.base_url or not self.model:
            return False
        if self.requires_api_key and not self.api_key:
            return False
        return True

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.enabled),
            "provider": self.provider,
            "base_url": self.base_url,
            "api_key": self.api_key,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout_seconds": self.timeout_seconds,
            "extra_headers": dict(self.extra_headers),
        }

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize configuration for API/UI responses WITHOUT exposing raw ``api_key``."""
        return {
            "enabled": bool(self.enabled),
            "provider": self.provider,
            "protocol": self.protocol,
            "base_url": self.base_url,
            "model": self.model,
            "has_api_key": bool(self.api_key),
            "api_key_masked": mask_api_key(self.api_key),
            "requires_api_key": self.requires_api_key,
            "configured": self.is_configured(),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout_seconds": self.timeout_seconds,
            "extra_headers": _sanitize_headers_public(self.extra_headers),
        }

    def to_dict(self) -> dict[str, Any]:
        """Safe default serializer — delegates to ``to_public_dict()`` so secrets never leak."""
        return self.to_public_dict()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AIConfig":
        provider = str(data.get("provider") or "openai").strip().lower()
        if provider not in PROVIDER_PRESETS:
            provider = "custom"
        preset = _get_preset(provider)
        return cls(
            enabled=bool(data.get("enabled", True)),
            provider=provider,
            base_url=str(data.get("base_url") if data.get("base_url") is not None else preset["base_url"]),
            api_key=str(data.get("api_key") or ""),
            model=str(data.get("model") if data.get("model") is not None else preset["default_model"]),
            temperature=float(data.get("temperature", DEFAULT_TEMPERATURE)),
            max_tokens=int(data.get("max_tokens", DEFAULT_MAX_TOKENS)),
            timeout_seconds=float(data.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
            extra_headers=dict(data.get("extra_headers") or {}),
        )


class AIConfigStore:
    """Persistent storage for ``AIConfig`` at ``<unpack_home>/ai_config.json`` (0o600)."""

    def __init__(self, base_dir: str | Path | None = None) -> None:
        self.home_dir = _resolve_unpack_home(base_dir)
        self.config_path = self.home_dir / "ai_config.json"
        self._lock = threading.RLock()

    def _read_raw_file(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        try:
            raw = self.config_path.read_text(encoding="utf-8")
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def load(self) -> AIConfig:
        """Load configuration from disk with environment-variable fallback."""
        with self._lock:
            stored = self._read_raw_file()
            env_provider = os.environ.get("UNPACK_AI_PROVIDER", "").strip().lower()
            env_base_url = os.environ.get("UNPACK_AI_BASE_URL", "").strip()
            env_api_key = os.environ.get("UNPACK_AI_API_KEY", "").strip()
            env_model = os.environ.get("UNPACK_AI_MODEL", "").strip()
            env_enabled = os.environ.get("UNPACK_AI_ENABLED")

            provider = str(stored.get("provider") or env_provider or "openai").strip().lower()
            if provider not in PROVIDER_PRESETS:
                provider = "custom"
            preset = _get_preset(provider)

            base_url = str(stored.get("base_url") or env_base_url or preset["base_url"]).strip()
            model = str(stored.get("model") or env_model or preset["default_model"]).strip()
            api_key = str(stored.get("api_key") or env_api_key or "").strip()

            if "enabled" in stored:
                enabled = bool(stored["enabled"])
            else:
                enabled = _parse_bool_env(env_enabled, default=True)

            return AIConfig(
                enabled=enabled,
                provider=provider,
                base_url=base_url,
                api_key=api_key,
                model=model,
                temperature=float(stored.get("temperature", DEFAULT_TEMPERATURE)),
                max_tokens=int(stored.get("max_tokens", DEFAULT_MAX_TOKENS)),
                timeout_seconds=float(stored.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
                extra_headers=dict(stored.get("extra_headers") or {}),
            )

    def save(
        self,
        config: AIConfig | dict[str, Any],
        *,
        clear_api_key: bool = False,
    ) -> AIConfig:
        """Persist configuration atomically with ``0o600`` permissions on POSIX.

        When the incoming ``api_key`` is empty or masked (e.g. ``sk-***1234``),
        the previously stored key is preserved unless ``clear_api_key=True``.
        """
        with self._lock:
            existing_raw = self._read_raw_file()
            existing_key = str(existing_raw.get("api_key") or "").strip()

            if isinstance(config, AIConfig):
                incoming = config.to_storage_dict()
            elif isinstance(config, dict):
                incoming = dict(config)
                if "clear_api_key" in incoming and not clear_api_key:
                    clear_api_key = bool(incoming.get("clear_api_key"))
            else:
                raise ValueError("config must be an AIConfig or dict.")

            provider = str(
                incoming.get("provider") or existing_raw.get("provider") or "openai"
            ).strip().lower()
            if provider not in PROVIDER_PRESETS:
                provider = "custom"
            preset = _get_preset(provider)
            provider_changed = (
                bool(existing_raw.get("provider"))
                and str(existing_raw.get("provider")).strip().lower() != provider
            )

            if "base_url" in incoming and str(incoming["base_url"] or "").strip():
                base_url = str(incoming["base_url"]).strip()
            elif provider_changed:
                base_url = str(preset["base_url"])
            else:
                base_url = str(existing_raw.get("base_url") or preset["base_url"]).strip()

            if "model" in incoming and str(incoming["model"] or "").strip():
                model = str(incoming["model"]).strip()
            elif provider_changed:
                model = str(preset["default_model"])
            else:
                model = str(existing_raw.get("model") or preset["default_model"]).strip()

            raw_incoming_key = str(incoming.get("api_key") or "").strip()
            if clear_api_key:
                final_key = ""
            elif not raw_incoming_key or is_masked_api_key(raw_incoming_key):
                final_key = existing_key
            else:
                final_key = raw_incoming_key

            enabled = (
                bool(incoming["enabled"])
                if "enabled" in incoming and incoming["enabled"] is not None
                else bool(existing_raw.get("enabled", True))
            )
            temperature = float(
                incoming["temperature"]
                if "temperature" in incoming and incoming["temperature"] is not None
                else existing_raw.get("temperature", DEFAULT_TEMPERATURE)
            )
            max_tokens = int(
                incoming["max_tokens"]
                if "max_tokens" in incoming and incoming["max_tokens"] is not None
                else existing_raw.get("max_tokens", DEFAULT_MAX_TOKENS)
            )
            timeout_seconds = float(
                incoming["timeout_seconds"]
                if "timeout_seconds" in incoming and incoming["timeout_seconds"] is not None
                else existing_raw.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
            )
            extra_headers = (
                dict(incoming["extra_headers"])
                if "extra_headers" in incoming and isinstance(incoming["extra_headers"], dict)
                else dict(existing_raw.get("extra_headers") or {})
            )

            final_cfg = AIConfig(
                enabled=enabled,
                provider=provider,
                base_url=base_url,
                api_key=final_key,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout_seconds=timeout_seconds,
                extra_headers=extra_headers,
            )
            _atomic_write_json_secure(self.config_path, final_cfg.to_storage_dict())
            return final_cfg

    def update(self, payload: dict[str, Any], *, clear_api_key: bool = False) -> AIConfig:
        """Partial update helper — merges ``payload`` into the stored configuration."""
        return self.save(payload, clear_api_key=clear_api_key)


# ---------------------------------------------------------------------------
# Analysis Result Model
# ---------------------------------------------------------------------------


@dataclass
class AIAnalysisResult:
    id: str
    module: str
    provider: str
    model: str
    lang: str
    title: str
    summary: str
    markdown: str
    latency_ms: int
    usage: dict[str, int] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "module": self.module,
            "provider": self.provider,
            "model": self.model,
            "lang": self.lang,
            "title": self.title,
            "summary": self.summary,
            "markdown": self.markdown,
            "latency_ms": int(self.latency_ms),
            "usage": dict(self.usage),
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# HTTP Protocol Adapters (urllib.request stdlib)
# ---------------------------------------------------------------------------


def _ensure_config_ready(cfg: AIConfig, lang: str = "zh") -> None:
    norm_lang = _normalize_lang(lang)
    if not cfg.enabled:
        if norm_lang == "zh":
            raise UnpackError(
                "AI 分析功能已禁用。",
                code=ErrorCode.ENGINE_UNAVAILABLE,
                hint="请在 Studio 的 AI 设置中启用 AI 分析，或设置环境变量 UNPACK_AI_ENABLED=true。",
            )
        raise UnpackError(
            "AI analysis is disabled.",
            code=ErrorCode.ENGINE_UNAVAILABLE,
            hint="Enable AI analysis in Studio AI Settings or set UNPACK_AI_ENABLED=true.",
        )
    if not cfg.base_url:
        if norm_lang == "zh":
            raise UnpackError(
                f"AI 提供商 '{cfg.provider}' 未配置接口地址 (base_url)。",
                code=ErrorCode.ENGINE_UNAVAILABLE,
                hint="请在 Studio AI 设置中填写 Base URL，或设置环境变量 UNPACK_AI_BASE_URL。",
            )
        raise UnpackError(
            f"AI provider '{cfg.provider}' is missing a base_url.",
            code=ErrorCode.ENGINE_UNAVAILABLE,
            hint="Configure Base URL in Studio AI Settings or set UNPACK_AI_BASE_URL.",
        )
    if not cfg.model:
        if norm_lang == "zh":
            raise UnpackError(
                f"AI 提供商 '{cfg.provider}' 未配置模型名称 (model)。",
                code=ErrorCode.ENGINE_UNAVAILABLE,
                hint="请在 Studio AI 设置中选择或输入模型名称，或设置环境变量 UNPACK_AI_MODEL。",
            )
        raise UnpackError(
            f"AI provider '{cfg.provider}' is missing a model name.",
            code=ErrorCode.ENGINE_UNAVAILABLE,
            hint="Select or enter a model in Studio AI Settings or set UNPACK_AI_MODEL.",
        )
    if cfg.requires_api_key and not cfg.api_key:
        if norm_lang == "zh":
            raise UnpackError(
                f"AI 提供商 '{cfg.provider}' 尚未配置 API Key。",
                code=ErrorCode.ENGINE_UNAVAILABLE,
                hint=(
                    "请在 Studio 的 AI 设置中配置 API Key、设置环境变量 UNPACK_AI_API_KEY，"
                    "或切换为本地 Ollama（无需 API Key）。"
                ),
            )
        raise UnpackError(
            f"AI provider '{cfg.provider}' requires an API key.",
            code=ErrorCode.ENGINE_UNAVAILABLE,
            hint=(
                "Configure an API key in Studio AI Settings, set UNPACK_AI_API_KEY, "
                "or switch to local Ollama (no API key required)."
            ),
        )


def _extract_error_detail(raw_body: bytes, api_key: str = "") -> str:
    text = raw_body[:4096].decode("utf-8", errors="replace").strip()
    detail = text
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            err = parsed.get("error")
            if isinstance(err, dict):
                detail = str(err.get("message") or err.get("type") or text)
            elif isinstance(err, str):
                detail = err
            elif parsed.get("message"):
                detail = str(parsed["message"])
    except (ValueError, json.JSONDecodeError):
        pass
    if api_key and api_key in detail:
        detail = detail.replace(api_key, mask_api_key(api_key))
    return detail[:400]


def _http_error_hint(status: int, provider: str, lang: str) -> str:
    zh = _normalize_lang(lang) == "zh"
    if status in (401, 403):
        return (
            "API Key 无效或权限不足，请检查密钥与模型访问权限。"
            if zh
            else "Invalid or unauthorized API key. Verify your key and model permissions."
        )
    if status == 404:
        return (
            f"接口地址或模型名称不存在，请检查 {provider} 的 Base URL 和 Model 配置。"
            if zh
            else f"Endpoint or model not found. Verify Base URL and model name for {provider}."
        )
    if status == 429:
        return (
            "请求频率超限或额度不足，请稍后重试或切换模型/提供商。"
            if zh
            else "Rate limit exceeded or insufficient quota. Retry later or switch provider/model."
        )
    if status >= 500:
        return (
            "AI 服务端暂时不可用，请稍后重试。"
            if zh
            else "AI provider server error. Retry shortly."
        )
    return (
        "请检查 AI 提供商配置与请求参数。"
        if zh
        else "Verify AI provider configuration and request parameters."
    )


def _build_provider_request(
    cfg: AIConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int | None = None,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    toks = max_tokens if max_tokens is not None else cfg.max_tokens
    protocol = cfg.protocol
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "UNPACK-Studio/1.0",
    }
    headers.update(cfg.extra_headers)

    if protocol == "anthropic":
        url = f"{cfg.base_url}/messages"
        headers["x-api-key"] = cfg.api_key
        headers.setdefault("anthropic-version", "2023-06-01")
        body = {
            "model": cfg.model,
            "max_tokens": toks,
            "temperature": cfg.temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        return url, headers, body

    if protocol == "gemini":
        encoded_model = urllib.parse.quote(cfg.model, safe="")
        url = f"{cfg.base_url}/models/{encoded_model}:generateContent"
        if cfg.api_key:
            headers["x-goog-api-key"] = cfg.api_key
        body = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": cfg.temperature,
                "maxOutputTokens": toks,
            },
        }
        return url, headers, body

    # Default: OpenAI-compatible chat/completions (openai, deepseek, qwen, ollama, custom)
    url = f"{cfg.base_url}/chat/completions"
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    body = {
        "model": cfg.model,
        "temperature": cfg.temperature,
        "max_tokens": toks,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    return url, headers, body


def _parse_provider_response(protocol: str, data: dict[str, Any]) -> tuple[str, dict[str, int]]:
    if protocol == "anthropic":
        blocks = data.get("content") or []
        parts: list[str] = []
        if isinstance(blocks, list):
            for blk in blocks:
                if isinstance(blk, dict) and blk.get("type") == "text":
                    parts.append(str(blk.get("text") or ""))
                elif isinstance(blk, str):
                    parts.append(blk)
        text = "\n".join(p for p in parts if p).strip()
        raw_usage = data.get("usage") or {}
        prompt_tok = int(raw_usage.get("input_tokens") or 0)
        comp_tok = int(raw_usage.get("output_tokens") or 0)
        usage = {
            "prompt_tokens": prompt_tok,
            "completion_tokens": comp_tok,
            "total_tokens": prompt_tok + comp_tok,
        }
        return text, usage

    if protocol == "gemini":
        candidates = data.get("candidates") or []
        parts = []
        if isinstance(candidates, list) and candidates:
            content = candidates[0].get("content") or {}
            for part in content.get("parts") or []:
                if isinstance(part, dict) and "text" in part:
                    parts.append(str(part["text"] or ""))
        text = "\n".join(p for p in parts if p).strip()
        meta = data.get("usageMetadata") or {}
        prompt_tok = int(meta.get("promptTokenCount") or 0)
        comp_tok = int(meta.get("candidatesTokenCount") or 0)
        total_tok = int(meta.get("totalTokenCount") or (prompt_tok + comp_tok))
        usage = {
            "prompt_tokens": prompt_tok,
            "completion_tokens": comp_tok,
            "total_tokens": total_tok,
        }
        return text, usage

    # OpenAI-compatible
    choices = data.get("choices") or []
    text = ""
    if isinstance(choices, list) and choices:
        msg = choices[0].get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            text = content.strip()
        elif isinstance(content, list):
            chunks = [
                str(c.get("text") or "")
                for c in content
                if isinstance(c, dict) and c.get("type") in ("text", "output_text", None)
            ]
            text = "\n".join(c for c in chunks if c).strip()
        elif isinstance(choices[0].get("text"), str):
            text = choices[0]["text"].strip()
    raw_usage = data.get("usage") or {}
    prompt_tok = int(raw_usage.get("prompt_tokens") or 0)
    comp_tok = int(raw_usage.get("completion_tokens") or 0)
    total_tok = int(raw_usage.get("total_tokens") or (prompt_tok + comp_tok))
    usage = {
        "prompt_tokens": prompt_tok,
        "completion_tokens": comp_tok,
        "total_tokens": total_tok,
    }
    return text, usage


def _invoke_chat_completion(
    cfg: AIConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    lang: str = "zh",
    max_tokens: int | None = None,
) -> tuple[str, dict[str, int], int]:
    """Execute a chat completion request via stdlib ``urllib.request``."""
    _ensure_config_ready(cfg, lang=lang)
    url, headers, body = _build_provider_request(
        cfg,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        max_tokens=max_tokens,
    )
    payload_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=payload_bytes, headers=headers, method="POST")

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        err_body = b""
        try:
            err_body = exc.read()
        except Exception:
            pass
        detail = _extract_error_detail(err_body, api_key=cfg.api_key)
        raise UnpackError(
            f"AI provider HTTP {exc.code}: {detail or exc.reason}",
            code=ErrorCode.ENGINE_UNAVAILABLE,
            hint=_http_error_hint(exc.code, cfg.provider, lang),
            details={"provider": cfg.provider, "model": cfg.model, "status": exc.code},
        ) from exc
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        reason = str(getattr(exc, "reason", exc))
        if cfg.api_key and cfg.api_key in reason:
            reason = reason.replace(cfg.api_key, mask_api_key(cfg.api_key))
        zh = _normalize_lang(lang) == "zh"
        if cfg.provider == "ollama":
            hint = (
                "无法连接本地 Ollama 服务，请先运行 `ollama serve` 并确认已拉取目标模型。"
                if zh
                else "Cannot connect to local Ollama. Run `ollama serve` and ensure the model is pulled."
            )
        else:
            hint = (
                "网络请求失败或超时，请检查 Base URL、代理设置及网络连通性。"
                if zh
                else "Network request failed or timed out. Check Base URL, proxy settings, and connectivity."
            )
        raise UnpackError(
            f"AI request failed ({cfg.provider}): {reason}",
            code=ErrorCode.ENGINE_UNAVAILABLE,
            hint=hint,
            details={"provider": cfg.provider, "model": cfg.model},
        ) from exc

    latency_ms = int(round((time.monotonic() - t0) * 1000))
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise UnpackError(
            f"AI provider returned invalid JSON ({cfg.provider}).",
            code=ErrorCode.ENGINE_UNAVAILABLE,
            hint="Verify the configured Base URL points to a valid API endpoint.",
        ) from exc

    if not isinstance(parsed, dict):
        raise UnpackError(
            f"AI provider returned unexpected response payload ({cfg.provider}).",
            code=ErrorCode.ENGINE_UNAVAILABLE,
        )

    text, usage = _parse_provider_response(cfg.protocol, parsed)
    if not text:
        raise UnpackError(
            f"AI provider returned an empty response ({cfg.provider}/{cfg.model}).",
            code=ErrorCode.ENGINE_UNAVAILABLE,
            hint="Try increasing max_tokens or switching to another model.",
        )
    return text, usage, latency_ms


# ---------------------------------------------------------------------------
# Connectivity Test
# ---------------------------------------------------------------------------


def test_connection(
    config: AIConfig | dict[str, Any] | None = None,
    *,
    config_store: AIConfigStore | None = None,
    lang: str = "zh",
) -> dict[str, Any]:
    """Verify AI provider connectivity with a minimal prompt."""
    if config is None:
        cfg = (config_store or AIConfigStore()).load()
    elif isinstance(config, dict):
        cfg = AIConfig.from_dict(config)
    else:
        cfg = config

    try:
        reply, _usage, latency_ms = _invoke_chat_completion(
            cfg,
            system_prompt="You are a connectivity probe. Reply briefly.",
            user_prompt="Reply with 'OK' to confirm connectivity.",
            lang=lang,
            max_tokens=32,
        )
        return {
            "ok": True,
            "provider": cfg.provider,
            "model": cfg.model,
            "latency_ms": latency_ms,
            "reply_preview": reply[:200],
            "error": "",
            "hint": "",
        }
    except UnpackError as exc:
        return {
            "ok": False,
            "provider": cfg.provider,
            "model": cfg.model,
            "latency_ms": 0,
            "reply_preview": "",
            "error": exc.message,
            "hint": exc.hint,
        }


test_connection.__test__ = False  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Compact Context Serialization (Token-Budget Safe)
# ---------------------------------------------------------------------------


def _truncate_str(text: Any, max_len: int = 300) -> str:
    s = str(text or "")
    if len(s) <= max_len:
        return s
    return s[: max(0, max_len - 15)] + "... [truncated]"


def _compact_value(value: Any, *, max_depth: int = 5, max_items: int = 30, max_str: int = 300) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _truncate_str(value, max_str)
    if max_depth <= 0:
        return _truncate_str(value, 120)
    if isinstance(value, list):
        out = [
            _compact_value(v, max_depth=max_depth - 1, max_items=max_items, max_str=max_str)
            for v in value[:max_items]
        ]
        if len(value) > max_items:
            out.append(f"... ({len(value) - max_items} more items omitted)")
        return out
    if isinstance(value, dict):
        out_dict: dict[str, Any] = {}
        keys = list(value.keys())
        for k in keys[:max_items]:
            out_dict[str(k)] = _compact_value(
                value[k],
                max_depth=max_depth - 1,
                max_items=max_items,
                max_str=max_str,
            )
        if len(keys) > max_items:
            out_dict["_omitted_keys"] = len(keys) - max_items
        return out_dict
    return _truncate_str(value, max_str)


def _dump_budgeted_json(obj: Any, max_chars: int = DEFAULT_MAX_CONTEXT_CHARS) -> str:
    text = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    if len(text) <= max_chars:
        return text
    # Try compact JSON without indentation before hard truncation
    compact = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str)
    if len(compact) <= max_chars:
        return compact
    notice = "\n... [context truncated to fit token budget]"
    cut = max(200, max_chars - len(notice))
    return compact[:cut] + notice


def _serialize_scan_context(
    scan: dict[str, Any],
    inspect: dict[str, Any] | None,
    max_chars: int,
) -> str:
    ctx: dict[str, Any] = {
        "scan": {
            "packer_name": scan.get("packer_name"),
            "packer_version": scan.get("packer_version"),
            "protection_level": scan.get("protection_level"),
            "confidence": scan.get("confidence"),
            "risk_score": scan.get("risk_score"),
            "recommended_engine": scan.get("recommended_engine"),
            "recommended_flags": scan.get("recommended_flags"),
            "strategy_reason": scan.get("strategy_reason"),
            "details": _truncate_str(scan.get("details"), 500),
            "evidence": _compact_value(scan.get("evidence") or [], max_items=25, max_str=220),
            "score_breakdown": _compact_value(scan.get("score_breakdown") or [], max_items=20),
            "matched_files": _compact_value(scan.get("matched_files") or [], max_items=25, max_str=160),
        }
    }
    if inspect:
        sec_libs = [
            lib
            for lib in (inspect.get("native_libs") or [])
            if isinstance(lib, dict) and lib.get("security_indicators")
        ]
        ctx["inspect_summary"] = {
            "file": inspect.get("file"),
            "size_bytes": inspect.get("size_bytes"),
            "manifest": _compact_value(inspect.get("manifest") or {}, max_items=20),
            "dex_files": _compact_value(inspect.get("dex_files") or [], max_items=15),
            "native_lib_count": len(inspect.get("native_libs") or []),
            "security_native_libs": _compact_value(sec_libs, max_items=20),
            "suspicious_assets": _compact_value(inspect.get("suspicious_assets") or [], max_items=20),
            "risk_score": inspect.get("risk_score"),
            "risk_grade": inspect.get("risk_grade"),
        }
    return _dump_budgeted_json(ctx, max_chars=max_chars)


def _serialize_method_context(
    disasm: dict[str, Any],
    class_name: str,
    max_chars: int,
) -> str:
    raw_insns = disasm.get("instructions") or []
    formatted_insns: list[str] = []
    for ins in raw_insns[:140]:
        if isinstance(ins, dict):
            off = ins.get("offset") or ins.get("offset_hex") or ""
            mnem = ins.get("mnemonic") or ""
            op = ins.get("operand") or ins.get("operands") or ins.get("resolved_ref") or ""
            line = f"{off}: {mnem} {op}".strip()
            formatted_insns.append(_truncate_str(line, 200))
        else:
            formatted_insns.append(_truncate_str(ins, 200))
    if len(raw_insns) > 140:
        formatted_insns.append(f"... ({len(raw_insns) - 140} more instructions omitted)")

    ctx = {
        "class_name": class_name or disasm.get("class_name") or "",
        "method_name": disasm.get("method_name") or disasm.get("name") or "",
        "method_idx": disasm.get("method_idx"),
        "registers_size": disasm.get("registers_size"),
        "insns_size": disasm.get("insns_size"),
        "truncated": bool(disasm.get("truncated")) or len(raw_insns) > 140,
        "note": disasm.get("note") or "",
        "instructions": formatted_insns,
    }
    return _dump_budgeted_json(ctx, max_chars=max_chars)


def _serialize_vmp_native_context(
    vmp: dict[str, Any] | None,
    native_libs: list[dict[str, Any]] | None,
    xref: dict[str, Any] | None,
    max_chars: int,
) -> str:
    ctx: dict[str, Any] = {}
    if vmp:
        ctx["vmp"] = {
            "dex": vmp.get("dex"),
            "total_methods": vmp.get("total_methods"),
            "normal_count": vmp.get("normal_count"),
            "nop_count": vmp.get("nop_count"),
            "vmp_count": vmp.get("vmp_count"),
            "vmp_ratio": vmp.get("vmp_ratio"),
            "risk_score": vmp.get("risk_score"),
            "verdict": vmp.get("verdict"),
            "dispatchers": _compact_value(vmp.get("dispatchers") or [], max_items=25),
            "class_density": _compact_value(vmp.get("class_density") or [], max_items=25),
            "sample_vmp_methods": _compact_value(vmp.get("vmp_methods") or [], max_items=25),
        }
    if native_libs is not None:
        # Prioritize libraries with security indicators or hardening findings
        prioritized = sorted(
            [lib for lib in native_libs if isinstance(lib, dict)],
            key=lambda x: (
                0 if x.get("security_indicators") else 1,
                -int(x.get("size_bytes") or 0),
            ),
        )
        ctx["native_libs"] = {
            "total_count": len(native_libs),
            "libraries": _compact_value(prioritized, max_items=30, max_str=180),
        }
    if xref:
        ctx["xref"] = {
            "counts": xref.get("counts"),
            "reflection_calls": _compact_value(xref.get("reflection_calls") or [], max_items=25),
            "sensitive_apis": _compact_value(xref.get("sensitive_apis") or [], max_items=25),
            "iocs": _compact_value(xref.get("iocs") or {}, max_items=25, max_str=160),
            "top_strings": _compact_value(xref.get("top_strings") or [], max_items=20, max_str=160),
        }
    return _dump_budgeted_json(ctx, max_chars=max_chars)


def _serialize_security_context(
    inspect: dict[str, Any],
    findings: list[dict[str, Any]] | None,
    max_chars: int,
) -> str:
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings = list(findings if findings is not None else (inspect.get("findings") or []))
    all_findings.sort(
        key=lambda f: sev_rank.get(str((f or {}).get("severity", "info")).lower(), 5)
        if isinstance(f, dict)
        else 5
    )

    perms = inspect.get("permissions") or []
    dangerous_perms = [
        p for p in perms if isinstance(p, dict) and str(p.get("level", "")).lower() == "dangerous"
    ]
    components = inspect.get("components") or {}
    exported_summary: dict[str, list[str]] = {}
    if isinstance(components, dict):
        for ctype, items in components.items():
            if isinstance(items, list):
                exported = [
                    str(c.get("name"))
                    for c in items
                    if isinstance(c, dict) and c.get("exported")
                ]
                if exported:
                    exported_summary[ctype] = exported[:20]

    ctx = {
        "file": inspect.get("file"),
        "sha256": inspect.get("sha256"),
        "risk_score": inspect.get("risk_score"),
        "risk_grade": inspect.get("risk_grade"),
        "manifest": _compact_value(inspect.get("manifest") or {}, max_items=20),
        "signing": _compact_value(inspect.get("signing") or {}, max_items=10),
        "permissions_total": len(perms),
        "dangerous_permissions": _compact_value(dangerous_perms, max_items=30),
        "exported_components": exported_summary,
        "findings_total": len(all_findings),
        "findings": _compact_value(all_findings, max_items=40, max_str=260),
        "suspicious_assets": _compact_value(inspect.get("suspicious_assets") or [], max_items=20),
    }
    return _dump_budgeted_json(ctx, max_chars=max_chars)


def _serialize_pipeline_context(
    stage: dict[str, Any],
    error_text: str,
    doctor: dict[str, Any] | None,
    max_chars: int,
) -> str:
    ctx: dict[str, Any] = {
        "stage": _compact_value(stage, max_items=25, max_str=300),
        "error_text": _truncate_str(error_text, 2500),
    }
    if doctor:
        ctx["doctor"] = {
            "overall_status": doctor.get("overall_status"),
            "python_version": doctor.get("python_version"),
            "unpack_version": doctor.get("unpack_version"),
            "checks": _compact_value(doctor.get("checks") or [], max_items=25),
            "devices": _compact_value(doctor.get("devices") or [], max_items=10),
            "engines": _compact_value(doctor.get("engines") or [], max_items=10),
        }
    return _dump_budgeted_json(ctx, max_chars=max_chars)


def _extract_summary(markdown: str, fallback: str = "") -> str:
    for line in (markdown or "").splitlines():
        cleaned = line.strip().lstrip("#").strip()
        if not cleaned or cleaned.startswith("```") or cleaned.startswith("|") or cleaned.startswith("---"):
            continue
        cleaned = cleaned.lstrip("-*• ").strip()
        if cleaned:
            return cleaned[:220]
    return fallback[:220]


# ---------------------------------------------------------------------------
# Prompts (Bilingual zh / en)
# ---------------------------------------------------------------------------


_SYSTEM_PROMPTS: dict[str, dict[str, str]] = {
    "scan": {
        "zh": (
            "你是资深 Android 逆向工程与加壳对抗专家。请基于给定的 APK 加壳扫描与静态摘要，"
            "使用清晰、专业、可落地的中文 Markdown 输出分析报告，包含：\n"
            "1. **加壳判定依据**（解读命中的证据、保护等级与置信度，指出可能误报或隐藏保护层）\n"
            "2. **脱壳与绕过作战手册 (Playbook)**（推荐引擎、具体 `unpack` CLI 命令参数、反检测/Frida/内存转储步骤）\n"
            "3. **优先风险与后续验证要点**（需要重点检查的 SO、VMP、壳入口与修复步骤）。\n"
            "仅基于提供的数据推理，不要编造未出现的类名或文件名。"
        ),
        "en": (
            "You are a senior Android reverse-engineering and packer-defeat specialist. "
            "Based on the provided APK scan and static inspection telemetry, produce a concise, "
            "actionable Markdown report covering:\n"
            "1. **Packer Identification Rationale** (evidence breakdown, protection level, confidence, possible hidden layers)\n"
            "2. **Unpack & Bypass Playbook** (recommended engine, exact `unpack` CLI flags, anti-detection/Frida/memory dump steps)\n"
            "3. **Priority Risks & Verification Checklist** (native SOs, VMP/DEX2C indicators, repair verification).\n"
            "Ground every claim in the provided telemetry; do not fabricate symbols or filenames."
        ),
    },
    "method": {
        "zh": (
            "你是资深 Dalvik/ART 字节码逆向专家。请分析给定的反汇编指令流，输出中文 Markdown：\n"
            "1. **行为摘要**（1-3 句话概括该方法的核心意图与副作用）\n"
            "2. **Java/Kotlin 伪代码还原**（用干净、带注释的 Java/Kotlin 代码块还原核心控制流与调用逻辑）\n"
            "3. **混淆与对抗指标**（指出是否存在 VMP 桩、反射隐藏、动态加载、加解密、反调试或 NOP 抽取迹象）。\n"
            "对于截断或不完整的字节码，请明确标注不确定处，不要臆造。"
        ),
        "en": (
            "You are a senior Dalvik/ART bytecode reverse engineer. Analyze the provided disassembly "
            "and return clean Markdown with:\n"
            "1. **Behavior Summary** (1-3 sentences describing intent and side effects)\n"
            "2. **Java/Kotlin Pseudocode Reconstruction** (readable, commented Java/Kotlin code block)\n"
            "3. **Obfuscation & Anti-Analysis Indicators** (VMP stubbing, reflection, dynamic class loading, crypto, NOP extraction).\n"
            "Explicitly flag any truncated or uncertain sections instead of guessing."
        ),
    },
    "vmp_native": {
        "zh": (
            "你是资深 Android VMP 虚拟化与 Native ELF 逆向专家。请综合 VMP 桩统计、Native SO 列表与交叉引用/IOC 数据，"
            "输出中文 Markdown 研判报告：\n"
            "1. **VMP 桩分级与调度器研判**（评估虚拟化覆盖率、核心调度入口与静态还原可行性）\n"
            "2. **Native ELF 加固与符号分析**（PIE/架构/安全壳 SO 识别、建议重点用 IDA/Ghidra 分析的库）\n"
            "3. **IOC 与反射/敏感 API 汇点风险结论**（评估 URL/IP、动态加载、反射调用与敏感权限风险等级）。"
        ),
        "en": (
            "You are a senior Android VMP virtualization and Native ELF reverse engineer. "
            "Synthesize the VMP stub telemetry, native ELF inventory, and xref/IOC signals into Markdown:\n"
            "1. **VMP Stub Triage** (virtualization coverage, dispatcher clustering, static vs dynamic recovery feasibility)\n"
            "2. **Native ELF Hardening & Symbol Analysis** (PIE/ABI posture, protector SOs, priority binaries for IDA/Ghidra)\n"
            "3. **IOC & Reflection/Sensitive-API Sink Risk Verdict** (URL/IP indicators, dynamic loading, reflection sinks, overall risk)."
        ),
    },
    "security": {
        "zh": (
            "你是资深移动应用安全架构师与红队评估专家。请基于 APK 静态检测与安全发现列表，"
            "输出商业级中文 Markdown 安全评估报告：\n"
            "1. **管理层安全态势摘要**（总体风险评级、最紧迫的 Top 3 风险）\n"
            "2. **可利用攻击路径推演**（结合 Manifest 配置、导出组件、危险权限、签名与明文传输串联真实攻击链）\n"
            "3. **可落地的分优先级修复建议**（给出具体 AndroidManifest/代码/构建加固修改方案）。"
        ),
        "en": (
            "You are a principal mobile application security architect and red-team specialist. "
            "Based on the APK inspection and security findings, deliver a commercial-grade Markdown assessment:\n"
            "1. **Executive Security Posture** (overall grade and top 3 urgent exposures)\n"
            "2. **Exploitable Attack Paths** (chain manifest flags, exported components, dangerous permissions, signing, and cleartext settings)\n"
            "3. **Prioritized Concrete Fixes** (specific AndroidManifest, code, and build-hardening remediations)."
        ),
    },
    "pipeline_issue": {
        "zh": (
            "你是 UNPACK 脱壳流水线与 Android 调试排障专家。请结合失败阶段信息、错误日志与 `unpack doctor` 环境诊断，"
            "输出中文 Markdown 排障方案：\n"
            "1. **根因定位**（明确指出是设备/Root/Frida/依赖/DEX 损坏还是目标反调试导致）\n"
            "2. **分步恢复命令**（给出可直接复制执行的排查与修复命令）\n"
            "3. **替代方案与预防建议**（如切换引擎或增加参数）。"
        ),
        "en": (
            "You are an UNPACK pipeline and Android instrumentation troubleshooting specialist. "
            "Using the failed stage details, error output, and `unpack doctor` diagnostics, output Markdown:\n"
            "1. **Root Cause Diagnosis** (pinpoint device, root, Frida, missing tool, corrupt DEX, or anti-debug cause)\n"
            "2. **Step-by-Step Recovery Commands** (copy-pasteable verification and fix commands)\n"
            "3. **Fallback Strategy** (alternative engine/flags to unblock the workflow)."
        ),
    },
}

_TITLES: dict[str, dict[str, str]] = {
    "scan": {"zh": "加壳识别与脱壳策略 AI 分析", "en": "AI Packer & Unpack Strategy Analysis"},
    "method": {"zh": "Dalvik 方法反汇编与伪代码还原", "en": "AI Method Reconstruction & Deobfuscation"},
    "vmp_native": {"zh": "VMP 虚拟化与 Native/IOC 综合研判", "en": "AI VMP, Native ELF & IOC Triage"},
    "security": {"zh": "APK 安全态势与攻击路径评估", "en": "AI Security Posture & Attack-Path Assessment"},
    "pipeline_issue": {"zh": "流水线故障根因诊断与修复建议", "en": "AI Pipeline Failure Diagnosis & Recovery"},
}


# ---------------------------------------------------------------------------
# AIAnalyzer
# ---------------------------------------------------------------------------


class AIAnalyzer:
    """Domain-expert bilingual AI analyzer for UNPACK reverse-engineering modules."""

    def __init__(
        self,
        config: AIConfig | dict[str, Any] | None = None,
        *,
        config_store: AIConfigStore | None = None,
        max_context_chars: int = DEFAULT_MAX_CONTEXT_CHARS,
    ) -> None:
        self._explicit_config: AIConfig | None
        if config is None:
            self._explicit_config = None
        elif isinstance(config, dict):
            self._explicit_config = AIConfig.from_dict(config)
        else:
            self._explicit_config = config
        self._config_store = config_store or AIConfigStore()
        self.max_context_chars = max(1000, int(max_context_chars))

    def get_config(self) -> AIConfig:
        if self._explicit_config is not None:
            return self._explicit_config
        return self._config_store.load()

    def _run_module(
        self,
        *,
        module: str,
        context_text: str,
        lang: str,
        title_suffix: str = "",
    ) -> AIAnalysisResult:
        norm_lang = _normalize_lang(lang)
        cfg = self.get_config()
        sys_prompt = _SYSTEM_PROMPTS[module][norm_lang]
        if norm_lang == "zh":
            user_prompt = (
                f"以下是 UNPACK 模块 `{module}` 采集到的结构化上下文数据（JSON）：\n\n"
                f"```json\n{context_text}\n```\n\n"
                "请严格依据以上数据输出专业分析报告。"
            )
        else:
            user_prompt = (
                f"Below is the structured telemetry from UNPACK module `{module}` (JSON):\n\n"
                f"```json\n{context_text}\n```\n\n"
                "Provide your expert analysis grounded strictly in the telemetry above."
            )

        markdown, usage, latency_ms = _invoke_chat_completion(
            cfg,
            system_prompt=sys_prompt,
            user_prompt=user_prompt,
            lang=norm_lang,
        )
        base_title = _TITLES[module][norm_lang]
        title = f"{base_title} — {title_suffix}" if title_suffix else base_title
        summary = _extract_summary(markdown, fallback=title)
        return AIAnalysisResult(
            id=f"ai_{uuid.uuid4().hex[:12]}",
            module=module,
            provider=cfg.provider,
            model=cfg.model,
            lang=norm_lang,
            title=title,
            summary=summary,
            markdown=markdown,
            latency_ms=latency_ms,
            usage=usage,
            created_at=_utc_now_iso(),
        )

    def analyze_scan(
        self,
        scan: dict[str, Any],
        inspect: dict[str, Any] | None = None,
        lang: str = "zh",
    ) -> AIAnalysisResult:
        """Analyze packer scan telemetry and recommend an unpack/bypass playbook."""
        ctx = _serialize_scan_context(scan or {}, inspect, self.max_context_chars)
        suffix = str((scan or {}).get("packer_name") or (inspect or {}).get("file") or "")
        return self._run_module(
            module="scan",
            context_text=ctx,
            lang=lang,
            title_suffix=suffix,
        )

    def analyze_method(
        self,
        disasm: dict[str, Any],
        class_name: str = "",
        lang: str = "zh",
    ) -> AIAnalysisResult:
        """Reconstruct Dalvik method disassembly into Java/Kotlin pseudocode and triage indicators."""
        ctx = _serialize_method_context(disasm or {}, class_name, self.max_context_chars)
        cls_label = class_name or str((disasm or {}).get("class_name") or "")
        meth_label = str((disasm or {}).get("method_name") or (disasm or {}).get("name") or "")
        suffix = f"{cls_label}.{meth_label}".strip(".")
        return self._run_module(
            module="method",
            context_text=ctx,
            lang=lang,
            title_suffix=suffix,
        )

    def analyze_vmp_native(
        self,
        vmp: dict[str, Any] | None = None,
        native_libs: list[dict[str, Any]] | None = None,
        xref: dict[str, Any] | None = None,
        lang: str = "zh",
    ) -> AIAnalysisResult:
        """Triage VMP stubs, native ELF hardening/symbols, and xref/IOC sinks."""
        ctx = _serialize_vmp_native_context(vmp, native_libs, xref, self.max_context_chars)
        suffix = str((vmp or {}).get("dex") or "")
        return self._run_module(
            module="vmp_native",
            context_text=ctx,
            lang=lang,
            title_suffix=suffix,
        )

    def analyze_security(
        self,
        inspect: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
        lang: str = "zh",
    ) -> AIAnalysisResult:
        """Produce an executive security posture, attack-path, and remediation assessment."""
        ctx = _serialize_security_context(inspect or {}, findings, self.max_context_chars)
        suffix = str((inspect or {}).get("file") or "")
        return self._run_module(
            module="security",
            context_text=ctx,
            lang=lang,
            title_suffix=suffix,
        )

    def analyze_pipeline_issue(
        self,
        stage: dict[str, Any],
        error_text: str = "",
        doctor: dict[str, Any] | None = None,
        lang: str = "zh",
    ) -> AIAnalysisResult:
        """Diagnose a pipeline failure and provide step-by-step recovery commands."""
        ctx = _serialize_pipeline_context(stage or {}, error_text, doctor, self.max_context_chars)
        suffix = str((stage or {}).get("name") or (stage or {}).get("stage") or "")
        return self._run_module(
            module="pipeline_issue",
            context_text=ctx,
            lang=lang,
            title_suffix=suffix,
        )


__all__ = [
    "PROVIDER_PRESETS",
    "DEFAULT_MAX_CONTEXT_CHARS",
    "list_provider_presets",
    "mask_api_key",
    "is_masked_api_key",
    "AIConfig",
    "AIConfigStore",
    "AIAnalysisResult",
    "test_connection",
    "AIAnalyzer",
]
