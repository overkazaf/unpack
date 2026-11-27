"""Validation helpers, unified API error envelopes, and logging bridge."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from flask import jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from unpack.logging_config import get_logger
from unpack.utils.fs import file_sha256

if TYPE_CHECKING:
    from flask import Flask, Response

ALLOWED_ENGINES: frozenset[str] = frozenset({"", "memory", "frida", "ebpf"})
ALLOWED_START_FROM: frozenset[str] = frozenset({"scan", "scan_only", "dumping", "repairing"})
PIPELINE_MODES: tuple[str, ...] = ("offline_audit", "repair_repack", "device_standard", "device_deep")
MAX_WORKSPACE_IMPORT_BYTES: int = 10 * 1024 * 1024  # 10 MB cap for workspace JSON import


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dir_fingerprint(dir_path: Path) -> tuple[str, int, int]:
    """Compute a deterministic hash, total byte size, and dex count for a DEX dir."""
    import hashlib

    h = hashlib.sha256()
    total_size = 0
    dex_files = sorted(p for p in dir_path.glob("*.dex") if p.is_file())
    for p in dex_files:
        st = p.stat()
        total_size += st.st_size
        h.update(f"{p.name}:{st.st_size}:{int(st.st_mtime)}".encode())
    return h.hexdigest(), total_size, len(dex_files)


def normalize_lang(raw: Any) -> str:
    s = str(raw or "en").strip().lower()
    return "zh" if s.startswith("zh") else "en"


def parse_int(
    value: Any,
    default: int,
    *,
    min_val: int | None = None,
    max_val: int | None = None,
    name: str = "parameter",
) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ValueError(f"Invalid integer for '{name}': {value!r}")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid integer for '{name}': {value!r}") from exc
    if min_val is not None and parsed < min_val:
        raise ValueError(f"'{name}' must be >= {min_val}, got {parsed}")
    if max_val is not None and parsed > max_val:
        raise ValueError(f"'{name}' must be <= {max_val}, got {parsed}")
    return parsed


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return default


def validate_dex_names(raw: Any) -> list[str] | None:
    """Validate optional ``dex_names`` payload is a list of non-empty safe strings."""
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ValueError("'dex_names' must be a list of filenames")
    cleaned: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip() or "/" in item or "\\" in item or "\x00" in item:
            raise ValueError(f"Invalid DEX filename in 'dex_names': {item!r}")
        cleaned.append(item.strip())
    return cleaned


def validate_engine(raw: Any) -> str:
    engine = str(raw or "").strip().lower()
    if engine not in ALLOWED_ENGINES:
        raise ValueError(f"Invalid engine: {engine!r}. Must be one of: memory, frida, ebpf")
    return engine


def validate_start_from(raw: Any, default: str = "scan") -> str:
    val = str(raw or default).strip().lower()
    if val not in ALLOWED_START_FROM:
        raise ValueError(f"Invalid start_from: {val!r}")
    return val


def validate_pipeline_mode(raw: Any) -> str | None:
    if raw is None or raw == "":
        return None
    mode = str(raw).strip()
    if mode not in PIPELINE_MODES:
        raise ValueError(f"Invalid pipeline mode: {mode!r}")
    return mode


def api_error(
    message: str,
    code: str = "BAD_REQUEST",
    status: int = 400,
    *,
    hint: str | None = None,
    details: Any = None,
    extra: dict[str, Any] | None = None,
) -> tuple[Response, int]:
    """Return a standardized JSON error envelope while preserving legacy keys."""
    payload: dict[str, Any] = {
        "error": message,
        "code": code,
    }
    if hint:
        payload["hint"] = hint
    if details is not None:
        payload["details"] = details
    if extra:
        payload.update(extra)
    return jsonify(payload), status


def register_error_handlers(app: Flask, version: str) -> None:
    """Attach structured JSON error handlers to the Flask application."""
    logger = get_logger("unpack.studio.errors")

    @app.errorhandler(400)
    def handle_400(e):
        return api_error(str(getattr(e, "description", e)), "BAD_REQUEST", 400)

    @app.errorhandler(403)
    def handle_403(e):
        return api_error(str(getattr(e, "description", e)), "FORBIDDEN", 403)

    @app.errorhandler(404)
    def handle_404(e):
        if request.path.startswith("/api/"):
            return api_error("Not found", "NOT_FOUND", 404)
        return render_template("index.html", version=version), 404

    @app.errorhandler(413)
    def handle_413(e):
        mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return api_error(
            f"Upload exceeds maximum limit ({mb} MB)",
            "PAYLOAD_TOO_LARGE",
            413,
        )

    @app.errorhandler(500)
    def handle_500(e):
        logger.exception("Unhandled 500 error on %s", request.path)
        return api_error(str(getattr(e, "description", e)), "INTERNAL_ERROR", 500)

    @app.errorhandler(Exception)
    def handle_exception(e):
        if isinstance(e, HTTPException):
            if request.path.startswith("/api/"):
                return api_error(str(e.description), f"HTTP_{e.code}", e.code or 500)
            return e
        logger.exception("Unhandled exception on %s", request.path)
        if request.path.startswith("/api/"):
            code = getattr(e, "code", "INTERNAL_ERROR")
            if hasattr(code, "value"):
                code = code.value
            return api_error(str(e), str(code), 500)
        return render_template("index.html", version=version), 500
