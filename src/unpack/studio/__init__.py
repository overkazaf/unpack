"""UNPACK Studio — Modular Flask Web Workbench & REST/SSE API."""

from __future__ import annotations

import atexit
import os
from pathlib import Path

os.environ.setdefault("LOGURU_LEVEL", "ERROR")

from flask import Flask

import unpack as unpack_pkg
from unpack.studio.context import MAX_ARTIFACTS, MAX_DEX_CACHE, MAX_INSPECT_LOCKS, StudioContext
from unpack.studio.jobs import JobManager, MAX_JOBS_RETAINED
from unpack.studio.routes import register_blueprints
from unpack.studio.schemas import register_error_handlers
from unpack.studio.security import ALLOWED_UPLOAD_EXTS, register_security_middleware

APP_VERSION: str = getattr(unpack_pkg, "__version__", "0.1.0")


def create_app(
    local_roots: list[Path | str] | None = None,
    max_content_length: int = 512 * 1024 * 1024,
    workspace_dir: Path | str | None = None,
    *,
    max_artifacts: int = MAX_ARTIFACTS,
    max_dex_cache: int = MAX_DEX_CACHE,
    max_inspect_locks: int = MAX_INSPECT_LOCKS,
) -> Flask:
    """Create and configure the UNPACK Studio Flask application."""
    pkg_dir = Path(__file__).resolve().parents[1]
    version = getattr(unpack_pkg, "__version__", APP_VERSION)

    app = Flask(
        "unpack.web",
        template_folder=str(pkg_dir / "templates"),
        static_folder=str(pkg_dir / "static"),
        static_url_path="/static",
    )
    app.config["MAX_CONTENT_LENGTH"] = max_content_length
    app.config["JSON_SORT_KEYS"] = False
    app.config["UNPACK_VERSION"] = version

    ctx = StudioContext(
        local_roots=local_roots,
        workspace_dir=workspace_dir,
        max_artifacts=max_artifacts,
        max_dex_cache=max_dex_cache,
        max_inspect_locks=max_inspect_locks,
    )

    atexit.register(ctx.cleanup)
    app.config["UNPACK_CTX"] = ctx
    app.config["UNPACK_CLEANUP"] = ctx.cleanup
    app.config["UNPACK_WORKSPACE"] = ctx.workspace_root
    app.config["UNPACK_WS_STORE"] = ctx.ws_store
    app.config["UNPACK_AI_STORE"] = ctx.ai_config_store

    register_security_middleware(app)
    register_error_handlers(app, version)
    register_blueprints(app)
    return app


def main() -> None:
    app = create_app()
    print(f"UNPACK Studio v{APP_VERSION}: http://127.0.0.1:8080")
    app.run(host="127.0.0.1", port=8080, debug=False)


__all__ = [
    "ALLOWED_UPLOAD_EXTS",
    "APP_VERSION",
    "JobManager",
    "MAX_ARTIFACTS",
    "MAX_DEX_CACHE",
    "MAX_INSPECT_LOCKS",
    "MAX_JOBS_RETAINED",
    "StudioContext",
    "create_app",
    "main",
]
