"""System, UI entrypoint, health/diagnostics, doctor, and local-library routes."""

from __future__ import annotations

from typing import Any

from flask import Blueprint, Response, current_app, jsonify, render_template, request

from unpack.studio.routes import get_ctx
from unpack.studio.schemas import parse_bool
from unpack.studio.security import ALLOWED_UPLOAD_EXTS

bp = Blueprint("studio_system", __name__)


@bp.route("/")
def index():
    return render_template("index.html", version=current_app.config["UNPACK_VERSION"])


@bp.route("/favicon.ico")
def favicon():
    return Response(status=204)


@bp.get("/api/v1/health")
def api_v1_health():
    ctx = get_ctx()
    metrics = ctx.health_metrics()
    return jsonify(
        status="ok",
        app="UNPACK Studio",
        version=current_app.config["UNPACK_VERSION"],
        local_roots=[r.name for r in ctx.allowed_local_roots],
        **metrics,
    )


@bp.get("/api/v1/doctor")
def api_v1_doctor():
    ctx = get_ctx()
    check_devices = parse_bool(request.args.get("check_devices"), default=True)
    return jsonify(ctx.get_doctor_cached(check_devices=check_devices, force_refresh=check_devices))


@bp.get("/api/v1/local-library")
def api_v1_local_library():
    ctx = get_ctx()
    items: list[dict[str, Any]] = []
    for root in ctx.allowed_local_roots:
        if not root.exists():
            continue
        try:
            children = sorted(root.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            continue
        for child in children:
            if child.name.startswith("."):
                continue
            if child.is_file() and child.suffix.lower() in ALLOWED_UPLOAD_EXTS:
                sz = child.stat().st_size
                items.append(
                    {
                        "name": child.name,
                        "kind": "apk" if child.suffix.lower() == ".apk" else "dex",
                        "root": root.name,
                        "path": str(child.resolve()),
                        "display_path": f"{root.name}/{child.name}",
                        "size_bytes": sz,
                        "size_mb": round(sz / (1024 * 1024), 2),
                    }
                )
            elif child.is_dir():
                dex_files = [p for p in child.glob("*.dex") if p.is_file()]
                if dex_files:
                    total_sz = sum(p.stat().st_size for p in dex_files)
                    items.append(
                        {
                            "name": child.name,
                            "kind": "dex_dir",
                            "root": root.name,
                            "path": str(child.resolve()),
                            "display_path": f"{root.name}/{child.name}",
                            "dex_count": len(dex_files),
                            "size_bytes": total_sz,
                            "size_mb": round(total_sz / (1024 * 1024), 2),
                        }
                    )
    return jsonify(roots=[r.name for r in ctx.allowed_local_roots], items=items)
