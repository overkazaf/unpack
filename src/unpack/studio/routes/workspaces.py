"""Persistent workspace CRUD, session history, and JSON export/import routes."""

from __future__ import annotations

import json

from flask import Blueprint, Response, jsonify, request

from unpack.studio.routes import get_ctx
from unpack.studio.schemas import (
    MAX_WORKSPACE_IMPORT_BYTES,
    api_error,
    parse_bool,
    parse_int,
)
from unpack.studio.security import safe_filename

bp = Blueprint("studio_workspaces", __name__)


@bp.get("/api/v1/workspaces")
def api_v1_workspaces_list():
    ctx = get_ctx()
    return jsonify(
        active_workspace_id=ctx.active_ws_id(),
        workspaces=ctx.ws_store.list_workspaces(),
    )


@bp.post("/api/v1/workspaces")
def api_v1_workspaces_create():
    ctx = get_ctx()
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()
    if not name:
        return api_error("Workspace name cannot be empty", "BAD_REQUEST", 400)
    try:
        ws = ctx.ws_store.create_workspace(
            name=name,
            description=str(body.get("description") or ""),
            tags=body.get("tags"),
            notes=str(body.get("notes") or ""),
            pinned=parse_bool(body.get("pinned"), default=False),
        )
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)
    if parse_bool(body.get("activate"), default=False):
        ctx.restore_workspace_samples(ws["id"])
    return jsonify(workspace=ws, active_workspace_id=ctx.active_ws_id()), 201


@bp.get("/api/v1/workspaces/<ws_id>")
def api_v1_workspace_detail(ws_id: str):
    ctx = get_ctx()
    ws = ctx.ws_store.get_workspace(ws_id)
    if ws is None:
        return api_error("Workspace not found", "NOT_FOUND", 404)
    if parse_bool(request.args.get("activate"), default=False):
        ctx.restore_workspace_samples(ws_id)
    return jsonify(workspace=ws, active_workspace_id=ctx.active_ws_id())


@bp.post("/api/v1/workspaces/<ws_id>/activate")
def api_v1_workspace_activate(ws_id: str):
    ctx = get_ctx()
    ws = ctx.ws_store.get_workspace(ws_id)
    if ws is None:
        return api_error("Workspace not found", "NOT_FOUND", 404)
    restored = ctx.restore_workspace_samples(ws_id)
    runs = ctx.ws_store.list_pipeline_runs(workspace_id=ws_id, limit=50)
    analyses = ctx.ws_store.list_ai_analyses(workspace_id=ws_id, limit=50)
    return jsonify(
        workspace=ws,
        active_workspace_id=ws_id,
        samples=restored,
        pipeline_runs=runs,
        ai_analyses=analyses,
    )


@bp.patch("/api/v1/workspaces/<ws_id>")
def api_v1_workspace_update(ws_id: str):
    ctx = get_ctx()
    body = request.get_json(silent=True) or {}
    try:
        updated = ctx.ws_store.update_workspace(
            ws_id,
            name=body.get("name"),
            description=body.get("description"),
            notes=body.get("notes"),
            tags=body.get("tags"),
            pinned=parse_bool(body.get("pinned")) if "pinned" in body else None,
        )
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)
    if updated is None:
        return api_error("Workspace not found", "NOT_FOUND", 404)
    return jsonify(workspace=updated)


@bp.delete("/api/v1/workspaces/<ws_id>")
def api_v1_workspace_delete(ws_id: str):
    ctx = get_ctx()
    if ws_id == ctx.default_workspace_id:
        return api_error("Cannot delete the default workspace", "BAD_REQUEST", 400)
    ok = ctx.ws_store.delete_workspace(ws_id)
    if not ok:
        return api_error("Workspace not found", "NOT_FOUND", 404)
    if ctx.active_ws_id() == ws_id:
        ctx.restore_workspace_samples(ctx.default_workspace_id)
    return jsonify(deleted=True, id=ws_id, active_workspace_id=ctx.active_ws_id())


@bp.get("/api/v1/workspaces/<ws_id>/history")
def api_v1_workspace_history(ws_id: str):
    ctx = get_ctx()
    ws = ctx.ws_store.get_workspace(ws_id)
    if ws is None:
        return api_error("Workspace not found", "NOT_FOUND", 404)
    try:
        limit = parse_int(request.args.get("limit"), 50, min_val=1, max_val=200, name="limit")
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)
    saved_samples = ctx.ws_store.list_samples(workspace_id=ws_id)
    runs = ctx.ws_store.list_pipeline_runs(workspace_id=ws_id, limit=limit)
    analyses = ctx.ws_store.list_ai_analyses(workspace_id=ws_id, limit=limit)
    return jsonify(
        workspace=ws,
        samples=saved_samples,
        pipeline_runs=runs,
        ai_analyses=analyses,
    )


@bp.get("/api/v1/workspaces/<ws_id>/export")
def api_v1_workspace_export(ws_id: str):
    ctx = get_ctx()
    try:
        bundle = ctx.ws_store.export_workspace_json(ws_id)
    except KeyError:
        return api_error("Workspace not found", "NOT_FOUND", 404)
    ws_name = safe_filename(bundle["workspace"]["name"], "workspace")
    payload = json.dumps(bundle, indent=2, ensure_ascii=False)
    resp = Response(payload, mimetype="application/json; charset=utf-8")
    resp.headers["Content-Disposition"] = f'attachment; filename="{ws_name}_workspace.json"'
    return resp


@bp.post("/api/v1/workspaces/import")
def api_v1_workspace_import():
    ctx = get_ctx()
    if request.content_length and request.content_length > MAX_WORKSPACE_IMPORT_BYTES:
        mb = MAX_WORKSPACE_IMPORT_BYTES // (1024 * 1024)
        return api_error(
            f"Workspace import exceeds maximum limit ({mb} MB)",
            "PAYLOAD_TOO_LARGE",
            413,
        )

    bundle = None
    name_override = None
    if "file" in request.files and request.files["file"].filename:
        try:
            raw_bytes = request.files["file"].read(MAX_WORKSPACE_IMPORT_BYTES + 1)
            if len(raw_bytes) > MAX_WORKSPACE_IMPORT_BYTES:
                mb = MAX_WORKSPACE_IMPORT_BYTES // (1024 * 1024)
                return api_error(
                    f"Workspace import exceeds maximum limit ({mb} MB)",
                    "PAYLOAD_TOO_LARGE",
                    413,
                )
            bundle = json.loads(raw_bytes.decode("utf-8"))
            name_override = request.form.get("name") or None
        except Exception as exc:
            return api_error(f"Invalid workspace JSON file: {exc}", "BAD_REQUEST", 400)
    else:
        body = request.get_json(silent=True)
        if isinstance(body, dict) and "bundle" in body and isinstance(body["bundle"], dict):
            bundle = body["bundle"]
            name_override = body.get("name") or None
        elif isinstance(body, dict):
            bundle = body
    if not isinstance(bundle, dict):
        return api_error("Provide a workspace JSON bundle", "BAD_REQUEST", 400)
    try:
        restored = ctx.ws_store.import_workspace_json(bundle, name_override=name_override)
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)
    return jsonify(workspace=restored), 201
