"""Sample vault, upload, sandboxed local-library import, and analyst notes routes."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from unpack.studio.routes import get_ctx
from unpack.studio.schemas import api_error, get_logger, parse_bool
from unpack.studio.security import resolve_allowed_local_path
from unpack.studio.services.analysis import scan_apk_rich

bp = Blueprint("studio_samples", __name__)
logger = get_logger("unpack.studio.samples")


@bp.get("/api/v1/samples")
def api_v1_samples():
    ctx = get_ctx()
    with ctx.lock:
        items = [ctx.public_sample(s) for s in reversed(ctx.samples.values())]
    return jsonify(items=items)


@bp.post("/api/v1/samples/upload")
def api_v1_samples_upload():
    ctx = get_ctx()
    files = request.files.getlist("files") or request.files.getlist("file")
    files = [f for f in files if f and f.filename]
    if not files:
        return api_error("No .apk or .dex files provided", "NO_FILE", 400)

    auto_scan = parse_bool(request.form.get("auto_scan"), default=True)
    uploaded = []
    errors = []
    for f in files:
        try:
            rec = ctx.save_uploaded_file(f)
            if auto_scan and rec["kind"] == "apk" and rec["scan_result"] is None:
                try:
                    scan_dict = scan_apk_rich(rec["path"])
                    with ctx.lock:
                        rec["scan_result"] = scan_dict
                    ctx.persist_sample(rec)
                except Exception:
                    logger.debug("Auto-scan failed after upload for %s", rec["id"], exc_info=True)
            uploaded.append(ctx.public_sample(rec, include_details=True))
        except ValueError as exc:
            errors.append({"file": f.filename, "error": str(exc)})

    if not uploaded and errors:
        return api_error(errors[0]["error"], "INVALID_FILE", 400, extra={"errors": errors})
    return jsonify(items=uploaded, errors=errors), 201


@bp.post("/api/v1/samples/import-local")
def api_v1_samples_import_local():
    ctx = get_ctx()
    body = request.get_json(silent=True) or {}
    raw_path = body.get("path", "")
    auto_scan = parse_bool(body.get("auto_scan"), default=True)

    resolved = resolve_allowed_local_path(raw_path, ctx.allowed_local_roots)
    if resolved is None:
        return api_error(
            "Path is outside allowlisted local library roots or does not exist",
            "FORBIDDEN_PATH",
            403,
        )

    try:
        rec = ctx.import_local_sample(resolved)
    except ValueError as exc:
        return api_error(str(exc), "INVALID_SAMPLE", 400)

    if auto_scan and rec["kind"] == "apk" and rec["scan_result"] is None:
        try:
            scan_dict = scan_apk_rich(rec["path"])
            with ctx.lock:
                rec["scan_result"] = scan_dict
            ctx.persist_sample(rec)
        except Exception:
            logger.debug("Auto-scan failed after local import for %s", rec["id"], exc_info=True)

    return jsonify(sample=ctx.public_sample(rec, include_details=True))


@bp.get("/api/v1/samples/<sample_id>")
def api_v1_sample_detail(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    return jsonify(sample=ctx.public_sample(sample, include_details=True))


@bp.delete("/api/v1/samples/<sample_id>")
def api_v1_sample_delete(sample_id: str):
    ctx = get_ctx()
    sample = ctx.delete_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    return jsonify(deleted=True, id=sample_id)


@bp.patch("/api/v1/samples/<sample_id>/notes")
def api_v1_sample_notes(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    body = request.get_json(silent=True) or {}
    notes = body.get("notes")
    bookmarks = body.get("bookmarks")
    if bookmarks is not None and not isinstance(bookmarks, list):
        return api_error("'bookmarks' must be a list", "BAD_REQUEST", 400)
    with ctx.lock:
        if notes is not None:
            sample["notes"] = str(notes)
        if bookmarks is not None:
            sample["bookmarks"] = list(bookmarks)
    ctx.persist_sample(sample)
    ctx.ws_store.update_sample_notes(
        sample_id,
        notes=sample["notes"] if notes is not None else None,
        bookmarks=sample["bookmarks"] if bookmarks is not None else None,
    )
    return jsonify(sample=ctx.public_sample(sample, include_details=True))
