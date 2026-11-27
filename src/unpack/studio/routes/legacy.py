"""Hardened backward-compatible legacy /api/* routes."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from flask import Blueprint, current_app, jsonify, request

from unpack.studio.routes import get_ctx
from unpack.studio.schemas import (
    api_error,
    parse_bool,
    parse_int,
    validate_engine,
    validate_start_from,
)
from unpack.studio.security import safe_filename
from unpack.studio.services.analysis import run_doctor_rich
from unpack.studio.services.pipeline import launch_legacy_pipeline_job

bp = Blueprint("studio_legacy", __name__)


@bp.get("/api/cache")
def api_cache():
    ctx = get_ctx()
    with ctx.lock:
        items = []
        for sid, s in ctx.samples.items():
            if s["kind"] != "apk":
                continue
            item: dict[str, Any] = {
                "hash": sid,
                "filename": s["name"],
                "size_mb": round(s["size_bytes"] / 1024 / 1024, 1),
            }
            if s.get("scan_result"):
                item["packer"] = s["scan_result"].get("packer_name")
            if s.get("last_job_id"):
                item["last_job"] = s["last_job_id"]
            items.append(item)
    return jsonify(items=items)


@bp.get("/api/engines")
def api_engines():
    doc = run_doctor_rich(check_devices=True)
    return jsonify(engines=doc.get("engines", []))


@bp.post("/api/scan")
def api_scan():
    if "file" not in request.files:
        return api_error("No file uploaded", "NO_FILE", 400)
    f = request.files["file"]
    safe = safe_filename(f.filename, "")
    if not safe or not safe.lower().endswith(".apk"):
        return api_error("File must be an .apk", "INVALID_FILE", 400)

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        f.save(tmp)
        tmp_path = Path(tmp.name)

    try:
        from unpack.core.scanner import PackerScanner

        result = PackerScanner().scan(tmp_path, verbose=True)
        return jsonify(result.to_verbose_dict())
    except Exception as exc:
        return api_error(str(exc), "SCAN_ERROR", 500)
    finally:
        tmp_path.unlink(missing_ok=True)


@bp.post("/api/full")
def api_full():
    ctx = get_ctx()
    try:
        engine = validate_engine(request.form.get("engine", ""))
        timeout_s = parse_int(request.form.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
        start_from = validate_start_from(request.form.get("start_from", "scan"))
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    deep = parse_bool(request.form.get("deep"), default=False)
    anti_detect = parse_bool(request.form.get("anti_detect"), default=True)
    cached_hash = request.form.get("apk_hash", "")

    sample: dict[str, Any] | None = None
    if cached_hash:
        sample = ctx.get_sample(cached_hash)
        if sample is None:
            return api_error("Cached APK not found", "NOT_FOUND", 404)
    elif "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        if not safe_filename(f.filename, "").lower().endswith(".apk"):
            return api_error("File must be an .apk", "INVALID_FILE", 400)
        try:
            sample = ctx.save_uploaded_file(f)
        except ValueError as exc:
            return api_error(str(exc), "INVALID_FILE", 400)
    else:
        return api_error("No file uploaded and no cached APK specified", "NO_FILE", 400)

    job_id = launch_legacy_pipeline_job(
        ctx,
        sample=sample,
        engine=engine,
        timeout_s=timeout_s,
        deep=deep,
        anti_detect=anti_detect,
        start_from=start_from,
    )
    return jsonify(job_id=job_id, apk_hash=sample["id"])


@bp.get("/api/job/<job_id>")
def api_job_status(job_id: str):
    job = get_ctx().job_mgr.get(job_id)
    if job is None:
        return api_error("Job not found", "NOT_FOUND", 404)
    return jsonify(job)


@bp.get("/api/job/<job_id>/export")
def api_job_export(job_id: str):
    job = get_ctx().job_mgr.get(job_id)
    if job is None:
        return api_error("Job not found", "NOT_FOUND", 404)
    if job["status"] != "done":
        return api_error("Job not finished yet", "JOB_NOT_READY", 400, extra={"status": job["status"]})

    return jsonify(
        {
            "tool": "unpack",
            "version": current_app.config["UNPACK_VERSION"],
            "apk": job.get("apk"),
            "phases": job.get("phases", {}),
            "prompt_hint": (
                "This is an UNPACK scan/dump result. Analyze: "
                "1) packer technology and version "
                "2) protection mechanisms to expect "
                "3) recommended next steps for deeper analysis "
                "4) which classes/methods to focus on"
            ),
        }
    )


@bp.post("/api/dump")
def api_dump():
    ctx = get_ctx()
    if "file" not in request.files or not request.files["file"].filename:
        return api_error("No file uploaded", "NO_FILE", 400)
    f = request.files["file"]
    try:
        engine = validate_engine(request.form.get("engine", ""))
        timeout_s = parse_int(request.form.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    deep = parse_bool(request.form.get("deep"), default=False)
    anti_detect = parse_bool(request.form.get("anti_detect"), default=True)
    try:
        sample = ctx.save_uploaded_file(f)
    except ValueError as exc:
        return api_error(str(exc), "INVALID_FILE", 400)

    job_id = launch_legacy_pipeline_job(
        ctx,
        sample=sample,
        engine=engine,
        timeout_s=timeout_s,
        deep=deep,
        anti_detect=anti_detect,
        start_from="scan",
    )
    return jsonify(job_id=job_id)


@bp.get("/api/dump/<job_id>")
def api_dump_status(job_id: str):
    job = get_ctx().job_mgr.get(job_id)
    if job is None:
        return api_error("Job not found", "NOT_FOUND", 404)
    return jsonify(job)


@bp.post("/api/repair")
def api_repair():
    files = request.files.getlist("files")
    files = [f for f in files if f and f.filename]
    if not files:
        return api_error("No files uploaded", "NO_FILE", 400)
    in_place = parse_bool(request.form.get("in_place"), default=False)

    from unpack.repair.dex_repair import DexRepairPipeline

    pipeline = DexRepairPipeline()
    results = []
    with tempfile.TemporaryDirectory(prefix="unpack_repair_") as td:
        for idx, f in enumerate(files):
            safe = safe_filename(f.filename, f"file_{idx}.dex")
            fpath = Path(td) / f"{idx}_{safe}"
            f.save(str(fpath))
            rr = pipeline.repair(fpath, in_place=in_place)
            results.append(
                {
                    "file": safe,
                    "success": rr.success,
                    "actions": list(rr.actions),
                    "nop_methods": rr.nop_method_count,
                }
            )
    return jsonify(results=results)


@bp.post("/api/verify")
def api_verify():
    files = request.files.getlist("files")
    files = [f for f in files if f and f.filename]
    if not files:
        return api_error("No files uploaded", "NO_FILE", 400)

    from unpack.repair.verifier import DexVerifier

    verifier = DexVerifier()
    results = []
    with tempfile.TemporaryDirectory(prefix="unpack_verify_") as td:
        for idx, f in enumerate(files):
            safe = safe_filename(f.filename, f"file_{idx}.dex")
            fpath = Path(td) / f"{idx}_{safe}"
            f.save(str(fpath))
            vr = verifier.verify(fpath)
            results.append(
                {
                    "file": safe,
                    "valid": vr.valid,
                    "issues": list(vr.issues),
                    "stats": dict(vr.stats),
                }
            )
    return jsonify(results=results)
