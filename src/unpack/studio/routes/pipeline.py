"""Pipeline planning, async job execution, and SSE streaming routes."""

from __future__ import annotations

from flask import Blueprint, Response, jsonify, request, stream_with_context

from unpack.studio.routes import get_ctx
from unpack.studio.schemas import (
    PIPELINE_MODES,
    api_error,
    normalize_lang,
    parse_bool,
    parse_int,
    validate_engine,
    validate_pipeline_mode,
    validate_start_from,
)
from unpack.studio.services.pipeline import (
    build_pipeline_plan,
    launch_deep_pipeline_job,
    launch_legacy_pipeline_job,
)

bp = Blueprint("studio_pipeline", __name__)


@bp.post("/api/v1/pipeline/plan")
def api_v1_pipeline_plan():
    ctx = get_ctx()
    body = request.get_json(silent=True) or {}
    sample_id = str(body.get("sample_id", "")).strip()
    if not sample_id:
        return api_error("Missing 'sample_id'", "BAD_REQUEST", 400)
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)

    try:
        mode = validate_pipeline_mode(body.get("mode"))
        engine = validate_engine(body.get("engine", ""))
        timeout_s = parse_int(body.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    repack_val = body.get("repack")
    repack = None if repack_val is None else parse_bool(repack_val, default=False)
    plan = build_pipeline_plan(
        ctx,
        sample=sample,
        mode=mode,
        engine=engine,
        deep=parse_bool(body.get("deep"), default=False),
        timeout_s=timeout_s,
        anti_detect=parse_bool(body.get("anti_detect"), default=True),
        repack=repack,
        generate_report=parse_bool(body.get("generate_report"), default=True),
        lang=normalize_lang(body.get("lang", "en")),
        check_devices=parse_bool(body.get("check_devices"), default=True),
        refresh_doctor=parse_bool(body.get("refresh_doctor"), default=False),
    )
    return jsonify(plan)


@bp.post("/api/v1/jobs/pipeline")
def api_v1_jobs_pipeline():
    ctx = get_ctx()
    body = request.get_json(silent=True) or {}
    sample_id = str(body.get("sample_id", "")).strip()
    if not sample_id:
        return api_error("Missing 'sample_id'", "BAD_REQUEST", 400)
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)

    try:
        mode = validate_pipeline_mode(body.get("mode")) or "offline_audit"
        engine = validate_engine(body.get("engine", ""))
        timeout_s = parse_int(body.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    job_id = launch_deep_pipeline_job(
        ctx,
        sample=sample,
        mode=mode,
        engine=engine,
        timeout_s=timeout_s,
        deep=parse_bool(body.get("deep"), default=(mode == "device_deep")),
        anti_detect=parse_bool(body.get("anti_detect"), default=True),
        repack=parse_bool(body.get("repack"), default=(mode == "repair_repack")),
        generate_report=parse_bool(body.get("generate_report"), default=True),
        lang=normalize_lang(body.get("lang", "en")),
    )
    return jsonify(job_id=job_id, sample_id=sample_id, mode=mode), 202


@bp.post("/api/v1/samples/<sample_id>/pipeline")
def api_v1_sample_pipeline(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)

    body = request.get_json(silent=True) or {}
    mode = body.get("mode")
    try:
        engine = validate_engine(body.get("engine", ""))
        timeout_s = parse_int(body.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    if mode in PIPELINE_MODES:
        job_id = launch_deep_pipeline_job(
            ctx,
            sample=sample,
            mode=mode,
            engine=engine,
            timeout_s=timeout_s,
            deep=parse_bool(body.get("deep"), default=(mode == "device_deep")),
            anti_detect=parse_bool(body.get("anti_detect"), default=True),
            repack=parse_bool(body.get("repack"), default=(mode == "repair_repack")),
            generate_report=parse_bool(body.get("generate_report"), default=True),
            lang=normalize_lang(body.get("lang", "en")),
        )
        return jsonify(job_id=job_id, sample_id=sample_id, mode=mode), 202

    if sample["kind"] != "apk":
        return api_error("Pipeline requires an APK sample", "UNSUPPORTED_KIND", 400)

    try:
        start_from = validate_start_from(body.get("start_from", "scan"))
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    job_id = launch_legacy_pipeline_job(
        ctx,
        sample=sample,
        engine=engine,
        timeout_s=timeout_s,
        deep=parse_bool(body.get("deep"), default=False),
        anti_detect=parse_bool(body.get("anti_detect"), default=True),
        start_from=start_from,
    )
    return jsonify(job_id=job_id, sample_id=sample_id), 202


@bp.get("/api/v1/jobs")
def api_v1_jobs():
    return jsonify(jobs=get_ctx().job_mgr.list_all())


@bp.get("/api/v1/jobs/<job_id>")
def api_v1_job_detail(job_id: str):
    job = get_ctx().job_mgr.get(job_id)
    if job is None:
        return api_error("Job not found", "NOT_FOUND", 404)
    return jsonify(job)


@bp.post("/api/v1/jobs/<job_id>/cancel")
def api_v1_job_cancel(job_id: str):
    if not get_ctx().job_mgr.cancel(job_id):
        return api_error("Job not found", "NOT_FOUND", 404)
    return jsonify(cancelled=True, job_id=job_id)


@bp.get("/api/v1/jobs/<job_id>/events")
def api_v1_job_events(job_id: str):
    job_mgr = get_ctx().job_mgr
    snapshot, sub_q = job_mgr.subscribe(job_id)
    if snapshot is None:
        return api_error("Job not found", "NOT_FOUND", 404)

    return Response(
        stream_with_context(job_mgr.iter_sse_events(job_id, snapshot, sub_q)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
