"""Verify, repair, repack, FART export, commercial reports, and artifact download routes."""

from __future__ import annotations

import tempfile
import uuid
import zipfile
from pathlib import Path

from flask import Blueprint, Response, jsonify, request, send_file

from unpack.studio.routes import get_ctx
from unpack.studio.schemas import (
    api_error,
    get_logger,
    normalize_lang,
    parse_bool,
    validate_dex_names,
)
from unpack.studio.security import safe_filename
from unpack.studio.services.analysis import (
    repair_dex_with_diff,
    scan_apk_rich,
    verify_dex_rich,
)
from unpack.studio.services.reporting import render_commercial_report

bp = Blueprint("studio_repair_export", __name__)
logger = get_logger("unpack.studio.repair_export")


@bp.post("/api/v1/samples/<sample_id>/verify")
def api_v1_sample_verify(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)

    body = request.get_json(silent=True) or {}
    try:
        dex_names = validate_dex_names(body.get("dex_names"))
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    with tempfile.TemporaryDirectory(prefix="unpack_verify_") as td:
        extracted = ctx.extract_sample_dex_files(sample, Path(td), dex_names=dex_names)
        if not extracted:
            return api_error("No DEX files available to verify", "NO_DEX", 400)
        results = [verify_dex_rich(p) for p in extracted]

    valid_count = sum(1 for r in results if r.get("valid"))
    avg_health = round(sum(float(r.get("health_score", 0)) for r in results) / len(results), 1)
    summary = {
        "total": len(results),
        "valid_count": valid_count,
        "invalid_count": len(results) - valid_count,
        "avg_health": avg_health,
        "results": results,
    }
    with ctx.lock:
        sample["verify_results"] = results
    return jsonify(summary)


@bp.post("/api/v1/samples/<sample_id>/repair")
def api_v1_sample_repair(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)

    body = request.get_json(silent=True) or {}
    try:
        dex_names = validate_dex_names(body.get("dex_names"))
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    run_dir = ctx.artifacts_dir / f"repair_{sample_id}_{uuid.uuid4().hex[:6]}"
    src_dir = run_dir / "src"
    out_dir = run_dir / "repaired"
    out_dir.mkdir(parents=True, exist_ok=True)

    extracted = ctx.extract_sample_dex_files(sample, src_dir, dex_names=dex_names)
    if not extracted:
        return api_error("No DEX files available to repair", "NO_DEX", 400)

    diffs = []
    repaired_files: list[Path] = []
    for p in extracted:
        diff, out_p = repair_dex_with_diff(p, out_dir)
        diffs.append(diff)
        if out_p and out_p.exists():
            repaired_files.append(out_p)

    zip_path = run_dir / f"{Path(sample['name']).stem}_repaired_dex.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rf in repaired_files:
            zf.write(rf, arcname=rf.name)

    art = ctx.register_artifact(zip_path, zip_path.name, "repaired_dex_bundle", "application/zip")
    with ctx.lock:
        sample["repair_diffs"] = diffs
        sample["repaired_dir"] = out_dir
        sample["artifacts"] = [art, *sample.get("artifacts", [])][:20]
    ctx.persist_sample(sample)

    resolved_total = sum(len(d.get("resolved_issues", [])) for d in diffs)
    return jsonify(
        total=len(diffs),
        resolved_issues_total=resolved_total,
        diffs=diffs,
        artifact=art,
    )


@bp.post("/api/v1/samples/<sample_id>/repack")
def api_v1_sample_repack(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    if sample["kind"] != "apk":
        return api_error("Base sample for repacking must be an APK", "UNSUPPORTED_KIND", 400)
    if not ctx.sample_file_exists(sample):
        return api_error(
            "Original APK file is no longer on disk (saved snapshot only); re-upload or re-mount to repack",
            "FILE_UNAVAILABLE",
            400,
        )

    body = request.get_json(silent=True) or {}
    dex_sample_id = body.get("dex_sample_id")
    strip_sigs = parse_bool(body.get("strip_signatures"), default=True)

    dex_dir: Path | None = None
    if dex_sample_id:
        dex_sample = ctx.get_sample(dex_sample_id)
        if dex_sample is None:
            return api_error("Selected DEX source sample not found", "NOT_FOUND", 404)
        if not ctx.sample_file_exists(dex_sample):
            return api_error("Selected DEX source sample is unavailable on disk", "FILE_UNAVAILABLE", 400)
        if dex_sample["kind"] == "dex_dir":
            dex_dir = dex_sample["path"]
        else:
            tmp_dex = ctx.artifacts_dir / f"repack_dex_{uuid.uuid4().hex[:6]}"
            ctx.extract_sample_dex_files(dex_sample, tmp_dex)
            dex_dir = tmp_dex
    elif sample.get("repaired_dir") and Path(sample["repaired_dir"]).exists():
        dex_dir = Path(sample["repaired_dir"])
    else:
        tmp_dex = ctx.artifacts_dir / f"repack_dex_{uuid.uuid4().hex[:6]}"
        ctx.extract_sample_dex_files(sample, tmp_dex)
        dex_dir = tmp_dex

    out_dir = ctx.artifacts_dir / f"repack_{sample_id}_{uuid.uuid4().hex[:6]}"
    from unpack.repack.repacker import Repacker

    rr = Repacker().repack(sample["path"], dex_dir, out_dir, strip_signatures=strip_sigs)
    if not rr.success or not rr.output_path:
        return api_error(rr.error or "Repack failed", "REPACK_FAILED", 400)

    art = ctx.register_artifact(
        rr.output_path,
        rr.output_path.name,
        "repacked_apk",
        "application/vnd.android.package-archive",
    )
    with ctx.lock:
        sample["artifacts"] = [art, *sample.get("artifacts", [])][:20]

    res_dict = (
        rr.to_dict()
        if hasattr(rr, "to_dict")
        else {
            "success": rr.success,
            "output": rr.output_path.name,
            "dex_count": rr.dex_count,
            "resources_preserved": rr.resources_preserved,
        }
    )
    return jsonify(repack=res_dict, artifact=art)


@bp.post("/api/v1/samples/<sample_id>/export/fart")
def api_v1_sample_export_fart(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)

    body = request.get_json(silent=True) or {}
    try:
        dex_names = validate_dex_names(body.get("dex_names"))
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    run_dir = ctx.artifacts_dir / f"fart_{sample_id}_{uuid.uuid4().hex[:6]}"
    src_dir = run_dir / "dex"
    out_dir = run_dir / "fart"
    extracted = ctx.extract_sample_dex_files(sample, src_dir, dex_names=dex_names)
    if not extracted:
        return api_error("No DEX files available for FART export", "NO_DEX", 400)

    from unpack.export.fart import FartExporter

    exporter = FartExporter()
    exported = []
    total_methods = 0
    for p in extracted:
        res = exporter.export(p, out_dir)
        total_methods += res.method_count
        exported.append(
            {
                "dex": p.name,
                "method_count": res.method_count,
                "bin_file": res.bin_path.name,
                "txt_file": res.txt_path.name,
            }
        )

    zip_path = run_dir / f"{Path(sample['name']).stem}_fart_export.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(out_dir.iterdir()):
            if f.is_file():
                zf.write(f, arcname=f.name)

    art = ctx.register_artifact(zip_path, zip_path.name, "fart_export", "application/zip")
    with ctx.lock:
        sample["artifacts"] = [art, *sample.get("artifacts", [])][:20]

    return jsonify(total_methods=total_methods, files=exported, artifact=art)


@bp.get("/api/v1/reports/<sample_id>")
@bp.get("/api/v1/samples/<sample_id>/reports")
def api_v1_report(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)

    fmt = request.args.get("format", "html")
    download = parse_bool(request.args.get("download"), default=False)
    title = request.args.get("title") or None
    lang = normalize_lang(request.args.get("lang", "en"))

    # Auto-enrich APK baseline only when source file exists on disk
    if sample["kind"] == "apk" and ctx.sample_file_exists(sample):
        if sample["scan_result"] is None:
            try:
                sc = scan_apk_rich(sample["path"])
                with ctx.lock:
                    sample["scan_result"] = sc
            except Exception:
                logger.debug("Auto-scan failed during report generation for %s", sample_id, exc_info=True)
        if sample["inspect_result"] is None:
            try:
                ctx.ensure_apk_inspect(sample, force=False)
            except Exception:
                logger.debug("Auto-inspect failed during report generation for %s", sample_id, exc_info=True)

    try:
        content, mime, ext = render_commercial_report(sample=sample, fmt=fmt, title=title, lang=lang)
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    resp = Response(content, mimetype=mime)
    if download:
        dl_name = safe_filename(f"{Path(sample['name']).stem}_audit_{lang}.{ext}", f"audit.{ext}")
        resp.headers["Content-Disposition"] = f'attachment; filename="{dl_name}"'
    return resp


@bp.get("/api/v1/artifacts/<token>/download")
def api_v1_artifact_download(token: str):
    ctx = get_ctx()
    meta = ctx.get_artifact(token)
    if meta is None or not Path(meta["path"]).exists():
        return api_error("Artifact not found", "NOT_FOUND", 404)
    return send_file(
        meta["path"],
        mimetype=meta["mimetype"],
        as_attachment=True,
        download_name=meta["name"],
    )
