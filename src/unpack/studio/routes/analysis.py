"""Scan, APK inspect, DEX browser, disassembly, VMP, and Xref routes."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from unpack.studio.routes import get_ctx
from unpack.studio.schemas import api_error, parse_bool, parse_int
from unpack.studio.services.analysis import (
    aggregate_vmp_analysis,
    analyze_xref_dex_bytes,
    scan_apk_rich,
)

bp = Blueprint("studio_analysis", __name__)


@bp.post("/api/v1/samples/<sample_id>/scan")
def api_v1_sample_scan(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    if sample["kind"] != "apk":
        return api_error("Packer scanning requires an APK sample", "UNSUPPORTED_KIND", 400)
    if not ctx.sample_file_exists(sample):
        if sample.get("scan_result"):
            return jsonify(scan=sample["scan_result"], sample=ctx.public_sample(sample))
        return api_error(
            "Original APK file is no longer on disk (saved snapshot only)",
            "FILE_UNAVAILABLE",
            400,
        )

    scan_dict = scan_apk_rich(sample["path"])
    with ctx.lock:
        sample["scan_result"] = scan_dict
    ctx.persist_sample(sample)
    return jsonify(scan=scan_dict, sample=ctx.public_sample(sample))


@bp.get("/api/v1/samples/<sample_id>/inspect")
def api_v1_sample_inspect(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)

    force = parse_bool(request.args.get("refresh"), default=False)
    if sample["kind"] == "apk":
        return jsonify(inspect=ctx.ensure_apk_inspect(sample, force=force))

    dex_list = ctx.list_sample_dex_entries(sample)
    overview = {
        "file": sample["name"],
        "sha256": sample["sha256"],
        "size_bytes": sample["size_bytes"],
        "kind": sample["kind"],
        "dex_files": dex_list,
        "manifest": None,
        "signing": None,
        "permissions": [],
        "components": {"activities": [], "services": [], "receivers": [], "providers": []},
        "native_libs": [],
        "findings": [],
        "risk_score": 0,
        "risk_grade": "A",
        "warnings": [],
    }
    return jsonify(inspect=overview)


@bp.get("/api/v1/samples/<sample_id>/dex")
def api_v1_sample_dex_list(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    return jsonify(dex_files=ctx.list_sample_dex_entries(sample))


@bp.get("/api/v1/samples/<sample_id>/dex/<dex_name>/classes")
def api_v1_sample_dex_classes(sample_id: str, dex_name: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    try:
        offset = parse_int(request.args.get("offset"), 0, min_val=0, name="offset")
        limit = parse_int(request.args.get("limit"), 100, min_val=1, max_val=500, name="limit")
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    browser = ctx.get_dex_browser(sample, dex_name)
    if browser is None:
        return api_error(f"DEX '{dex_name}' not found", "NOT_FOUND", 404)

    q = request.args.get("q", "")
    pkg = request.args.get("package", "")
    health = request.args.get("health", "")
    data = browser.list_classes(query=q, package=pkg, health=health, offset=offset, limit=limit)
    data["summary"] = browser.summary()
    return jsonify(data)


@bp.get("/api/v1/samples/<sample_id>/dex/<dex_name>/class")
def api_v1_sample_dex_class_detail(sample_id: str, dex_name: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    class_name = request.args.get("name", "")
    if not class_name:
        return api_error("Missing 'name' query parameter", "BAD_REQUEST", 400)
    browser = ctx.get_dex_browser(sample, dex_name)
    if browser is None:
        return api_error(f"DEX '{dex_name}' not found", "NOT_FOUND", 404)
    detail = browser.inspect_class(class_name)
    if detail is None:
        return api_error(f"Class '{class_name}' not found", "NOT_FOUND", 404)
    return jsonify(detail)


@bp.get("/api/v1/samples/<sample_id>/dex/<dex_name>/disasm")
def api_v1_sample_dex_disasm(sample_id: str, dex_name: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    class_name = request.args.get("class", "")
    method_name = request.args.get("method", "")
    if not class_name or not method_name:
        return api_error("Both 'class' and 'method' query parameters are required", "BAD_REQUEST", 400)
    try:
        method_idx = (
            parse_int(request.args.get("method_idx"), 0, min_val=0, name="method_idx")
            if request.args.get("method_idx") not in (None, "")
            else None
        )
        max_insns = parse_int(request.args.get("max_insns"), 500, min_val=1, max_val=2000, name="max_insns")
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    browser = ctx.get_dex_browser(sample, dex_name)
    if browser is None:
        return api_error(f"DEX '{dex_name}' not found", "NOT_FOUND", 404)
    disasm = browser.disassemble_method(class_name, method_name, method_idx=method_idx, max_insns=max_insns)
    if disasm is None:
        return api_error("Method not found", "NOT_FOUND", 404)
    return jsonify(disasm)


@bp.get("/api/v1/samples/<sample_id>/dex/<dex_name>/strings")
def api_v1_sample_dex_strings(sample_id: str, dex_name: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    try:
        limit = parse_int(request.args.get("limit"), 100, min_val=1, max_val=500, name="limit")
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)
    browser = ctx.get_dex_browser(sample, dex_name)
    if browser is None:
        return api_error(f"DEX '{dex_name}' not found", "NOT_FOUND", 404)
    q = request.args.get("q", "")
    return jsonify(strings=browser.search_strings(query=q, limit=limit))


@bp.post("/api/v1/samples/<sample_id>/vmp")
def api_v1_sample_vmp(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)

    body = request.get_json(silent=True) or {}
    selected_dex = body.get("dex_name")
    dex_entries = ctx.list_sample_dex_entries(sample)
    if not dex_entries:
        return api_error("No DEX files found in sample", "NO_DEX", 400)

    target_names = [selected_dex] if selected_dex else [d["name"] for d in dex_entries[:12]]
    dex_payloads: list[tuple[str, bytes]] = []
    for dname in target_names:
        raw = ctx.read_sample_dex_bytes(sample, dname)
        if raw is not None:
            dex_payloads.append((dname, raw))
    if not dex_payloads:
        return api_error("Original sample DEX files are not available on disk", "FILE_UNAVAILABLE", 400)

    merged = aggregate_vmp_analysis(dex_payloads, total_dex=len(dex_entries))
    with ctx.lock:
        sample["vmp_result"] = merged
    ctx.persist_sample(sample)
    return jsonify(vmp=merged)


@bp.post("/api/v1/samples/<sample_id>/xref")
def api_v1_sample_xref(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)

    body = request.get_json(silent=True) or {}
    dex_name = body.get("dex_name")
    try:
        limit = parse_int(body.get("limit"), 100, min_val=10, max_val=500, name="limit")
    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)

    dex_entries = ctx.list_sample_dex_entries(sample)
    if not dex_entries:
        return api_error("No DEX files found in sample", "NO_DEX", 400)

    target = dex_name or dex_entries[0]["name"]
    raw = ctx.read_sample_dex_bytes(sample, target)
    if raw is None:
        return api_error(f"DEX '{target}' not found", "NOT_FOUND", 404)

    summary = analyze_xref_dex_bytes(raw, limit=limit)
    summary["dex_name"] = target
    with ctx.lock:
        sample["xref_result"] = summary
    ctx.persist_sample(sample)
    return jsonify(xref=summary)
