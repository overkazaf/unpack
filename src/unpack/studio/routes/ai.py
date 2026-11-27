"""AI model configuration and embedded reverse-engineering analysis routes."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from unpack.studio.routes import get_ctx
from unpack.studio.schemas import api_error, normalize_lang, parse_bool, parse_int
from unpack.studio.services.analysis import scan_apk_rich

bp = Blueprint("studio_ai", __name__)

VALID_AI_MODULES: frozenset[str] = frozenset({"scan", "security", "method", "vmp_native", "pipeline_issue"})


@bp.get("/api/v1/ai/config")
def api_v1_ai_config_get():
    from unpack.core.ai_engine import list_provider_presets

    cfg = get_ctx().ai_config_store.load()
    return jsonify(config=cfg.to_public_dict(), presets=list_provider_presets())


@bp.put("/api/v1/ai/config")
def api_v1_ai_config_put():
    from unpack.core.ai_engine import list_provider_presets

    body = request.get_json(silent=True) or {}
    clear_key = parse_bool(body.get("clear_api_key"), default=False)
    try:
        cfg = get_ctx().ai_config_store.update(body, clear_api_key=clear_key)
    except (ValueError, TypeError) as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)
    return jsonify(config=cfg.to_public_dict(), presets=list_provider_presets())


@bp.post("/api/v1/ai/test")
def api_v1_ai_test():
    from unpack.core.ai_engine import (
        AIConfig,
        is_masked_api_key,
        test_connection as ai_test_connection,
    )

    ctx = get_ctx()
    body = request.get_json(silent=True) or {}
    lang = normalize_lang(body.get("lang", "zh"))
    override = body.get("config") if isinstance(body.get("config"), dict) else None
    if override is not None:
        stored = ctx.ai_config_store.load()
        merged = dict(stored.to_storage_dict())
        for k in ("enabled", "provider", "base_url", "model", "temperature", "max_tokens", "timeout_seconds"):
            if k in override and override[k] is not None:
                merged[k] = override[k]
        incoming_key = str(override.get("api_key") or "").strip()
        if parse_bool(override.get("clear_api_key"), default=False):
            merged["api_key"] = ""
        elif incoming_key and not is_masked_api_key(incoming_key):
            merged["api_key"] = incoming_key
        try:
            cfg = AIConfig.from_dict(merged)
        except ValueError as exc:
            return api_error(str(exc), "BAD_REQUEST", 400)
        res = ai_test_connection(cfg, lang=lang)
    else:
        res = ai_test_connection(config_store=ctx.ai_config_store, lang=lang)
    return jsonify(res)


@bp.get("/api/v1/samples/<sample_id>/ai")
def api_v1_sample_ai_history(sample_id: str):
    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    module = (request.args.get("module") or "").strip() or None
    items = ctx.ws_store.list_ai_analyses(
        workspace_id=sample.get("workspace_id") or ctx.active_ws_id(),
        sample_id=sample_id,
        module=module,
        limit=50,
    )
    return jsonify(analyses=items)


@bp.post("/api/v1/samples/<sample_id>/ai/<module>")
def api_v1_sample_ai_analyze(sample_id: str, module: str):
    from unpack.core.ai_engine import AIAnalyzer
    from unpack.core.errors import UnpackError

    ctx = get_ctx()
    sample = ctx.get_sample(sample_id)
    if sample is None:
        return api_error("Sample not found", "NOT_FOUND", 404)
    mod = module.strip().lower()
    if mod not in VALID_AI_MODULES:
        return api_error(f"Unsupported AI module: {module!r}", "BAD_REQUEST", 400)

    body = request.get_json(silent=True) or {}
    lang = normalize_lang(body.get("lang", "zh"))
    analyzer = AIAnalyzer(config_store=ctx.ai_config_store)

    try:
        if mod == "scan":
            scan_data = sample.get("scan_result")
            if scan_data is None and sample["kind"] == "apk" and ctx.sample_file_exists(sample):
                scan_data = scan_apk_rich(sample["path"])
                with ctx.lock:
                    sample["scan_result"] = scan_data
                ctx.persist_sample(sample)
            insp_data = sample.get("inspect_result")
            if insp_data is None and sample["kind"] == "apk" and ctx.sample_file_exists(sample):
                insp_data = ctx.ensure_apk_inspect(sample, force=False)
            result = analyzer.analyze_scan(scan_data or {}, insp_data, lang=lang)

        elif mod == "security":
            insp_data = sample.get("inspect_result")
            if insp_data is None and sample["kind"] == "apk" and ctx.sample_file_exists(sample):
                insp_data = ctx.ensure_apk_inspect(sample, force=False)
            if not insp_data:
                insp_data = {
                    "file": sample["name"],
                    "sha256": sample["sha256"],
                    "findings": [],
                    "risk_score": 0,
                    "risk_grade": "A",
                }
            result = analyzer.analyze_security(insp_data, findings=insp_data.get("findings"), lang=lang)

        elif mod == "method":
            disasm = body.get("disasm") if isinstance(body.get("disasm"), dict) else None
            cls_name = str(body.get("class_name") or "")
            if disasm is None:
                dex_name = str(body.get("dex_name") or "")
                meth_name = str(body.get("method_name") or "")
                meth_idx = (
                    parse_int(body.get("method_idx"), 0, min_val=0, name="method_idx")
                    if body.get("method_idx") not in (None, "")
                    else None
                )
                if not dex_name or not cls_name or not meth_name:
                    return api_error(
                        "Provide 'disasm' or ('dex_name', 'class_name', 'method_name')",
                        "BAD_REQUEST",
                        400,
                    )
                browser = ctx.get_dex_browser(sample, dex_name)
                if browser is None:
                    return api_error(f"DEX '{dex_name}' not available on disk", "FILE_UNAVAILABLE", 400)
                disasm = browser.disassemble_method(cls_name, meth_name, method_idx=meth_idx)
                if disasm is None:
                    return api_error("Method not found", "NOT_FOUND", 404)
            result = analyzer.analyze_method(disasm, class_name=cls_name or disasm.get("class_name", ""), lang=lang)

        elif mod == "vmp_native":
            vmp_data = sample.get("vmp_result")
            insp_data = sample.get("inspect_result") or {}
            xref_data = sample.get("xref_result")
            native_libs = insp_data.get("native_libs") if isinstance(insp_data, dict) else None
            result = analyzer.analyze_vmp_native(
                vmp=vmp_data,
                native_libs=native_libs,
                xref=xref_data,
                lang=lang,
            )

        else:  # pipeline_issue
            stage_data = body.get("stage") if isinstance(body.get("stage"), dict) else {"name": str(body.get("stage") or "pipeline")}
            error_text = str(body.get("error_text") or "")
            doc = ctx.get_doctor_cached(check_devices=False)
            result = analyzer.analyze_pipeline_issue(stage_data, error_text=error_text, doctor=doc, lang=lang)

    except ValueError as exc:
        return api_error(str(exc), "BAD_REQUEST", 400)
    except UnpackError as exc:
        code_val = exc.code.value if hasattr(exc.code, "value") else str(exc.code)
        status_code = 400 if code_val == "ENGINE_UNAVAILABLE" else 502
        return api_error(exc.message, code_val, status_code, hint=exc.hint)

    ws_id = sample.get("workspace_id") or ctx.active_ws_id()
    saved = ctx.ws_store.save_ai_analysis(ws_id, sample_id, mod, result)
    with ctx.lock:
        cur_list = [x for x in (sample.get("ai_analyses") or []) if x.get("id") != saved["id"]]
        sample["ai_analyses"] = [saved, *cur_list][:50]

    all_for_mod = ctx.ws_store.list_ai_analyses(workspace_id=ws_id, sample_id=sample_id, module=mod, limit=25)
    return jsonify(analysis=saved, analyses=all_for_mod)
