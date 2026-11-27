"""Packer-aware Pipeline Blueprint Planner and Offline Audit & Repair Runner.

Provides pure-core orchestration (zero Rich/CLI dependencies) used by both
``unpack pipeline`` / ``unpack dump --explain`` and UNPACK Studio.
"""

from __future__ import annotations

import json
import shutil
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from unpack.i18n import get_lang, resolve_lang, t

PipelineEventCallback = Callable[[str, dict[str, Any]], None]


def _format_bytes(size: int | float | None) -> str:
    """Format byte counts into concise human-readable units."""
    if size is None:
        return "—"
    n = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{size} B"


def _emit(on_event: PipelineEventCallback | None, event: str, payload: dict[str, Any]) -> None:
    if on_event is not None:
        on_event(event, payload)


def build_pipeline_plan(
    apk: Path,
    *,
    output: Path = Path("./unpacked"),
    device: str | None = None,
    engine: str | None = None,
    timeout: int = 0,
    deep: bool = False,
    skip_repair: bool = False,
    no_anti_detect: bool = False,
    repack: bool = False,
    report_html: Path | None = None,
    mode: str = "auto",
    check_devices: bool = True,
    lang: str | None = None,
) -> dict[str, Any]:
    """Build a structured, packer-aware Pipeline Execution Blueprint with live preflight checks."""
    from unpack.core.doctor import run_doctor
    from unpack.core.scanner import PackerScanner

    eff = resolve_lang(lang) if lang is not None else get_lang()

    # 1. Static scan & archive probe
    apk_valid = False
    apk_size = 0
    dex_entries = 0
    so_entries = 0
    scan_result = None
    if apk.exists() and apk.is_file():
        apk_size = apk.stat().st_size
        try:
            with zipfile.ZipFile(apk, "r") as zf:
                names = zf.namelist()
                apk_valid = True
                dex_entries = sum(1 for n in names if n.endswith(".dex") and "/" not in n)
                so_entries = sum(1 for n in names if n.startswith("lib/") and n.endswith(".so"))
        except zipfile.BadZipFile:
            apk_valid = False

    if apk_valid:
        scan_result = PackerScanner().scan(apk, verbose=True)

    # 2. Live doctor probe
    doc_res = run_doctor(check_devices=check_devices, device_serial=device)
    doc = doc_res.to_dict() if hasattr(doc_res, "to_dict") else dict(doc_res)
    devices = doc.get("devices") or []
    rooted_cnt = sum(1 for d in devices if d.get("rooted") or d.get("root"))
    engines_map = {str(e.get("name", "")).lower(): e for e in (doc.get("engines") or [])}
    checks_map = {str(c.get("name", "")).lower(): c for c in (doc.get("checks") or [])}

    packer_name = getattr(scan_result, "packer_name", None) if scan_result else None
    packer_version = getattr(scan_result, "packer_version", None) if scan_result else None
    confidence = float(getattr(scan_result, "confidence", 0.0) or 0.0) if scan_result else 0.0
    prot_obj = getattr(scan_result, "protection_level", None) if scan_result else None
    prot_level = getattr(prot_obj, "value", str(prot_obj or "none")) if prot_obj else "none"

    # 3. Resolve mode & recommendations from PackerScanner intelligence
    norm_mode = (mode or "auto").strip().lower()
    if norm_mode == "auto":
        if not packer_name:
            effective_mode = "offline"
        elif prot_level == "function_extraction":
            effective_mode = "deep"
        else:
            effective_mode = "standard"
    elif norm_mode in ("offline", "standard", "deep"):
        effective_mode = norm_mode
    else:
        effective_mode = "deep" if deep else "standard"

    use_deep = deep or effective_mode == "deep"
    is_offline = effective_mode == "offline"

    rec_engine = engine or (getattr(scan_result, "recommended_engine", None) if scan_result else None) or "memory"
    rec_engine_display = "offline" if is_offline else rec_engine

    rec_flags: list[str] = list(getattr(scan_result, "recommended_flags", None) or []) if scan_result else []
    if use_deep and "--deep" not in rec_flags:
        rec_flags.append("--deep")
    if is_offline:
        rec_flags = ["--mode", "offline", "--execute"]

    if not packer_name:
        why = t("pipe.why.clean", eff)
    elif prot_level in ("vmp", "dex2c"):
        why = t("pipe.why.vmp", eff)
    elif prot_level == "function_extraction":
        why = t("pipe.why.func", eff)
    elif prot_level == "dex_encryption":
        why = t("pipe.why.dex_enc", eff)
    else:
        why = t("pipe.why.unknown", eff)

    # 4. Live Preflight Checks
    preflight: list[dict[str, Any]] = []
    if apk_valid:
        preflight.append(
            {
                "id": "apk",
                "name": t("pipe.preflight.apk", eff),
                "status": "pass",
                "detail": t(
                    "pipe.preflight.apk_ok",
                    eff,
                    size=_format_bytes(apk_size),
                    dex=dex_entries,
                    so=so_entries,
                ),
                "remediation": "",
            }
        )
    else:
        preflight.append(
            {
                "id": "apk",
                "name": t("pipe.preflight.apk", eff),
                "status": "block",
                "detail": t("pipe.preflight.apk_bad", eff),
                "remediation": t("pipe.preflight.apk_fix", eff),
            }
        )

    adb_chk = checks_map.get("adb")
    adb_path = (adb_chk or {}).get("version") or shutil.which("adb")
    if not is_offline:
        if adb_path:
            preflight.append(
                {
                    "id": "adb",
                    "name": t("pipe.preflight.adb", eff),
                    "status": "pass",
                    "detail": t("pipe.preflight.adb_ok", eff, path=adb_path),
                    "remediation": "",
                }
            )
        else:
            preflight.append(
                {
                    "id": "adb",
                    "name": t("pipe.preflight.adb", eff),
                    "status": "block",
                    "detail": t("pipe.preflight.adb_miss", eff),
                    "remediation": t("pipe.preflight.adb_fix", eff),
                }
            )

        if devices and rooted_cnt > 0:
            preflight.append(
                {
                    "id": "device",
                    "name": t("pipe.preflight.device", eff),
                    "status": "pass",
                    "detail": t("pipe.preflight.device_ok", eff, count=len(devices), rooted=rooted_cnt),
                    "remediation": "",
                }
            )
        elif devices:
            preflight.append(
                {
                    "id": "device",
                    "name": t("pipe.preflight.device", eff),
                    "status": "warn",
                    "detail": t("pipe.preflight.device_unrooted", eff, count=len(devices)),
                    "remediation": t("pipe.preflight.device_fix", eff),
                }
            )
        else:
            preflight.append(
                {
                    "id": "device",
                    "name": t("pipe.preflight.device", eff),
                    "status": "block",
                    "detail": t("pipe.preflight.device_miss", eff),
                    "remediation": t("pipe.preflight.device_fix", eff),
                }
            )

        eng_info = engines_map.get(rec_engine.lower()) or {"available": False, "reason": "unknown engine"}
        if eng_info.get("available"):
            preflight.append(
                {
                    "id": "engine",
                    "name": t("pipe.preflight.engine", eff, engine=rec_engine),
                    "status": "pass",
                    "detail": t("pipe.preflight.engine_ok", eff, engine=rec_engine),
                    "remediation": "",
                }
            )
        else:
            preflight.append(
                {
                    "id": "engine",
                    "name": t("pipe.preflight.engine", eff, engine=rec_engine),
                    "status": "block",
                    "detail": t(
                        "pipe.preflight.engine_miss",
                        eff,
                        engine=rec_engine,
                        reason=eng_info.get("reason") or "requirements not met",
                    ),
                    "remediation": t("pipe.preflight.engine_fix", eff),
                }
            )

        if use_deep:
            frida_ready = bool((engines_map.get("frida") or {}).get("available"))
            preflight.append(
                {
                    "id": "deep",
                    "name": t("pipe.preflight.deep", eff),
                    "status": "pass" if frida_ready else "warn",
                    "detail": t("pipe.preflight.deep_ok", eff) if frida_ready else t("pipe.preflight.deep_warn", eff),
                    "remediation": "" if frida_ready else "pip install -e '.[frida]'",
                }
            )

    preflight.append(
        {
            "id": "output",
            "name": t("pipe.preflight.output", eff),
            "status": "pass",
            "detail": t("pipe.preflight.output_ok", eff, path=output),
            "remediation": "",
        }
    )

    device_blocked = any(p["status"] == "block" for p in preflight if p["id"] in ("adb", "device", "engine"))
    can_execute = not any(p["status"] == "block" for p in preflight)

    # 5. Stage-by-stage Execution Blueprint
    stages: list[dict[str, Any]] = []
    if is_offline:
        order = 1
        stages.append(
            {
                "order": order,
                "id": "scan",
                "title": t("pipe.stage.scan.title", eff),
                "what_it_does": t("pipe.stage.scan.desc", eff),
                "prerequisites": t("pipe.stage.scan.prereq", eff),
                "readiness": "ready" if apk_valid else "blocked",
                "inputs": apk.name,
                "outputs": "ScanResult (packer, confidence, evidence)",
                "will_run": True,
                "skip_reason": None,
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "inspect",
                "title": t("pipe.stage.inspect.title", eff),
                "what_it_does": t("pipe.stage.inspect.desc", eff),
                "prerequisites": t("pipe.stage.inspect.prereq", eff),
                "readiness": "ready" if apk_valid else "blocked",
                "inputs": apk.name,
                "outputs": "ApkInspectResult (manifest, signing, ELF, risk)",
                "will_run": True,
                "skip_reason": None,
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "extract_dex",
                "title": t("pipe.stage.extract_dex.title", eff),
                "what_it_does": t("pipe.stage.extract_dex.desc", eff),
                "prerequisites": t("pipe.stage.extract_dex.prereq", eff),
                "readiness": "ready" if dex_entries > 0 else "warn",
                "inputs": f"{apk.name} ({dex_entries} DEX)",
                "outputs": f"{output}/*.dex",
                "will_run": dex_entries > 0,
                "skip_reason": None if dex_entries > 0 else "no root classes*.dex",
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "repair",
                "title": f"{order}. {t('pipe.stage.repair.title', eff)}",
                "what_it_does": t("pipe.stage.repair.desc", eff),
                "prerequisites": t("pipe.stage.repair.prereq", eff),
                "readiness": "skipped" if (skip_repair or dex_entries == 0) else "ready",
                "inputs": f"{output}/*.dex",
                "outputs": f"{output}/*_repaired.dex",
                "will_run": not skip_repair and dex_entries > 0,
                "skip_reason": "--skip-repair" if skip_repair else (None if dex_entries > 0 else "no DEX"),
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "verify",
                "title": f"{order}. {t('pipe.stage.verify.title', eff)}",
                "what_it_does": t("pipe.stage.verify.desc", eff),
                "prerequisites": t("pipe.stage.verify.prereq", eff),
                "readiness": "ready" if dex_entries > 0 else "skipped",
                "inputs": f"{output}/*.dex",
                "outputs": f"{output}/report.json",
                "will_run": dex_entries > 0,
                "skip_reason": None if dex_entries > 0 else "no DEX",
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "vmp",
                "title": f"{order}. {t('pipe.stage.vmp.title', eff)}",
                "what_it_does": t("pipe.stage.vmp.desc", eff),
                "prerequisites": t("pipe.stage.vmp.prereq", eff),
                "readiness": "ready" if dex_entries > 0 else "skipped",
                "inputs": f"{output}/*.dex",
                "outputs": "VmpReport (normal / NOP / VMP stubs)",
                "will_run": dex_entries > 0,
                "skip_reason": None if dex_entries > 0 else "no DEX",
            }
        )
        if repack:
            order += 1
            stages.append(
                {
                    "order": order,
                    "id": "repack",
                    "title": f"{order}. {t('pipe.stage.repack.title', eff)}",
                    "what_it_does": t("pipe.stage.repack.desc", eff),
                    "prerequisites": t("pipe.stage.repack.prereq", eff),
                    "readiness": "ready" if dex_entries > 0 else "skipped",
                    "inputs": f"{apk.name} + {output}/*.dex",
                    "outputs": f"{output}/repacked/*.apk",
                    "will_run": dex_entries > 0,
                    "skip_reason": None if dex_entries > 0 else "no DEX",
                }
            )
        order += 1
        report_target = report_html or (output / "audit_report.html")
        stages.append(
            {
                "order": order,
                "id": "report",
                "title": f"{order}. {t('pipe.stage.report.title', eff)}",
                "what_it_does": t("pipe.stage.report.desc", eff),
                "prerequisites": t("pipe.stage.report.prereq", eff),
                "readiness": "ready" if apk_valid else "blocked",
                "inputs": "All stage results",
                "outputs": str(report_target),
                "will_run": True,
                "skip_reason": None,
            }
        )
    else:
        order = 1
        stages.append(
            {
                "order": order,
                "id": "scan",
                "title": t("pipe.stage.scan.title", eff),
                "what_it_does": t("pipe.stage.scan.desc", eff),
                "prerequisites": t("pipe.stage.scan.prereq", eff),
                "readiness": "ready" if apk_valid else "blocked",
                "inputs": apk.name,
                "outputs": "ScanResult (packer, level, strategy)",
                "will_run": True,
                "skip_reason": None,
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "dump",
                "title": t("pipe.stage.dump.title", eff),
                "what_it_does": t("pipe.stage.dump.desc", eff, engine=rec_engine),
                "prerequisites": t("pipe.stage.dump.prereq", eff, engine=rec_engine),
                "readiness": "blocked" if device_blocked else "ready",
                "inputs": apk.name,
                "outputs": f"{output}/classes_*.dex",
                "will_run": True,
                "skip_reason": None,
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "dedup",
                "title": t("pipe.stage.dedup.title", eff),
                "what_it_does": t("pipe.stage.dedup.desc", eff),
                "prerequisites": t("pipe.stage.dedup.prereq", eff),
                "readiness": "blocked" if device_blocked else "ready",
                "inputs": f"{output}/*.dex",
                "outputs": "Unique DEX set",
                "will_run": True,
                "skip_reason": None,
            }
        )
        order += 1
        deep_readiness = (
            "skipped"
            if not use_deep
            else ("blocked" if device_blocked else ("ready" if (engines_map.get("frida") or {}).get("available") else "warn"))
        )
        stages.append(
            {
                "order": order,
                "id": "deep_invoke",
                "title": t("pipe.stage.deep.title", eff),
                "what_it_does": t("pipe.stage.deep.desc", eff),
                "prerequisites": t("pipe.stage.deep.prereq", eff),
                "readiness": deep_readiness,
                "inputs": f"{apk.name} + {output}/*.dex",
                "outputs": "Merged CodeItems (recovered NOPs)",
                "will_run": use_deep,
                "skip_reason": None if use_deep else "pass --deep to enable",
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "repair",
                "title": f"{order}. {t('pipe.stage.repair.title', eff)}",
                "what_it_does": t("pipe.stage.repair.desc", eff),
                "prerequisites": t("pipe.stage.repair.prereq", eff),
                "readiness": "skipped" if skip_repair else ("blocked" if device_blocked else "ready"),
                "inputs": f"{output}/*.dex",
                "outputs": f"{output}/*_repaired.dex",
                "will_run": not skip_repair,
                "skip_reason": "--skip-repair" if skip_repair else None,
            }
        )
        order += 1
        stages.append(
            {
                "order": order,
                "id": "verify",
                "title": f"{order}. {t('pipe.stage.verify.title', eff)}",
                "what_it_does": t("pipe.stage.verify.desc", eff),
                "prerequisites": t("pipe.stage.verify.prereq", eff),
                "readiness": "blocked" if device_blocked else "ready",
                "inputs": f"{output}/*.dex",
                "outputs": f"{output}/report.json",
                "will_run": True,
                "skip_reason": None,
            }
        )
        if report_html is not None:
            order += 1
            stages.append(
                {
                    "order": order,
                    "id": "report",
                    "title": f"{order}. {t('pipe.stage.report.title', eff)}",
                    "what_it_does": t("pipe.stage.report.desc", eff),
                    "prerequisites": t("pipe.stage.report.prereq", eff),
                    "readiness": "blocked" if device_blocked else "ready",
                    "inputs": "Scan + Quality + Repair",
                    "outputs": str(report_html),
                    "will_run": True,
                    "skip_reason": None,
                }
            )

    # 6. Copyable Commands
    lf = " --lang zh" if eff == "zh" else ""
    if is_offline:
        rec_cmd = f"unpack pipeline {apk} --mode offline -o {output} --execute{lf}"
    else:
        cmd_parts = [f"unpack dump {apk}", f"-o {output}"]
        if engine:
            cmd_parts.append(f"-e {engine}")
        if use_deep:
            cmd_parts.append("--deep")
        if timeout > 0:
            cmd_parts.append(f"-t {timeout}")
        if skip_repair:
            cmd_parts.append("--skip-repair")
        if no_anti_detect:
            cmd_parts.append("--no-anti-detect")
        if report_html:
            cmd_parts.append(f"--report-html {report_html}")
        if eff == "zh":
            cmd_parts.append("--lang zh")
        rec_cmd = " ".join(cmd_parts)

    offline_alt_cmd = f"unpack pipeline {apk} --mode offline -o {output} --execute{lf}"

    return {
        "target": str(apk),
        "output": str(output),
        "mode": effective_mode,
        "mode_label": t(f"pipe.mode.{effective_mode}", eff),
        "lang": eff,
        "packer_name": packer_name,
        "packer_version": packer_version,
        "confidence": round(confidence, 3),
        "protection_level": prot_level,
        "recommended_engine": rec_engine_display,
        "recommended_flags": rec_flags,
        "strategy_reason": why,
        "can_execute": can_execute,
        "preflight_checks": preflight,
        "stages": stages,
        "recommended_cmd": rec_cmd,
        "offline_alternative_cmd": offline_alt_cmd,
    }


def run_offline_pipeline(
    apk: Path,
    *,
    output: Path,
    skip_repair: bool = False,
    repack: bool = False,
    report_html: Path | None = None,
    lang: str = "en",
    on_event: PipelineEventCallback | None = None,
) -> dict[str, Any]:
    """Execute the zero-device Offline Audit & Repair Pipeline end-to-end.

    Pure-core execution with optional ``on_event(event_type, payload)`` hook
    for CLI or UI progress rendering.
    """
    from unpack.analysis.vmp import VmpDetector
    from unpack.core.inspector import ApkInspector
    from unpack.core.reporter import ReportGenerator, Reporter
    from unpack.core.scanner import PackerScanner
    from unpack.repair.dex_repair import DexRepairPipeline
    from unpack.repair.verifier import DexVerifier

    output.mkdir(parents=True, exist_ok=True)
    total_steps = 6 + (1 if repack else 0)
    step = 0

    # 1. Scan
    step += 1
    _emit(
        on_event,
        "stage_start",
        {
            "step": step,
            "total_steps": total_steps,
            "stage": "scan",
            "title": t("pipe.stage.scan.title", lang),
            "detail": apk.name,
        },
    )
    scan_res = PackerScanner().scan(apk, verbose=True)
    _emit(on_event, "scan_done", {"scan": scan_res, "apk": apk})

    # 2. Static APK Inspection
    step += 1
    _emit(
        on_event,
        "stage_start",
        {
            "step": step,
            "total_steps": total_steps,
            "stage": "inspect",
            "title": t("pipe.stage.inspect.title", lang),
            "detail": apk.name,
        },
    )
    inspect_data = ApkInspector().inspect(apk).to_dict()
    _emit(on_event, "inspect_done", {"inspect": inspect_data})

    # 3. Extract embedded DEX files
    step += 1
    _emit(
        on_event,
        "stage_start",
        {
            "step": step,
            "total_steps": total_steps,
            "stage": "extract_dex",
            "title": t("pipe.stage.extract_dex.title", lang),
            "detail": None,
        },
    )
    extracted: list[Path] = []
    with zipfile.ZipFile(apk, "r") as zf:
        for info in zf.infolist():
            if info.filename.endswith(".dex") and "/" not in info.filename:
                dest = output / Path(info.filename).name
                dest.write_bytes(zf.read(info.filename))
                extracted.append(dest)
    _emit(on_event, "extract_done", {"extracted": extracted})

    # 4. Repair & Verify
    step += 1
    _emit(
        on_event,
        "stage_start",
        {
            "step": step,
            "total_steps": total_steps,
            "stage": "repair",
            "title": t("pipe.stage.repair.title", lang),
            "detail": None,
        },
    )
    repair_dicts: list[dict[str, Any]] = []
    verify_list: list[dict[str, Any]] = []
    if extracted and not skip_repair:
        rp = DexRepairPipeline()
        for p in extracted:
            rr = rp.repair(p)
            repair_dicts.append(
                {
                    "file": p.name,
                    "success": rr.success,
                    "actions": rr.actions,
                    "nop_methods": rr.nop_method_count,
                    "output": str(rr.output_path) if rr.output_path else None,
                }
            )
        _emit(on_event, "repair_done", {"repair_results": repair_dicts})

    verifier = DexVerifier()
    for p in extracted:
        vr = verifier.verify(p)
        verify_list.append({"file": p.name, "valid": vr.valid, "issues": vr.issues, "stats": vr.stats})
    if verify_list:
        _emit(on_event, "verify_done", {"verify_results": verify_list})

    # 5. VMP & Quality
    step += 1
    _emit(
        on_event,
        "stage_start",
        {
            "step": step,
            "total_steps": total_steps,
            "stage": "vmp",
            "title": t("pipe.stage.vmp.title", lang),
            "detail": None,
        },
    )
    reporter = Reporter()
    quality_report = reporter.evaluate(output, scan_res) if extracted else None
    vmp_data: dict[str, Any] | None = None
    if extracted:
        det = VmpDetector()
        tot = norm = nops = vmps = 0
        v_methods: list[dict[str, Any]] = []
        c_graph: list[dict[str, Any]] = []
        per_dex: list[dict[str, Any]] = []
        for p in extracted:
            vr_vmp = det.analyze_dex(p.read_bytes())
            tot += vr_vmp.total_methods
            norm += vr_vmp.normal_count
            nops += vr_vmp.nop_count
            vmps += vr_vmp.vmp_count
            v_methods.extend({**m, "dex_file": p.name} for m in vr_vmp.vmp_methods)
            c_graph.extend({**c, "dex_file": p.name} for c in vr_vmp.call_graph)
            per_dex.append({"file": p.name, "normal": vr_vmp.normal_count, "nop": vr_vmp.nop_count, "vmp": vr_vmp.vmp_count})
        vmp_data = {
            "total_methods": tot,
            "normal_count": norm,
            "nop_count": nops,
            "vmp_count": vmps,
            "vmp_methods": v_methods,
            "call_graph": c_graph,
        }
        _emit(
            on_event,
            "vmp_done",
            {
                "per_dex": per_dex,
                "vmp": vmp_data,
                "vmp_methods": v_methods,
                "quality": quality_report,
            },
        )
        if quality_report is not None:
            (output / "report.json").write_text(json.dumps(quality_report.to_dict(), indent=2, ensure_ascii=False))

    # Optional Repack
    repacked_path: Path | None = None
    if repack and extracted:
        step += 1
        _emit(
            on_event,
            "stage_start",
            {
                "step": step,
                "total_steps": total_steps,
                "stage": "repack",
                "title": t("pipe.stage.repack.title", lang),
                "detail": None,
            },
        )
        from unpack.repack.repacker import Repacker

        rep_res = Repacker().repack(apk, output, output / "repacked")
        if rep_res.success:
            repacked_path = rep_res.output_path
        _emit(on_event, "repack_done", {"repacked_path": repacked_path, "result": rep_res})

    # 6. Commercial Audit Report
    step += 1
    _emit(
        on_event,
        "stage_start",
        {
            "step": step,
            "total_steps": total_steps,
            "stage": "report",
            "title": t("pipe.stage.report.title", lang),
            "detail": None,
        },
    )
    audit = reporter.build_audit_report(
        apk,
        scan=scan_res,
        inspect=inspect_data,
        quality=quality_report,
        verify_results=verify_list,
        repair_results=repair_dicts,
        vmp=vmp_data,
        lang=lang,
    )
    html_dest = report_html or (output / "audit_report.html")
    html_dest.parent.mkdir(parents=True, exist_ok=True)
    html_dest.write_text(ReportGenerator.render(audit, "html", lang=lang))
    _emit(on_event, "report_done", {"audit": audit, "report_html": html_dest, "apk": apk})

    return {
        "target": str(apk),
        "mode": "offline",
        "grade": audit.grade,
        "risk_score": audit.risk_score,
        "findings": len(audit.findings),
        "extracted_dex": [p.name for p in extracted],
        "report_html": str(html_dest),
        "repacked": str(repacked_path) if repacked_path else None,
    }


__all__ = [
    "PipelineEventCallback",
    "build_pipeline_plan",
    "run_offline_pipeline",
]
