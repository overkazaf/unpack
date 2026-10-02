"""UNPACK Web UI — Flask-based single-page interface for scan/dump/repair/verify."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path

os.environ.setdefault("LOGURU_LEVEL", "ERROR")

from flask import Flask, jsonify, render_template, request


def create_app() -> Flask:
    import hashlib

    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512 MB

    _jobs: dict[str, dict] = {}
    # APK cache: sha256 -> {path, filename, scan_result, work_dir}
    _cache: dict[str, dict] = {}
    _cache_dir = Path(tempfile.mkdtemp(prefix="unpack_cache_"))

    def _file_hash(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()[:16]

    # ── Error handlers (always return JSON, never HTML) ──

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify(error=str(e)), 400

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify(error="Not found"), 404
        return render_template("index.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify(error=str(e)), 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        if request.path.startswith("/api/"):
            return jsonify(error=str(e)), 500
        return render_template("index.html"), 500

    # ── Pages ──

    @app.route("/")
    def index():
        return render_template("index.html")

    # ── Cache: list cached APKs ──

    @app.get("/api/cache")
    def api_cache():
        items = []
        for h, c in _cache.items():
            item = {"hash": h, "filename": c["filename"], "size_mb": round(c["path"].stat().st_size / 1024 / 1024, 1)}
            if c.get("scan_result"):
                item["packer"] = c["scan_result"].get("packer_name")
            if c.get("last_job"):
                item["last_job"] = c["last_job"]
            items.append(item)
        return jsonify(items=items)

    # ── Full pipeline (one-click) ──

    @app.post("/api/full")
    def api_full():
        engine = request.form.get("engine", "")
        timeout_s = int(request.form.get("timeout", "15"))
        deep = request.form.get("deep", "false") == "true"
        anti_detect = request.form.get("anti_detect", "true") == "true"
        start_from = request.form.get("start_from", "scan")
        cached_hash = request.form.get("apk_hash", "")

        # Resolve APK: from cache or new upload
        if cached_hash and cached_hash in _cache:
            entry = _cache[cached_hash]
            apk_path = entry["path"]
            work_dir = entry["work_dir"]
            filename = entry["filename"]
        elif "file" in request.files and request.files["file"].filename:
            f = request.files["file"]
            if not f.filename.endswith(".apk"):
                return jsonify(error="File must be an .apk"), 400
            # Save to persistent cache dir
            work_dir = _cache_dir / str(uuid.uuid4())[:8]
            work_dir.mkdir(parents=True, exist_ok=True)
            apk_path = work_dir / f.filename
            f.save(str(apk_path))
            filename = f.filename
            h = _file_hash(apk_path)
            # Dedup: if same APK already cached, reuse
            if h in _cache:
                apk_path.unlink(missing_ok=True)
                work_dir.rmdir()
                entry = _cache[h]
                apk_path = entry["path"]
                work_dir = entry["work_dir"]
                filename = entry["filename"]
            else:
                _cache[h] = {"path": apk_path, "filename": filename, "work_dir": work_dir, "scan_result": None, "last_job": None}
            cached_hash = h
        else:
            return jsonify(error="No file uploaded and no cached APK specified"), 400

        job_id = str(uuid.uuid4())[:8]
        output_dir = work_dir / f"output_{job_id}"
        output_dir.mkdir(parents=True, exist_ok=True)
        if cached_hash:
            _cache[cached_hash]["last_job"] = job_id

        _jobs[job_id] = {
            "status": "running",
            "phase": start_from,
            "phases": {},
            "apk": filename,
            "apk_hash": cached_hash,
            "error": None,
        }

        # Pre-populate cached phases
        if start_from != "scan" and cached_hash and _cache.get(cached_hash, {}).get("scan_result"):
            _jobs[job_id]["phases"]["scan"] = _cache[cached_hash]["scan_result"]

        def _run_full():
            try:
                from unpack.core.scanner import PackerScanner, ProtectionLevel
                from unpack.core.dispatcher import Dispatcher
                from unpack.core.reporter import Reporter
                from unpack.core.dedup import dedup_dex_files
                from unpack.repair.dex_repair import DexRepairPipeline

                # Phase 1: Scan (skip if cached and start_from is later)
                if start_from == "scan" or "scan" not in _jobs[job_id]["phases"]:
                    _jobs[job_id]["phase"] = "scanning"
                    scanner = PackerScanner()
                    scan_result = scanner.scan(apk_path, verbose=True)
                    scan_dict = scan_result.to_verbose_dict()
                    _jobs[job_id]["phases"]["scan"] = scan_dict
                    if cached_hash:
                        _cache[cached_hash]["scan_result"] = scan_dict
                else:
                    scan_dict = _jobs[job_id]["phases"]["scan"]
                    scanner = PackerScanner()
                    scan_result = scanner.scan(apk_path)

                if start_from == "scan_only":
                    _jobs[job_id]["status"] = "done"
                    _jobs[job_id]["phase"] = "done"
                    return

                # Phase 2: Dump
                _jobs[job_id]["phase"] = "dumping"
                dispatcher = Dispatcher()
                dump_result = dispatcher.dispatch(
                    apk=apk_path,
                    scan_result=scan_result,
                    output_dir=output_dir,
                    force_engine=engine or None,
                    timeout=timeout_s if timeout_s > 0 else None,
                    anti_detect=anti_detect,
                )

                if not dump_result.dex_files:
                    _jobs[job_id]["status"] = "failed"
                    _jobs[job_id]["error"] = dump_result.error or "No DEX files dumped"
                    return

                _jobs[job_id]["phases"]["dump"] = {
                    "dex_count": len(dump_result.dex_files),
                    "so_count": len(dump_result.so_files),
                    "duration_ms": dump_result.duration_ms,
                    "engine": dump_result.engine.value,
                }

                # Phase 2.5: Dedup
                unique = dedup_dex_files(output_dir)
                removed = len(dump_result.dex_files) - len(unique)
                if removed > 0:
                    _jobs[job_id]["phases"]["dump"]["duplicates_removed"] = removed

                # Phase 3: Deep mode (optional)
                if deep and scan_result.protection_level in (
                    ProtectionLevel.FUNCTION_EXTRACTION, ProtectionLevel.VMP,
                ):
                    _jobs[job_id]["phase"] = "active_invoke"
                    try:
                        from unpack.engines.active_invoke import ActiveInvoker
                        from unpack.repair.codeitem_merger import CodeItemMerger
                        from unpack.utils.apk import get_package_name

                        pkg = get_package_name(apk_path)
                        if pkg:
                            invoker = ActiveInvoker(
                                wait_seconds=timeout_s if timeout_s > 0 else 15,
                                anti_detect=anti_detect,
                            )
                            inv_result = invoker.invoke(pkg, output_dir)
                            if inv_result.code_items:
                                merger = CodeItemMerger()
                                total_merged = 0
                                for dex in unique:
                                    mr = merger.merge(dex, inv_result.code_items)
                                    total_merged += mr.methods_merged
                                _jobs[job_id]["phases"]["active_invoke"] = {
                                    "code_items_captured": len(inv_result.code_items),
                                    "methods_merged": total_merged,
                                }
                    except ImportError:
                        pass

                # Phase 4: Repair
                _jobs[job_id]["phase"] = "repairing"
                pipeline = DexRepairPipeline()
                repair_results = []
                for dex_path in unique:
                    rr = pipeline.repair(dex_path, in_place=True)
                    repair_results.append({
                        "file": dex_path.name,
                        "success": rr.success,
                        "actions": rr.actions,
                    })
                _jobs[job_id]["phases"]["repair"] = repair_results

                # Phase 5: Verify
                _jobs[job_id]["phase"] = "verifying"
                reporter = Reporter()
                report = reporter.evaluate(output_dir, scan_result)
                _jobs[job_id]["phases"]["report"] = report.to_dict()

                _jobs[job_id]["status"] = "done"
                _jobs[job_id]["phase"] = "done"

            except Exception as exc:
                _jobs[job_id]["status"] = "failed"
                _jobs[job_id]["error"] = str(exc)

        threading.Thread(target=_run_full, daemon=True).start()
        return jsonify(job_id=job_id, apk_hash=cached_hash)

    @app.get("/api/job/<job_id>")
    def api_job_status(job_id: str):
        job = _jobs.get(job_id)
        if not job:
            return jsonify(error="Job not found"), 404
        return jsonify(job)

    # ── Job result export (for LLM/agent integration) ──

    @app.get("/api/job/<job_id>/export")
    def api_job_export(job_id: str):
        """Export full job result as structured JSON for LLM consumption."""
        job = _jobs.get(job_id)
        if not job:
            return jsonify(error="Job not found"), 404
        if job["status"] != "done":
            return jsonify(error="Job not finished yet", status=job["status"]), 400

        export = {
            "tool": "unpack",
            "version": "0.1.0",
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
        return jsonify(export)

    # ── Scan ──

    @app.post("/api/scan")
    def api_scan():
        if "file" not in request.files:
            return jsonify(error="No file uploaded"), 400
        f = request.files["file"]
        if not f.filename or not f.filename.endswith(".apk"):
            return jsonify(error="File must be an .apk"), 400

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            f.save(tmp)
            tmp_path = Path(tmp.name)

        try:
            from unpack.core.scanner import PackerScanner
            scanner = PackerScanner()
            result = scanner.scan(tmp_path, verbose=True)
            return jsonify(result.to_verbose_dict())
        except Exception as exc:
            return jsonify(error=str(exc)), 500
        finally:
            tmp_path.unlink(missing_ok=True)

    # ── Engines ──

    @app.get("/api/engines")
    def api_engines():
        engines = []
        try:
            from unpack.engines.frida_engine import FridaEngine
            fe = FridaEngine()
            avail = fe.is_available()
            engines.append({"name": "frida", "available": avail, "reason": "" if avail else "frida not installed or no device"})
        except Exception:
            engines.append({"name": "frida", "available": False, "reason": "import error"})

        try:
            from unpack.engines.memory_engine import MemoryEngine
            me = MemoryEngine()
            avail = me.is_available()
            engines.append({"name": "memory", "available": avail, "reason": "" if avail else (me.unavailable_reason or "")})
        except Exception:
            engines.append({"name": "memory", "available": False, "reason": "import error"})

        try:
            from unpack.engines.ebpf_engine import EbpfEngine
            ee = EbpfEngine()
            avail = ee.is_available()
            engines.append({"name": "ebpf", "available": avail, "reason": "" if avail else (ee.unavailable_reason or "")})
        except Exception:
            engines.append({"name": "ebpf", "available": False, "reason": "import error"})

        return jsonify(engines=engines)

    # ── Dump (async) ──

    @app.post("/api/dump")
    def api_dump():
        if "file" not in request.files:
            return jsonify(error="No file uploaded"), 400
        f = request.files["file"]
        if not f.filename:
            return jsonify(error="No filename"), 400

        engine = request.form.get("engine", "")
        timeout_s = int(request.form.get("timeout", "15"))
        deep = request.form.get("deep", "false") == "true"
        anti_detect = request.form.get("anti_detect", "true") == "true"

        job_id = str(uuid.uuid4())[:8]
        work_dir = Path(tempfile.mkdtemp(prefix=f"unpack_{job_id}_"))
        apk_path = work_dir / f.filename
        f.save(str(apk_path))
        output_dir = work_dir / "output"
        output_dir.mkdir()

        _jobs[job_id] = {
            "status": "running",
            "phase": "starting",
            "apk": f.filename,
            "engine": engine or "auto",
            "output_dir": str(output_dir),
            "result": None,
            "error": None,
        }

        def _run():
            try:
                from unpack.core.scanner import PackerScanner
                from unpack.core.dispatcher import Dispatcher
                from unpack.core.reporter import Reporter
                from unpack.repair.dex_repair import DexRepairPipeline

                _jobs[job_id]["phase"] = "scanning"
                scanner = PackerScanner()
                scan_result = scanner.scan(apk_path, verbose=True)

                _jobs[job_id]["phase"] = "dumping"
                dispatcher = Dispatcher()
                dump_result = dispatcher.dispatch(
                    apk=apk_path,
                    scan_result=scan_result,
                    output_dir=output_dir,
                    force_engine=engine or None,
                    timeout=timeout_s if timeout_s > 0 else None,
                    anti_detect=anti_detect,
                )

                if not dump_result.dex_files:
                    _jobs[job_id]["status"] = "failed"
                    _jobs[job_id]["error"] = dump_result.error or "No DEX files dumped"
                    return

                _jobs[job_id]["phase"] = "repairing"
                pipeline = DexRepairPipeline()
                repair_results = []
                for dex_path in dump_result.dex_files:
                    rr = pipeline.repair(dex_path)
                    repair_results.append({
                        "file": dex_path.name,
                        "success": rr.success,
                        "actions": rr.actions,
                    })

                _jobs[job_id]["phase"] = "verifying"
                reporter = Reporter()
                report = reporter.evaluate(output_dir, scan_result)

                _jobs[job_id]["status"] = "done"
                _jobs[job_id]["result"] = {
                    "scan": scan_result.to_verbose_dict(),
                    "dex_count": len(dump_result.dex_files),
                    "duration_ms": dump_result.duration_ms,
                    "repairs": repair_results,
                    "report": report.to_dict(),
                }
            except Exception as exc:
                _jobs[job_id]["status"] = "failed"
                _jobs[job_id]["error"] = str(exc)

        threading.Thread(target=_run, daemon=True).start()
        return jsonify(job_id=job_id)

    @app.get("/api/dump/<job_id>")
    def api_dump_status(job_id: str):
        job = _jobs.get(job_id)
        if not job:
            return jsonify(error="Job not found"), 404
        return jsonify(job)

    # ── Repair ──

    @app.post("/api/repair")
    def api_repair():
        if "files" not in request.files:
            return jsonify(error="No files uploaded"), 400

        files = request.files.getlist("files")
        in_place = request.form.get("in_place", "false") == "true"

        from unpack.repair.dex_repair import DexRepairPipeline
        pipeline = DexRepairPipeline()
        results = []

        with tempfile.TemporaryDirectory(prefix="unpack_repair_") as td:
            for f in files:
                if not f.filename:
                    continue
                fpath = Path(td) / f.filename
                f.save(str(fpath))
                rr = pipeline.repair(fpath, in_place=in_place)
                results.append({
                    "file": f.filename,
                    "success": rr.success,
                    "actions": rr.actions,
                    "nop_methods": rr.nop_method_count,
                })

        return jsonify(results=results)

    # ── Verify ──

    @app.post("/api/verify")
    def api_verify():
        if "files" not in request.files:
            return jsonify(error="No files uploaded"), 400

        files = request.files.getlist("files")

        from unpack.repair.verifier import DexVerifier
        verifier = DexVerifier()
        results = []

        with tempfile.TemporaryDirectory(prefix="unpack_verify_") as td:
            for f in files:
                if not f.filename:
                    continue
                fpath = Path(td) / f.filename
                f.save(str(fpath))
                vr = verifier.verify(fpath)
                results.append({
                    "file": f.filename,
                    "valid": vr.valid,
                    "issues": vr.issues,
                    "stats": vr.stats,
                })

        return jsonify(results=results)

    return app


def main():
    app = create_app()
    print("UNPACK Web UI: http://127.0.0.1:8080")
    app.run(host="127.0.0.1", port=8080, debug=False)


if __name__ == "__main__":
    main()
