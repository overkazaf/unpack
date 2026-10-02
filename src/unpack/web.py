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
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512 MB

    _jobs: dict[str, dict] = {}

    # ── Pages ──

    @app.route("/")
    def index():
        return render_template("index.html")

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
