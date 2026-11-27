"""Thread-safe StudioContext managing samples, bounded caches, artifacts, and persistence."""

from __future__ import annotations

import shutil
import struct
import tempfile
import threading
import time
import uuid
import zipfile
from collections import OrderedDict
from pathlib import Path
from typing import Any

from unpack.studio.jobs import JobManager
from unpack.studio.schemas import (
    dir_fingerprint,
    file_sha256,
    get_logger,
    utc_now_iso,
)
from unpack.studio.security import (
    ALLOWED_UPLOAD_EXTS,
    discover_default_local_roots,
    is_valid_apk_zip,
    is_valid_dex_header,
    safe_filename,
)
from unpack.studio.services.analysis import (
    DexBrowserSession,
    inspect_apk_rich,
    run_doctor_rich,
)

MAX_DEX_CACHE = 8
MAX_ARTIFACTS = 200
MAX_INSPECT_LOCKS = 128
DOCTOR_CACHE_TTL_SECONDS = 15.0

logger = get_logger("unpack.studio.context")


def _count_apk_dex(apk_path: Path) -> int:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            return sum(1 for n in zf.namelist() if n.endswith(".dex") and "/" not in n)
    except Exception:
        logger.debug("Failed to count DEX entries in %s", apk_path, exc_info=True)
        return 0


def _dex_quick_meta(name: str, head: bytes, full_size: int | None = None) -> dict[str, Any]:
    sz = full_size if full_size is not None else len(head)
    magic = ""
    classes = methods = strings = 0
    valid_magic = False
    if len(head) >= 0x70 and head[:4] in (b"dex\n", b"cdex"):
        valid_magic = True
        magic = head[:7].decode("ascii", errors="replace").replace("\n", " ")
        strings = struct.unpack_from("<I", head, 56)[0]
        methods = struct.unpack_from("<I", head, 88)[0]
        classes = struct.unpack_from("<I", head, 96)[0]
    return {
        "name": name,
        "size_bytes": sz,
        "size_kb": round(sz / 1024, 1),
        "magic": magic,
        "valid_magic": valid_magic,
        "classes": classes,
        "methods": methods,
        "strings": strings,
    }


def _relative_display_path(p: Path, roots: list[Path]) -> str:
    for r in roots:
        try:
            rel = p.resolve().relative_to(r.resolve())
            return f"{r.name}/{rel.as_posix()}" if str(rel) != "." else r.name
        except ValueError:
            continue
    return p.name


class StudioContext:
    """Encapsulates all runtime state, bounded caches, and stores for one Studio app instance."""

    def __init__(
        self,
        *,
        local_roots: list[Path | str] | None = None,
        workspace_dir: Path | str | None = None,
        max_artifacts: int = MAX_ARTIFACTS,
        max_dex_cache: int = MAX_DEX_CACHE,
        max_inspect_locks: int = MAX_INSPECT_LOCKS,
    ):
        from unpack.core.ai_engine import AIConfigStore
        from unpack.core.workspace_store import DEFAULT_WORKSPACE_ID, WorkspaceStore

        self.default_workspace_id = DEFAULT_WORKSPACE_ID
        self.started_mono = time.monotonic()
        self.started_at = utc_now_iso()

        self.allowed_local_roots: list[Path] = (
            [Path(r).resolve() for r in local_roots if Path(r).exists()]
            if local_roots is not None
            else discover_default_local_roots()
        )

        self.workspace_root = Path(tempfile.mkdtemp(prefix="unpack_studio_"))
        self.uploads_dir = self.workspace_root / "uploads"
        self.artifacts_dir = self.workspace_root / "artifacts"
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        if workspace_dir is not None:
            ws_base = Path(workspace_dir).expanduser()
            self.ws_store = WorkspaceStore(base_dir=ws_base / "studio")
            self.ai_config_store = AIConfigStore(base_dir=ws_base)
        else:
            self.ws_store = WorkspaceStore()
            self.ai_config_store = AIConfigStore()
        self.ws_store.ensure_default_workspace()

        self.lock = threading.RLock()
        self._active_workspace_id: str = DEFAULT_WORKSPACE_ID
        self._max_artifacts = max(1, int(max_artifacts))
        self._max_dex_cache = max(1, int(max_dex_cache))
        self._max_inspect_locks = max(1, int(max_inspect_locks))

        self.samples: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.artifacts: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.inspect_locks: OrderedDict[str, threading.Lock] = OrderedDict()
        self.dex_sessions: OrderedDict[tuple[str, str], DexBrowserSession] = OrderedDict()
        self._doctor_cache: dict[str, Any] = {"ts": 0.0, "data": None}

        self.job_mgr = JobManager(on_finish=self.persist_job_run)
        self.restore_workspace_samples(DEFAULT_WORKSPACE_ID)

    # ── Lifecycle & Health ──

    def cleanup(self) -> None:
        try:
            self.job_mgr.shutdown()
        except Exception:
            logger.debug("Error shutting down JobManager", exc_info=True)
        try:
            self.ws_store.close()
        except Exception:
            logger.debug("Error closing WorkspaceStore", exc_info=True)
        shutil.rmtree(self.workspace_root, ignore_errors=True)

    def active_ws_id(self) -> str:
        with self.lock:
            return self._active_workspace_id

    def health_metrics(self) -> dict[str, Any]:
        with self.lock:
            sample_count = len(self.samples)
            artifact_count = len(self.artifacts)
            dex_cache_count = len(self.dex_sessions)
        job_stats = self.job_mgr.stats()
        try:
            ws_count = len(self.ws_store.list_workspaces())
        except Exception:
            logger.debug("Failed to count workspaces for health endpoint", exc_info=True)
            ws_count = 1
        try:
            ai_configured = bool(self.ai_config_store.load().configured)
        except Exception:
            logger.debug("Failed to inspect AI config for health endpoint", exc_info=True)
            ai_configured = False
        return {
            "uptime_seconds": round(time.monotonic() - self.started_mono, 2),
            "started_at": self.started_at,
            "sample_count": sample_count,
            "artifact_count": artifact_count,
            "dex_cache_count": dex_cache_count,
            "workspace_count": ws_count,
            "active_workspace_id": self.active_ws_id(),
            "active_jobs": job_stats["active_jobs"],
            "total_jobs": job_stats["total_jobs"],
            "capabilities": {
                "ai_configured": ai_configured,
                "local_library_enabled": bool(self.allowed_local_roots),
                "sse_streaming": True,
                "persistent_workspaces": True,
            },
        }

    # ── Persistence & Auto-Relocation ──

    def persist_sample(self, record: dict[str, Any], ws_id: str | None = None) -> None:
        """Persist sample snapshot and analysis results into WorkspaceStore."""
        target_ws = ws_id or record.get("workspace_id") or self.active_ws_id()
        try:
            path_obj = record.get("path")
            src_path = str(path_obj) if path_obj else str(record.get("source_path") or "")
            saved = self.ws_store.save_sample(
                target_ws,
                {
                    "sample_id": record["id"],
                    "filename": record["name"],
                    "sha256": record.get("sha256", ""),
                    "kind": record.get("kind", "apk"),
                    "size_bytes": int(record.get("size_bytes") or 0),
                    "source_path": src_path,
                    "scan_result": record.get("scan_result"),
                    "inspect_result": record.get("inspect_result"),
                    "vmp_result": record.get("vmp_result"),
                    "xref_result": record.get("xref_result"),
                    "repair_result": record.get("repair_diffs"),
                    "notes": record.get("notes", ""),
                    "bookmarks": record.get("bookmarks", []),
                    "ai_analyses": record.get("ai_analyses", []),
                },
            )
            with self.lock:
                record["workspace_id"] = saved["workspace_id"]
                record["updated_at"] = saved["updated_at"]
        except Exception:
            logger.debug("Failed to persist sample %s", record.get("id"), exc_info=True)

    def persist_job_run(self, job_snap: dict[str, Any]) -> None:
        ws_id = job_snap.get("workspace_id") or self.active_ws_id()
        try:
            stages = job_snap.get("stages") or []
            done_cnt = sum(1 for st in stages if st.get("status") == "done")
            summary = (
                f"{job_snap.get('mode', 'pipeline')} · {done_cnt}/{len(stages)} stages"
                if stages
                else f"{job_snap.get('phase', '')}"
            )
            self.ws_store.save_pipeline_run(
                ws_id,
                {
                    "id": job_snap["id"],
                    "sample_id": job_snap.get("sample_id") or job_snap.get("apk_hash"),
                    "name": f"{job_snap.get('mode', 'pipeline')}:{job_snap.get('apk', '')}",
                    "stage": job_snap.get("phase", ""),
                    "status": job_snap.get("status", "done"),
                    "started_at": job_snap.get("created_at", ""),
                    "finished_at": job_snap.get("finished_at") or utc_now_iso(),
                    "duration_ms": int(job_snap.get("duration_ms") or 0),
                    "summary": summary,
                    "error": job_snap.get("error") or "",
                    "stages": stages,
                    "payload": {
                        "apk": job_snap.get("apk"),
                        "mode": job_snap.get("mode"),
                        "phases": job_snap.get("phases", {}),
                    },
                },
            )
            sid = job_snap.get("sample_id") or job_snap.get("apk_hash")
            if sid:
                rec = self.get_sample(str(sid))
                if rec is not None:
                    self.persist_sample(rec, ws_id=ws_id)
        except Exception:
            logger.debug("Failed to persist job run %s", job_snap.get("id"), exc_info=True)

    def restore_workspace_samples(self, ws_id: str) -> list[dict[str, Any]]:
        """Load persisted samples for ``ws_id`` into the active vault (with SHA-256 auto-relocation)."""
        persisted = self.ws_store.list_samples(workspace_id=ws_id)
        with self.lock:
            self._active_workspace_id = ws_id
            self.samples.clear()
            self.dex_sessions.clear()
            for item in reversed(persisted):
                sid = str(item["sample_id"])
                raw_src = str(item.get("source_path") or "").strip()
                kind = str(item.get("kind") or "apk")
                p_obj: Path | None = None
                file_ok = False
                if raw_src:
                    cand = Path(raw_src)
                    if cand.exists():
                        p_obj = cand
                        file_ok = True

                # Auto-relocate local-library samples when workspace/repo directory was moved
                if not file_ok and self.allowed_local_roots:
                    target_name = Path(raw_src).name if raw_src else str(item.get("filename") or "")
                    expected_sha = str(item.get("sha256") or "")
                    if target_name:
                        for root in self.allowed_local_roots:
                            relocated = root / target_name
                            if not relocated.exists():
                                continue
                            if kind == "dex_dir" and relocated.is_dir():
                                p_obj = relocated.resolve()
                                raw_src = str(p_obj)
                                file_ok = True
                                break
                            if kind in {"apk", "dex"} and relocated.is_file():
                                if not expected_sha or file_sha256(relocated) == expected_sha:
                                    p_obj = relocated.resolve()
                                    raw_src = str(p_obj)
                                    file_ok = True
                                    break

                dex_cnt = 0
                if file_ok and p_obj is not None:
                    if kind == "dex":
                        dex_cnt = 1
                    elif kind == "dex_dir":
                        dex_cnt = len([p for p in p_obj.glob("*.dex") if p.is_file()])
                    elif kind == "apk":
                        dex_cnt = _count_apk_dex(p_obj)
                elif item.get("inspect_result") and isinstance(item["inspect_result"], dict):
                    dex_cnt = len(item["inspect_result"].get("dex_files") or [])

                work_dir = self.uploads_dir / f"restored_{sid}"
                work_dir.mkdir(parents=True, exist_ok=True)
                repair_diffs = item.get("repair_result")
                verify_res = None
                if isinstance(repair_diffs, list):
                    verify_res = [
                        d["after"] for d in repair_diffs if isinstance(d, dict) and d.get("after")
                    ] or None
                ai_list = self.ws_store.list_ai_analyses(workspace_id=ws_id, sample_id=sid, limit=50)
                if not ai_list and item.get("ai_analyses"):
                    ai_list = list(item["ai_analyses"])

                self.samples[sid] = {
                    "id": sid,
                    "workspace_id": ws_id,
                    "name": item["filename"],
                    "kind": kind,
                    "source": "local" if file_ok else "saved",
                    "path": p_obj,
                    "source_path": raw_src,
                    "file_available": file_ok,
                    "work_dir": work_dir,
                    "display_path": (
                        _relative_display_path(p_obj, self.allowed_local_roots)
                        if (file_ok and p_obj is not None)
                        else f"saved://{item['filename']}"
                    ),
                    "size_bytes": int(item.get("size_bytes") or 0),
                    "sha256": item.get("sha256") or "",
                    "created_at": item.get("created_at") or utc_now_iso(),
                    "updated_at": item.get("updated_at") or utc_now_iso(),
                    "dex_count": dex_cnt,
                    "scan_result": item.get("scan_result"),
                    "inspect_result": item.get("inspect_result"),
                    "vmp_result": item.get("vmp_result"),
                    "xref_result": item.get("xref_result"),
                    "verify_results": verify_res,
                    "repair_diffs": repair_diffs if isinstance(repair_diffs, list) else None,
                    "quality_report": None,
                    "last_job_id": None,
                    "artifacts": [],
                    "notes": item.get("notes") or "",
                    "bookmarks": list(item.get("bookmarks") or []),
                    "ai_analyses": ai_list,
                }
            return [self.public_sample(s) for s in reversed(self.samples.values())]

    # ── Doctor Cache ──

    def get_doctor_cached(self, *, check_devices: bool = True, force_refresh: bool = False) -> dict[str, Any]:
        if not check_devices:
            return run_doctor_rich(check_devices=False)
        now = time.monotonic()
        with self.lock:
            if (
                not force_refresh
                and self._doctor_cache["data"] is not None
                and (now - self._doctor_cache["ts"]) < DOCTOR_CACHE_TTL_SECONDS
            ):
                return self._doctor_cache["data"]
        fresh = run_doctor_rich(check_devices=True)
        with self.lock:
            self._doctor_cache["data"] = fresh
            self._doctor_cache["ts"] = time.monotonic()
        return fresh

    # ── Bounded Artifact Registry ──

    def register_artifact(
        self,
        path: Path,
        name: str,
        kind: str,
        mimetype: str = "application/octet-stream",
    ) -> dict[str, Any]:
        token = uuid.uuid4().hex[:16]
        size = path.stat().st_size if path.exists() else 0
        meta = {
            "token": token,
            "path": path,
            "name": safe_filename(name, "artifact.bin"),
            "kind": kind,
            "size_bytes": size,
            "mimetype": mimetype,
            "created_at": utc_now_iso(),
        }
        with self.lock:
            self.artifacts[token] = meta
            while len(self.artifacts) > self._max_artifacts:
                _, evicted = self.artifacts.popitem(last=False)
                logger.debug("Evicted oldest artifact %s (%s)", evicted["token"], evicted["name"])
        return {
            "token": token,
            "name": meta["name"],
            "kind": kind,
            "size_bytes": size,
            "download_url": f"/api/v1/artifacts/{token}/download",
        }

    def get_artifact(self, token: str) -> dict[str, Any] | None:
        with self.lock:
            meta = self.artifacts.get(token)
            if meta is not None:
                self.artifacts.move_to_end(token)
            return meta

    # ── Sample Vault Helpers ──

    @staticmethod
    def sample_file_exists(sample: dict[str, Any]) -> bool:
        p = sample.get("path")
        return bool(p is not None and Path(p).exists())

    def get_sample(self, sample_id: str) -> dict[str, Any] | None:
        with self.lock:
            return self.samples.get(sample_id)

    def public_sample(self, s: dict[str, Any], include_details: bool = False) -> dict[str, Any]:
        file_ok = self.sample_file_exists(s)
        ai_list = s.get("ai_analyses") or []
        out: dict[str, Any] = {
            "id": s["id"],
            "workspace_id": s.get("workspace_id") or self.active_ws_id(),
            "name": s["name"],
            "kind": s["kind"],
            "source": s["source"],
            "file_available": file_ok,
            "display_path": s["display_path"],
            "size_bytes": s["size_bytes"],
            "size_mb": round(s["size_bytes"] / (1024 * 1024), 2),
            "sha256": s["sha256"],
            "created_at": s["created_at"],
            "updated_at": s.get("updated_at") or s["created_at"],
            "dex_count": s.get("dex_count", 0),
            "packer": (s.get("scan_result") or {}).get("packer_name"),
            "protection_level": (s.get("scan_result") or {}).get("protection_level"),
            "risk_score": (s.get("inspect_result") or {}).get("risk_score")
            or (s.get("scan_result") or {}).get("risk_score"),
            "last_job_id": s.get("last_job_id"),
            "has_scan": s.get("scan_result") is not None,
            "has_inspect": s.get("inspect_result") is not None,
            "has_vmp": s.get("vmp_result") is not None,
            "has_xref": s.get("xref_result") is not None,
            "has_repair": bool(s.get("repair_diffs")),
            "notes": s.get("notes") or "",
            "bookmarks_count": len(s.get("bookmarks") or []),
            "ai_analyses_count": len(ai_list),
        }
        if include_details:
            out["scan_result"] = s.get("scan_result")
            out["inspect_result"] = s.get("inspect_result")
            out["vmp_result"] = s.get("vmp_result")
            out["xref_result"] = s.get("xref_result")
            out["verify_results"] = s.get("verify_results")
            out["repair_diffs"] = s.get("repair_diffs")
            out["artifacts"] = s.get("artifacts", [])
            out["bookmarks"] = list(s.get("bookmarks") or [])
            out["ai_analyses"] = list(ai_list)
        return out

    def save_uploaded_file(self, file_storage) -> dict[str, Any]:
        raw_name = file_storage.filename or ""
        safe_name = safe_filename(raw_name, "")
        ext = Path(safe_name).suffix.lower()
        if not safe_name or ext not in ALLOWED_UPLOAD_EXTS:
            raise ValueError("Only .apk and .dex files are supported")

        tmp_dir = self.uploads_dir / uuid.uuid4().hex[:10]
        tmp_dir.mkdir(parents=True, exist_ok=True)
        dest = tmp_dir / safe_name
        file_storage.save(str(dest))

        if ext == ".apk" and not is_valid_apk_zip(dest):
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise ValueError(f"'{safe_name}' is not a valid APK archive")
        if ext == ".dex" and not is_valid_dex_header(dest):
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise ValueError(f"'{safe_name}' does not have a valid DEX/CDEX header")

        sha = file_sha256(dest)
        sid = sha[:16]
        with self.lock:
            if sid in self.samples:
                existing = self.samples[sid]
                if not self.sample_file_exists(existing):
                    existing["path"] = dest
                    existing["source_path"] = str(dest)
                    existing["source"] = "upload"
                    existing["work_dir"] = tmp_dir
                    existing["file_available"] = True
                    existing["display_path"] = f"upload://{safe_name}"
                else:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                return existing

            dex_count = 1 if ext == ".dex" else _count_apk_dex(dest)
            record = {
                "id": sid,
                "workspace_id": self.active_ws_id(),
                "name": safe_name,
                "kind": "apk" if ext == ".apk" else "dex",
                "source": "upload",
                "path": dest,
                "source_path": str(dest),
                "file_available": True,
                "work_dir": tmp_dir,
                "display_path": f"upload://{safe_name}",
                "size_bytes": dest.stat().st_size,
                "sha256": sha,
                "created_at": utc_now_iso(),
                "updated_at": utc_now_iso(),
                "dex_count": dex_count,
                "scan_result": None,
                "inspect_result": None,
                "vmp_result": None,
                "xref_result": None,
                "verify_results": None,
                "repair_diffs": None,
                "quality_report": None,
                "last_job_id": None,
                "artifacts": [],
                "notes": "",
                "bookmarks": [],
                "ai_analyses": [],
            }
            self.samples[sid] = record
        self.persist_sample(record)
        return record

    def import_local_sample(self, resolved: Path) -> dict[str, Any]:
        if resolved.is_dir():
            sha, total_size, dex_count = dir_fingerprint(resolved)
            if dex_count == 0:
                raise ValueError(f"Directory '{resolved.name}' contains no .dex files")
            kind = "dex_dir"
            name = resolved.name
        else:
            ext = resolved.suffix.lower()
            if ext not in ALLOWED_UPLOAD_EXTS:
                raise ValueError("Local sample must be an .apk, .dex, or DEX directory")
            sha = file_sha256(resolved)
            total_size = resolved.stat().st_size
            kind = "apk" if ext == ".apk" else "dex"
            dex_count = 1 if kind == "dex" else _count_apk_dex(resolved)
            name = resolved.name

        sid = sha[:16]
        with self.lock:
            if sid in self.samples:
                existing = self.samples[sid]
                if not self.sample_file_exists(existing):
                    existing["path"] = resolved
                    existing["source_path"] = str(resolved)
                    existing["source"] = "local"
                    existing["file_available"] = True
                    existing["display_path"] = _relative_display_path(resolved, self.allowed_local_roots)
                return existing

            work_dir = self.uploads_dir / f"local_{sid}"
            work_dir.mkdir(parents=True, exist_ok=True)
            rel_display = _relative_display_path(resolved, self.allowed_local_roots)
            record = {
                "id": sid,
                "workspace_id": self.active_ws_id(),
                "name": name,
                "kind": kind,
                "source": "local",
                "path": resolved,
                "source_path": str(resolved),
                "file_available": True,
                "work_dir": work_dir,
                "display_path": rel_display,
                "size_bytes": total_size,
                "sha256": sha,
                "created_at": utc_now_iso(),
                "updated_at": utc_now_iso(),
                "dex_count": dex_count,
                "scan_result": None,
                "inspect_result": None,
                "vmp_result": None,
                "xref_result": None,
                "verify_results": None,
                "repair_diffs": None,
                "quality_report": None,
                "last_job_id": None,
                "artifacts": [],
                "notes": "",
                "bookmarks": [],
                "ai_analyses": [],
            }
            self.samples[sid] = record
        self.persist_sample(record)
        return record

    def delete_sample(self, sample_id: str) -> dict[str, Any] | None:
        with self.lock:
            sample = self.samples.pop(sample_id, None)
            if sample is None:
                return None
            for k in [k for k in self.dex_sessions if k[0] == sample_id]:
                self.dex_sessions.pop(k, None)
            self.inspect_locks.pop(sample_id, None)
        try:
            self.ws_store.delete_sample(sample_id)
        except Exception:
            logger.debug("Failed to delete persisted sample %s", sample_id, exc_info=True)
        if sample["source"] == "upload" and sample.get("work_dir"):
            shutil.rmtree(sample["work_dir"], ignore_errors=True)
        return sample

    # ── Single-Flight Inspect & DEX Access ──

    def _get_inspect_lock(self, sample_id: str) -> threading.Lock:
        with self.lock:
            if sample_id in self.inspect_locks:
                self.inspect_locks.move_to_end(sample_id)
                return self.inspect_locks[sample_id]
            slock = threading.Lock()
            self.inspect_locks[sample_id] = slock
            while len(self.inspect_locks) > self._max_inspect_locks:
                self.inspect_locks.popitem(last=False)
            return slock

    def ensure_apk_inspect(self, sample: dict[str, Any], force: bool = False) -> dict[str, Any]:
        slock = self._get_inspect_lock(sample["id"])
        with slock:
            if sample["inspect_result"] is None or force:
                if not self.sample_file_exists(sample):
                    return sample.get("inspect_result") or {
                        "file": sample["name"],
                        "sha256": sample["sha256"],
                        "size_bytes": sample["size_bytes"],
                        "manifest": {},
                        "signing": {},
                        "permissions": [],
                        "components": {"activities": [], "services": [], "receivers": [], "providers": []},
                        "native_libs": [],
                        "dex_files": [],
                        "findings": [],
                        "risk_score": 0,
                        "risk_grade": "A",
                        "warnings": ["Original APK file not on disk; showing saved snapshot."],
                    }
                insp = inspect_apk_rich(sample["path"])
                with self.lock:
                    sample["inspect_result"] = insp
                self.persist_sample(sample)
            return sample["inspect_result"]

    def list_sample_dex_entries(self, sample: dict[str, Any]) -> list[dict[str, Any]]:
        path: Path | None = sample.get("path")
        if path is None or not path.exists():
            insp = sample.get("inspect_result") or {}
            return list(insp.get("dex_files") or [])
        kind = sample["kind"]
        entries: list[dict[str, Any]] = []

        if kind == "dex":
            raw = path.read_bytes()
            entries.append(_dex_quick_meta(path.name, raw))
        elif kind == "dex_dir":
            for p in sorted(path.glob("*.dex")):
                if p.is_file():
                    entries.append(_dex_quick_meta(p.name, p.read_bytes()[:0x70], full_size=p.stat().st_size))
        elif kind == "apk":
            with zipfile.ZipFile(path, "r") as zf:
                dex_names = sorted(n for n in zf.namelist() if n.endswith(".dex") and "/" not in n)
                for name in dex_names:
                    info = zf.getinfo(name)
                    with zf.open(name) as fp:
                        head = fp.read(0x70)
                    entries.append(_dex_quick_meta(name, head, full_size=info.file_size))
        return entries

    def read_sample_dex_bytes(self, sample: dict[str, Any], dex_name: str) -> bytes | None:
        safe = safe_filename(dex_name, "")
        if not safe or safe != dex_name:
            return None
        path: Path | None = sample.get("path")
        if path is None or not path.exists():
            return None
        kind = sample["kind"]
        if kind == "dex":
            return path.read_bytes() if path.name == safe else None
        if kind == "dex_dir":
            target = (path / safe).resolve()
            if target.is_relative_to(path.resolve()) and target.is_file():
                return target.read_bytes()
            return None
        if kind == "apk":
            with zipfile.ZipFile(path, "r") as zf:
                if safe in zf.namelist():
                    return zf.read(safe)
        return None

    def get_dex_browser(self, sample: dict[str, Any], dex_name: str) -> DexBrowserSession | None:
        key = (sample["id"], dex_name)
        with self.lock:
            if key in self.dex_sessions:
                self.dex_sessions.move_to_end(key)
                return self.dex_sessions[key]

        raw = self.read_sample_dex_bytes(sample, dex_name)
        if raw is None:
            return None
        session = DexBrowserSession(raw, dex_name)
        with self.lock:
            self.dex_sessions[key] = session
            while len(self.dex_sessions) > self._max_dex_cache:
                self.dex_sessions.popitem(last=False)
        return session

    def extract_sample_dex_files(
        self,
        sample: dict[str, Any],
        target_dir: Path,
        dex_names: list[str] | None = None,
    ) -> list[Path]:
        """Materialize selected or all DEX files of ``sample`` into ``target_dir``."""
        target_dir.mkdir(parents=True, exist_ok=True)
        path: Path | None = sample.get("path")
        if path is None or not path.exists():
            return []
        kind = sample["kind"]
        out: list[Path] = []
        wanted = set(dex_names) if dex_names else None

        if kind == "dex":
            if wanted is None or path.name in wanted:
                dst = target_dir / path.name
                shutil.copy2(path, dst)
                out.append(dst)
        elif kind == "dex_dir":
            for p in sorted(path.glob("*.dex")):
                if p.is_file() and (wanted is None or p.name in wanted):
                    dst = target_dir / p.name
                    shutil.copy2(p, dst)
                    out.append(dst)
        elif kind == "apk":
            with zipfile.ZipFile(path, "r") as zf:
                for name in sorted(zf.namelist()):
                    if name.endswith(".dex") and "/" not in name:
                        if wanted is None or name in wanted:
                            dst = target_dir / safe_filename(name, "classes.dex")
                            dst.write_bytes(zf.read(name))
                            out.append(dst)
        return out
