"""Thread-safe JobManager with bounded ThreadPoolExecutor and SSE pub/sub."""

from __future__ import annotations

import copy
import json
import queue
import threading
import uuid
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable

from unpack.studio.schemas import get_logger, utc_now_iso

MAX_JOBS_RETAINED = 100
DEFAULT_MAX_WORKERS = 4
MAX_SUBSCRIBERS_PER_JOB = 16

logger = get_logger("unpack.studio.jobs")


class JobManager:
    """Thread-safe async job tracker with bounded worker pool and SSE event streaming."""

    def __init__(
        self,
        max_jobs: int = MAX_JOBS_RETAINED,
        max_workers: int = DEFAULT_MAX_WORKERS,
        on_finish: Callable[[dict[str, Any]], None] | None = None,
    ):
        self._lock = threading.RLock()
        self._jobs: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._cancel_events: dict[str, threading.Event] = {}
        self._subscribers: dict[str, list[queue.Queue]] = {}
        self._max_jobs = max(1, int(max_jobs))
        self._on_finish = on_finish
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(max_workers)),
            thread_name_prefix="unpack-studio-job",
        )
        self._shutdown = False

    def submit(self, fn: Callable[[], None]) -> Future[None]:
        """Submit a background job worker to the bounded thread pool."""
        return self._executor.submit(fn)

    def shutdown(self) -> None:
        """Cancel pending/running jobs and shut down the worker pool gracefully."""
        with self._lock:
            self._shutdown = True
            for ev in self._cancel_events.values():
                ev.set()
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            self._executor.shutdown(wait=False)

    def stats(self) -> dict[str, int]:
        with self._lock:
            total = len(self._jobs)
            active = sum(1 for j in self._jobs.values() if j["status"] == "running")
            subs = sum(len(v) for v in self._subscribers.values())
            return {"total_jobs": total, "active_jobs": active, "sse_subscribers": subs}

    def create_job(
        self,
        *,
        job_type: str,
        apk: str,
        apk_hash: str = "",
        sample_id: str = "",
        phase: str = "queued",
        extra: dict[str, Any] | None = None,
    ) -> str:
        job_id = str(uuid.uuid4())[:8]
        now = utc_now_iso()
        job: dict[str, Any] = {
            "id": job_id,
            "type": job_type,
            "status": "running",
            "phase": phase,
            "progress": 0,
            "apk": apk,
            "apk_hash": apk_hash,
            "sample_id": sample_id or apk_hash,
            "mode": (extra or {}).get("mode", "legacy"),
            "stages": list((extra or {}).get("stages", [])),
            "phases": {},
            "result": None,
            "error": None,
            "logs": [],
            "artifacts": [],
            "created_at": now,
            "finished_at": None,
            "duration_ms": 0,
        }
        if extra:
            for k, v in extra.items():
                if k != "stages":
                    job[k] = v

        with self._lock:
            self._jobs[job_id] = job
            self._cancel_events[job_id] = threading.Event()
            self._subscribers[job_id] = []
            self._evict_locked()
        return job_id

    def _evict_locked(self) -> None:
        while len(self._jobs) > self._max_jobs:
            evict_id = None
            for jid, job in self._jobs.items():
                if job["status"] in {"done", "failed", "cancelled"}:
                    evict_id = jid
                    break
            if evict_id is None:
                break
            self._jobs.pop(evict_id, None)
            self._cancel_events.pop(evict_id, None)
            self._subscribers.pop(evict_id, None)

    def _snapshot_locked(self, job: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(job)

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return self._snapshot_locked(job) if job is not None else None

    def list_all(self) -> list[dict[str, Any]]:
        with self._lock:
            items = []
            for job in reversed(self._jobs.values()):
                items.append(
                    {
                        "id": job["id"],
                        "type": job["type"],
                        "status": job["status"],
                        "phase": job["phase"],
                        "progress": job["progress"],
                        "apk": job["apk"],
                        "sample_id": job["sample_id"],
                        "created_at": job["created_at"],
                        "finished_at": job["finished_at"],
                        "duration_ms": job["duration_ms"],
                        "error": job["error"],
                        "artifact_count": len(job.get("artifacts", [])),
                    }
                )
            return items

    def is_cancelled(self, job_id: str) -> bool:
        with self._lock:
            ev = self._cancel_events.get(job_id)
            return ev.is_set() if ev else False

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            ev = self._cancel_events.get(job_id)
            if ev:
                ev.set()
            if job["status"] == "running":
                job["status"] = "cancelled"
                job["phase"] = "cancelled"
                job["finished_at"] = utc_now_iso()
                self._append_log_locked(job_id, "warn", "cancelled", "Cancellation requested by user.")
                self._broadcast_locked(job_id, "cancelled", {"status": "cancelled", "phase": "cancelled"})
            return True

    def log(self, job_id: str, message: str, *, level: str = "info", phase: str | None = None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            entry = self._append_log_locked(job_id, level, phase or job["phase"], message)
            self._broadcast_locked(job_id, "log", entry)

    def _append_log_locked(self, job_id: str, level: str, phase: str, message: str) -> dict[str, Any]:
        entry = {"ts": utc_now_iso(), "level": level, "phase": phase, "message": message}
        logs = self._jobs[job_id]["logs"]
        logs.append(entry)
        if len(logs) > 500:
            del logs[:100]
        return entry

    def set_phase(self, job_id: str, phase: str, progress: int | None = None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["phase"] = phase
            if progress is not None:
                job["progress"] = progress
            self._broadcast_locked(job_id, "phase", {"phase": phase, "progress": job["progress"]})

    def set_phase_data(self, job_id: str, key: str, data: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["phases"][key] = data
            self._broadcast_locked(job_id, "phase_data", {"key": key, "data": data})

    def add_artifact(self, job_id: str, artifact: dict[str, Any]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["artifacts"].append(artifact)
            self._broadcast_locked(job_id, "artifact", artifact)

    def update_stage(
        self,
        job_id: str,
        stage_id: str,
        *,
        status: str,
        duration_ms: int | None = None,
        summary: str | None = None,
        metrics: dict[str, Any] | None = None,
        artifacts: list[dict[str, Any]] | None = None,
        next_hint: str | None = None,
        log_message: str | None = None,
        log_level: str = "info",
    ) -> None:
        """Update per-stage structured telemetry and emit an SSE ``stage`` event."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            stage_obj = None
            for st in job.setdefault("stages", []):
                if st.get("id") == stage_id or st.get("stage_id") == stage_id:
                    stage_obj = st
                    break
            if stage_obj is None:
                stage_obj = {
                    "id": stage_id,
                    "stage_id": stage_id,
                    "status": status,
                    "duration_ms": 0,
                    "summary": "",
                    "metrics": {},
                    "artifacts": [],
                    "next_hint": "",
                    "logs": [],
                }
                job["stages"].append(stage_obj)

            stage_obj["stage_id"] = stage_id
            stage_obj["status"] = status
            if duration_ms is not None:
                stage_obj["duration_ms"] = int(duration_ms)
            if summary is not None:
                stage_obj["summary"] = summary
            if metrics is not None:
                stage_obj["metrics"] = dict(metrics)
            if artifacts is not None:
                stage_obj["artifacts"] = list(artifacts)
            if next_hint is not None:
                stage_obj["next_hint"] = next_hint
            if log_message:
                entry = self._append_log_locked(job_id, log_level, stage_id, log_message)
                stage_obj.setdefault("logs", []).append(entry)
                self._broadcast_locked(job_id, "log", entry)

            payload = {
                "stage_id": stage_id,
                "status": stage_obj["status"],
                "duration_ms": stage_obj.get("duration_ms", 0),
                "summary": stage_obj.get("summary", ""),
                "metrics": stage_obj.get("metrics", {}),
                "artifacts": stage_obj.get("artifacts", []),
                "next_hint": stage_obj.get("next_hint", ""),
                "logs": stage_obj.get("logs", [])[-50:],
            }
            self._broadcast_locked(job_id, "stage", payload)

    def finish(
        self,
        job_id: str,
        *,
        status: str = "done",
        result: Any = None,
        error: str | None = None,
        duration_ms: int = 0,
    ) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            if job["status"] == "cancelled":
                return
            job["status"] = status
            if status == "done":
                job["phase"] = "done"
                job["progress"] = 100
            if result is not None:
                job["result"] = result
            if error is not None:
                job["error"] = error
            job["finished_at"] = utc_now_iso()
            job["duration_ms"] = duration_ms
            snapshot = self._snapshot_locked(job)
        if self._on_finish is not None:
            try:
                self._on_finish(snapshot)
            except Exception:
                logger.debug("Job on_finish persistence callback failed for %s", job_id, exc_info=True)
        with self._lock:
            self._broadcast_locked(
                job_id,
                status,
                {"status": status, "phase": snapshot["phase"], "progress": snapshot["progress"], "error": error},
            )

    def _broadcast_locked(self, job_id: str, event: str, payload: Any) -> None:
        for q in list(self._subscribers.get(job_id, [])):
            try:
                q.put_nowait((event, payload))
            except queue.Full:
                logger.debug("Dropping SSE event %s for slow subscriber on job %s", event, job_id)

    def subscribe(self, job_id: str) -> tuple[dict[str, Any] | None, queue.Queue]:
        q: queue.Queue = queue.Queue(maxsize=256)
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None, q
            snapshot = self._snapshot_locked(job)
            subs = self._subscribers.setdefault(job_id, [])
            if len(subs) >= MAX_SUBSCRIBERS_PER_JOB:
                subs.pop(0)
            subs.append(q)
            return snapshot, q

    def unsubscribe(self, job_id: str, q: queue.Queue) -> None:
        with self._lock:
            subs = self._subscribers.get(job_id)
            if subs and q in subs:
                subs.remove(q)

    def iter_sse_events(self, job_id: str, snapshot: dict[str, Any], sub_q: queue.Queue):
        """Yield Server-Sent Events frames for ``job_id`` until terminal state."""
        try:
            yield f"event: snapshot\ndata: {json.dumps(snapshot, default=str)}\n\n"
            if snapshot["status"] in {"done", "failed", "cancelled"}:
                return
            while True:
                try:
                    event, payload = sub_q.get(timeout=15.0)
                    yield f"event: {event}\ndata: {json.dumps(payload, default=str)}\n\n"
                    if event in {"done", "failed", "cancelled"}:
                        return
                except queue.Empty:
                    cur = self.get(job_id)
                    if cur is None or cur["status"] in {"done", "failed", "cancelled"}:
                        if cur is not None:
                            yield (
                                f"event: {cur['status']}\n"
                                f"data: {json.dumps({'status': cur['status'], 'phase': cur['phase'], 'error': cur.get('error')})}\n\n"
                            )
                        return
                    yield ": keepalive\n\n"
        finally:
            self.unsubscribe(job_id, sub_q)
