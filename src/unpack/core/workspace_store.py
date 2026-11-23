"""Persistent Workspace & Session History Storage for UNPACK Studio.

Thread-safe, zero-extra-dependency storage backed by SQLite3 (WAL mode) with
atomic JSON snapshot/index helpers under ``~/.unpack/studio`` (configurable via
``base_dir`` argument or ``UNPACK_HOME`` environment variable).
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
DEFAULT_WORKSPACE_ID = "default"
DEFAULT_WORKSPACE_NAME = "Default Workspace"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def resolve_unpack_home(base_dir: str | Path | None = None) -> Path:
    """Resolve the root UNPACK home directory (``~/.unpack`` or ``UNPACK_HOME``)."""
    if base_dir is not None:
        return Path(base_dir).expanduser()
    env_home = os.environ.get("UNPACK_HOME", "").strip()
    if env_home:
        return Path(env_home).expanduser()
    return Path.home() / ".unpack"


def resolve_studio_dir(base_dir: str | Path | None = None) -> Path:
    """Resolve the Studio persistence directory.

    If ``base_dir`` is explicitly provided, it is used directly as the Studio
    storage directory. Otherwise ``<UNPACK_HOME>/studio`` (defaulting to
    ``~/.unpack/studio``) is used.
    """
    if base_dir is not None:
        return Path(base_dir).expanduser()
    return resolve_unpack_home() / "studio"


def _atomic_write_json(path: Path, payload: Any, *, mode: int | None = None) -> None:
    """Atomically write JSON to ``path`` using temp-file + ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None and os.name == "posix":
            os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        if mode is not None and os.name == "posix":
            os.chmod(path, mode)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _safe_json_loads(raw: str | None, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _safe_json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _normalize_tags(tags: Any) -> list[str]:
    if not tags:
        return []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    seen: set[str] = set()
    out: list[str] = []
    for item in tags:
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _normalize_bookmarks(bookmarks: Any) -> list[dict[str, Any]]:
    if not bookmarks:
        return []
    if not isinstance(bookmarks, list):
        return []
    out: list[dict[str, Any]] = []
    for item in bookmarks:
        if isinstance(item, dict):
            out.append(dict(item))
        elif item is not None:
            out.append({"label": str(item)})
    return out


def _normalize_ai_list(items: Any) -> list[dict[str, Any]]:
    if not items or not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if hasattr(item, "to_dict") and callable(item.to_dict):
            out.append(dict(item.to_dict()))
        elif isinstance(item, dict):
            out.append(dict(item))
    return out


# ---------------------------------------------------------------------------
# Typed Record Dataclasses (all JSON-serializable via .to_dict())
# ---------------------------------------------------------------------------


@dataclass
class WorkspaceRecord:
    id: str
    name: str
    description: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    pinned: bool = False
    is_default: bool = False
    created_at: str = ""
    updated_at: str = ""
    sample_count: int = 0
    pipeline_run_count: int = 0
    ai_analysis_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "notes": self.notes,
            "tags": list(self.tags),
            "pinned": bool(self.pinned),
            "is_default": bool(self.is_default),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "sample_count": int(self.sample_count),
            "pipeline_run_count": int(self.pipeline_run_count),
            "ai_analysis_count": int(self.ai_analysis_count),
        }


@dataclass
class SampleRecord:
    sample_id: str
    workspace_id: str
    filename: str
    sha256: str = ""
    kind: str = "apk"
    size_bytes: int = 0
    source_path: str = ""
    scan_result: dict[str, Any] | None = None
    inspect_result: dict[str, Any] | None = None
    vmp_result: dict[str, Any] | None = None
    xref_result: dict[str, Any] | None = None
    repair_result: Any = None
    notes: str = ""
    bookmarks: list[dict[str, Any]] = field(default_factory=list)
    ai_analyses: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "workspace_id": self.workspace_id,
            "filename": self.filename,
            "sha256": self.sha256,
            "kind": self.kind,
            "size_bytes": int(self.size_bytes),
            "source_path": self.source_path,
            "scan_result": self.scan_result,
            "inspect_result": self.inspect_result,
            "vmp_result": self.vmp_result,
            "xref_result": self.xref_result,
            "repair_result": self.repair_result,
            "notes": self.notes,
            "bookmarks": list(self.bookmarks),
            "ai_analyses": list(self.ai_analyses),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class PipelineRunRecord:
    id: str
    workspace_id: str
    sample_id: str | None = None
    name: str = ""
    stage: str = ""
    status: str = "unknown"
    started_at: str = ""
    finished_at: str = ""
    duration_ms: int = 0
    summary: str = ""
    error: str = ""
    stages: list[dict[str, Any]] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "sample_id": self.sample_id,
            "name": self.name,
            "stage": self.stage,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": int(self.duration_ms),
            "summary": self.summary,
            "error": self.error,
            "stages": list(self.stages),
            "payload": dict(self.payload),
            "created_at": self.created_at,
        }


@dataclass
class AIAnalysisRecord:
    id: str
    workspace_id: str
    sample_id: str | None
    module: str
    provider: str = ""
    model: str = ""
    lang: str = "zh"
    title: str = ""
    summary: str = ""
    markdown: str = ""
    latency_ms: int = 0
    usage: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "sample_id": self.sample_id,
            "module": self.module,
            "provider": self.provider,
            "model": self.model,
            "lang": self.lang,
            "title": self.title,
            "summary": self.summary,
            "markdown": self.markdown,
            "latency_ms": int(self.latency_ms),
            "usage": dict(self.usage),
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# WorkspaceStore
# ---------------------------------------------------------------------------


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    pinned INTEGER NOT NULL DEFAULT 0,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'apk',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    source_path TEXT NOT NULL DEFAULT '',
    scan_result_json TEXT,
    inspect_result_json TEXT,
    vmp_result_json TEXT,
    xref_result_json TEXT,
    repair_result_json TEXT,
    notes TEXT NOT NULL DEFAULT '',
    bookmarks_json TEXT NOT NULL DEFAULT '[]',
    ai_analyses_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_samples_ws_sha
    ON samples(workspace_id, sha256)
    WHERE sha256 != '';

CREATE INDEX IF NOT EXISTS idx_samples_ws_updated
    ON samples(workspace_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    sample_id TEXT,
    name TEXT NOT NULL DEFAULT '',
    stage TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unknown',
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    stages_json TEXT NOT NULL DEFAULT '[]',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pipeline_ws_created
    ON pipeline_runs(workspace_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_pipeline_sample_created
    ON pipeline_runs(sample_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ai_analyses (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    sample_id TEXT,
    module TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    lang TEXT NOT NULL DEFAULT 'zh',
    title TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    markdown TEXT NOT NULL DEFAULT '',
    latency_ms INTEGER NOT NULL DEFAULT 0,
    usage_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ai_ws_created
    ON ai_analyses(workspace_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ai_sample_module
    ON ai_analyses(sample_id, module, created_at DESC);
"""


class WorkspaceStore:
    """Thread-safe persistent storage for UNPACK Studio workspaces and history."""

    def __init__(self, base_dir: str | Path | None = None) -> None:
        self.base_dir = resolve_studio_dir(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_dir / "workspace.db"
        self.index_path = self.base_dir / "studio_index.json"
        self._lock = threading.RLock()
        self._conn = self._open_db_with_recovery()
        self.ensure_default_workspace()

    def __enter__(self) -> "WorkspaceStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None  # type: ignore[assignment]

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=30000;")
        return conn

    def _open_db_with_recovery(self) -> sqlite3.Connection:
        """Open SQLite DB, quarantining a corrupt file and reinitializing cleanly."""
        try:
            conn = self._connect()
            conn.executescript(_SCHEMA_SQL)
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            conn.commit()
            return conn
        except sqlite3.DatabaseError:
            self._quarantine_corrupt_db()
            conn = self._connect()
            conn.executescript(_SCHEMA_SQL)
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            conn.commit()
            return conn

    def _quarantine_corrupt_db(self) -> None:
        stamp = int(time.time())
        for suffix in ("", "-wal", "-shm"):
            src = Path(f"{self.db_path}{suffix}")
            if src.exists():
                dst = Path(f"{self.db_path}.corrupt.{stamp}{suffix}")
                try:
                    os.replace(src, dst)
                except OSError:
                    try:
                        src.unlink(missing_ok=True)
                    except OSError:
                        pass

    def _write_index_mirror(self) -> None:
        """Atomically persist a lightweight JSON index of workspaces for quick inspection."""
        try:
            rows = self._conn.execute(
                """
                SELECT id, name, description, pinned, is_default, created_at, updated_at
                FROM workspaces
                ORDER BY pinned DESC, updated_at DESC
                """
            ).fetchall()
            payload = {
                "schema_version": SCHEMA_VERSION,
                "updated_at": _utc_now_iso(),
                "workspaces": [
                    {
                        "id": r["id"],
                        "name": r["name"],
                        "description": r["description"],
                        "pinned": bool(r["pinned"]),
                        "is_default": bool(r["is_default"]),
                        "created_at": r["created_at"],
                        "updated_at": r["updated_at"],
                    }
                    for r in rows
                ],
            }
            _atomic_write_json(self.index_path, payload)
        except OSError:
            # Mirror is best-effort; SQLite remains the source of truth.
            pass

    def _touch_workspace(self, ws_id: str, ts: str | None = None) -> None:
        now = ts or _utc_now_iso()
        self._conn.execute(
            "UPDATE workspaces SET updated_at = ? WHERE id = ?",
            (now, ws_id),
        )

    def _ensure_workspace_exists(self, ws_id: str) -> str:
        target = (ws_id or "").strip() or DEFAULT_WORKSPACE_ID
        row = self._conn.execute(
            "SELECT id FROM workspaces WHERE id = ?",
            (target,),
        ).fetchone()
        if row is not None:
            return str(row["id"])
        if target == DEFAULT_WORKSPACE_ID:
            self.ensure_default_workspace()
            return DEFAULT_WORKSPACE_ID
        raise KeyError(f"Workspace not found: {target}")

    # ------------------------------------------------------------------
    # Row deserialization helpers
    # ------------------------------------------------------------------

    def _row_to_workspace(self, row: sqlite3.Row) -> dict[str, Any]:
        rec = WorkspaceRecord(
            id=str(row["id"]),
            name=str(row["name"]),
            description=str(row["description"] or ""),
            notes=str(row["notes"] or ""),
            tags=_normalize_tags(_safe_json_loads(row["tags_json"], [])),
            pinned=bool(row["pinned"]),
            is_default=bool(row["is_default"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            sample_count=int(row["sample_count"]) if "sample_count" in row.keys() else 0,
            pipeline_run_count=(
                int(row["pipeline_run_count"]) if "pipeline_run_count" in row.keys() else 0
            ),
            ai_analysis_count=(
                int(row["ai_analysis_count"]) if "ai_analysis_count" in row.keys() else 0
            ),
        )
        return rec.to_dict()

    def _row_to_sample(self, row: sqlite3.Row) -> dict[str, Any]:
        rec = SampleRecord(
            sample_id=str(row["sample_id"]),
            workspace_id=str(row["workspace_id"]),
            filename=str(row["filename"]),
            sha256=str(row["sha256"] or ""),
            kind=str(row["kind"] or "apk"),
            size_bytes=int(row["size_bytes"] or 0),
            source_path=str(row["source_path"] or ""),
            scan_result=_safe_json_loads(row["scan_result_json"], None),
            inspect_result=_safe_json_loads(row["inspect_result_json"], None),
            vmp_result=_safe_json_loads(row["vmp_result_json"], None),
            xref_result=_safe_json_loads(row["xref_result_json"], None),
            repair_result=_safe_json_loads(row["repair_result_json"], None),
            notes=str(row["notes"] or ""),
            bookmarks=_normalize_bookmarks(_safe_json_loads(row["bookmarks_json"], [])),
            ai_analyses=_normalize_ai_list(_safe_json_loads(row["ai_analyses_json"], [])),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )
        return rec.to_dict()

    def _row_to_pipeline_run(self, row: sqlite3.Row) -> dict[str, Any]:
        rec = PipelineRunRecord(
            id=str(row["id"]),
            workspace_id=str(row["workspace_id"]),
            sample_id=row["sample_id"],
            name=str(row["name"] or ""),
            stage=str(row["stage"] or ""),
            status=str(row["status"] or "unknown"),
            started_at=str(row["started_at"] or ""),
            finished_at=str(row["finished_at"] or ""),
            duration_ms=int(row["duration_ms"] or 0),
            summary=str(row["summary"] or ""),
            error=str(row["error"] or ""),
            stages=_safe_json_loads(row["stages_json"], []),
            payload=_safe_json_loads(row["payload_json"], {}),
            created_at=str(row["created_at"]),
        )
        return rec.to_dict()

    def _row_to_ai_analysis(self, row: sqlite3.Row) -> dict[str, Any]:
        rec = AIAnalysisRecord(
            id=str(row["id"]),
            workspace_id=str(row["workspace_id"]),
            sample_id=row["sample_id"],
            module=str(row["module"]),
            provider=str(row["provider"] or ""),
            model=str(row["model"] or ""),
            lang=str(row["lang"] or "zh"),
            title=str(row["title"] or ""),
            summary=str(row["summary"] or ""),
            markdown=str(row["markdown"] or ""),
            latency_ms=int(row["latency_ms"] or 0),
            usage=_safe_json_loads(row["usage_json"], {}),
            created_at=str(row["created_at"]),
        )
        return rec.to_dict()

    # ------------------------------------------------------------------
    # Workspaces CRUD
    # ------------------------------------------------------------------

    def ensure_default_workspace(self) -> dict[str, Any]:
        """Ensure the default workspace exists and return it."""
        with self._lock:
            existing = self.get_workspace(DEFAULT_WORKSPACE_ID)
            if existing is not None:
                return existing
            now = _utc_now_iso()
            with self._conn:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO workspaces
                    (id, name, description, notes, tags_json, pinned, is_default, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        DEFAULT_WORKSPACE_ID,
                        DEFAULT_WORKSPACE_NAME,
                        "Default persistent reverse-engineering workspace.",
                        "",
                        "[]",
                        1,
                        1,
                        now,
                        now,
                    ),
                )
            self._write_index_mirror()
            ws = self.get_workspace(DEFAULT_WORKSPACE_ID)
            assert ws is not None
            return ws

    def create_workspace(
        self,
        name: str,
        description: str = "",
        tags: list[str] | None = None,
        *,
        notes: str = "",
        pinned: bool = False,
    ) -> dict[str, Any]:
        """Create a new workspace and return its serialized representation."""
        clean_name = (name or "").strip()
        if not clean_name:
            raise ValueError("Workspace name cannot be empty.")
        ws_id = f"ws_{uuid.uuid4().hex[:12]}"
        now = _utc_now_iso()
        norm_tags = _normalize_tags(tags)
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO workspaces
                    (id, name, description, notes, tags_json, pinned, is_default, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
                    """,
                    (
                        ws_id,
                        clean_name,
                        str(description or ""),
                        str(notes or ""),
                        _safe_json_dumps(norm_tags),
                        1 if pinned else 0,
                        now,
                        now,
                    ),
                )
            self._write_index_mirror()
            ws = self.get_workspace(ws_id)
            assert ws is not None
            return ws

    def list_workspaces(self) -> list[dict[str, Any]]:
        """List all workspaces ordered by pinned status and recent activity."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    w.*,
                    (SELECT COUNT(*) FROM samples s WHERE s.workspace_id = w.id) AS sample_count,
                    (SELECT COUNT(*) FROM pipeline_runs p WHERE p.workspace_id = w.id) AS pipeline_run_count,
                    (SELECT COUNT(*) FROM ai_analyses a WHERE a.workspace_id = w.id) AS ai_analysis_count
                FROM workspaces w
                ORDER BY w.pinned DESC, w.updated_at DESC, w.created_at DESC
                """
            ).fetchall()
            return [self._row_to_workspace(r) for r in rows]

    def get_workspace(self, ws_id: str) -> dict[str, Any] | None:
        """Fetch a single workspace by ID, or ``None`` if not found."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT
                    w.*,
                    (SELECT COUNT(*) FROM samples s WHERE s.workspace_id = w.id) AS sample_count,
                    (SELECT COUNT(*) FROM pipeline_runs p WHERE p.workspace_id = w.id) AS pipeline_run_count,
                    (SELECT COUNT(*) FROM ai_analyses a WHERE a.workspace_id = w.id) AS ai_analysis_count
                FROM workspaces w
                WHERE w.id = ?
                """,
                (ws_id,),
            ).fetchone()
            return self._row_to_workspace(row) if row is not None else None

    def update_workspace(
        self,
        ws_id: str,
        name: str | None = None,
        description: str | None = None,
        notes: str | None = None,
        tags: list[str] | None = None,
        pinned: bool | None = None,
    ) -> dict[str, Any] | None:
        """Update mutable fields of a workspace. Returns ``None`` if not found."""
        with self._lock:
            existing = self.get_workspace(ws_id)
            if existing is None:
                return None

            new_name = existing["name"] if name is None else name.strip()
            if not new_name:
                raise ValueError("Workspace name cannot be empty.")
            new_desc = existing["description"] if description is None else str(description)
            new_notes = existing["notes"] if notes is None else str(notes)
            new_tags = existing["tags"] if tags is None else _normalize_tags(tags)
            new_pinned = existing["pinned"] if pinned is None else bool(pinned)
            now = _utc_now_iso()

            with self._conn:
                self._conn.execute(
                    """
                    UPDATE workspaces
                    SET name = ?, description = ?, notes = ?, tags_json = ?, pinned = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        new_name,
                        new_desc,
                        new_notes,
                        _safe_json_dumps(new_tags),
                        1 if new_pinned else 0,
                        now,
                        ws_id,
                    ),
                )
            self._write_index_mirror()
            return self.get_workspace(ws_id)

    def delete_workspace(self, ws_id: str) -> bool:
        """Delete a workspace and cascade-delete its samples, runs, and AI history."""
        with self._lock:
            with self._conn:
                cur = self._conn.execute("DELETE FROM workspaces WHERE id = ?", (ws_id,))
            deleted = cur.rowcount > 0
            if deleted:
                self._write_index_mirror()
            return deleted

    # ------------------------------------------------------------------
    # Saved Samples & Analysis Snapshots
    # ------------------------------------------------------------------

    def save_sample(self, workspace_id: str, sample_dict: dict[str, Any]) -> dict[str, Any]:
        """Upsert a sample snapshot into ``workspace_id`` keyed by ``(workspace_id, sha256)``.

        Existing analysis fields, notes, bookmarks, and AI analyses are preserved
        when omitted from ``sample_dict`` so incremental stage saves never wipe
        prior results.
        """
        if not isinstance(sample_dict, dict):
            raise ValueError("sample_dict must be a dictionary.")

        with self._lock:
            ws_id = self._ensure_workspace_exists(workspace_id)
            now = _utc_now_iso()

            raw_sha = str(sample_dict.get("sha256") or "").strip().lower()
            raw_id = str(sample_dict.get("sample_id") or sample_dict.get("id") or "").strip()

            existing_row: sqlite3.Row | None = None
            if raw_sha:
                existing_row = self._conn.execute(
                    "SELECT * FROM samples WHERE workspace_id = ? AND sha256 = ?",
                    (ws_id, raw_sha),
                ).fetchone()
            if existing_row is None and raw_id:
                existing_row = self._conn.execute(
                    "SELECT * FROM samples WHERE sample_id = ?",
                    (raw_id,),
                ).fetchone()
                # If raw_id belongs to a different workspace, allocate a fresh sample_id
                # so samples stay isolated per workspace.
                if existing_row is not None and existing_row["workspace_id"] != ws_id:
                    existing_row = None
                    raw_id = ""

            existing = self._row_to_sample(existing_row) if existing_row is not None else None

            if existing is not None:
                sample_id = existing["sample_id"]
                created_at = existing["created_at"]
            else:
                sample_id = raw_id or f"smp_{uuid.uuid4().hex[:12]}"
                created_at = str(sample_dict.get("created_at") or now)

            filename = str(
                sample_dict.get("filename")
                or sample_dict.get("name")
                or (existing["filename"] if existing else "unknown")
            )
            sha256 = raw_sha or (existing["sha256"] if existing else "")
            kind = str(sample_dict.get("kind") or (existing["kind"] if existing else "apk"))
            size_bytes = int(
                sample_dict["size_bytes"]
                if "size_bytes" in sample_dict and sample_dict["size_bytes"] is not None
                else (existing["size_bytes"] if existing else 0)
            )
            source_path = str(
                sample_dict.get("source_path")
                if sample_dict.get("source_path") is not None
                else (
                    sample_dict.get("path")
                    if sample_dict.get("path") is not None
                    else (existing["source_path"] if existing else "")
                )
            )

            def _pick(key: str, alt_key: str | None = None) -> Any:
                if key in sample_dict and sample_dict[key] is not None:
                    return sample_dict[key]
                if alt_key and alt_key in sample_dict and sample_dict[alt_key] is not None:
                    return sample_dict[alt_key]
                return existing[key] if existing else None

            scan_result = _pick("scan_result")
            inspect_result = _pick("inspect_result")
            vmp_result = _pick("vmp_result")
            xref_result = _pick("xref_result")
            repair_result = _pick("repair_result", "repair_diffs")

            notes = (
                str(sample_dict["notes"])
                if "notes" in sample_dict and sample_dict["notes"] is not None
                else (existing["notes"] if existing else "")
            )
            bookmarks = (
                _normalize_bookmarks(sample_dict["bookmarks"])
                if "bookmarks" in sample_dict and sample_dict["bookmarks"] is not None
                else (existing["bookmarks"] if existing else [])
            )
            ai_analyses = (
                _normalize_ai_list(sample_dict["ai_analyses"])
                if "ai_analyses" in sample_dict and sample_dict["ai_analyses"] is not None
                else (existing["ai_analyses"] if existing else [])
            )

            with self._conn:
                if existing is not None:
                    self._conn.execute(
                        """
                        UPDATE samples
                        SET filename = ?, sha256 = ?, kind = ?, size_bytes = ?, source_path = ?,
                            scan_result_json = ?, inspect_result_json = ?, vmp_result_json = ?,
                            xref_result_json = ?, repair_result_json = ?,
                            notes = ?, bookmarks_json = ?, ai_analyses_json = ?, updated_at = ?
                        WHERE sample_id = ?
                        """,
                        (
                            filename,
                            sha256,
                            kind,
                            size_bytes,
                            source_path,
                            _safe_json_dumps(scan_result) if scan_result is not None else None,
                            _safe_json_dumps(inspect_result) if inspect_result is not None else None,
                            _safe_json_dumps(vmp_result) if vmp_result is not None else None,
                            _safe_json_dumps(xref_result) if xref_result is not None else None,
                            _safe_json_dumps(repair_result) if repair_result is not None else None,
                            notes,
                            _safe_json_dumps(bookmarks),
                            _safe_json_dumps(ai_analyses),
                            now,
                            sample_id,
                        ),
                    )
                else:
                    self._conn.execute(
                        """
                        INSERT INTO samples
                        (sample_id, workspace_id, filename, sha256, kind, size_bytes, source_path,
                         scan_result_json, inspect_result_json, vmp_result_json, xref_result_json,
                         repair_result_json, notes, bookmarks_json, ai_analyses_json,
                         created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sample_id,
                            ws_id,
                            filename,
                            sha256,
                            kind,
                            size_bytes,
                            source_path,
                            _safe_json_dumps(scan_result) if scan_result is not None else None,
                            _safe_json_dumps(inspect_result) if inspect_result is not None else None,
                            _safe_json_dumps(vmp_result) if vmp_result is not None else None,
                            _safe_json_dumps(xref_result) if xref_result is not None else None,
                            _safe_json_dumps(repair_result) if repair_result is not None else None,
                            notes,
                            _safe_json_dumps(bookmarks),
                            _safe_json_dumps(ai_analyses),
                            created_at,
                            now,
                        ),
                    )
                self._touch_workspace(ws_id, now)

            result = self.get_sample(sample_id, workspace_id=ws_id)
            assert result is not None
            return result

    def list_samples(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        """List saved samples, optionally filtered by ``workspace_id``."""
        with self._lock:
            if workspace_id:
                rows = self._conn.execute(
                    "SELECT * FROM samples WHERE workspace_id = ? ORDER BY updated_at DESC",
                    (workspace_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM samples ORDER BY updated_at DESC"
                ).fetchall()
            return [self._row_to_sample(r) for r in rows]

    def get_sample(
        self,
        sample_id: str,
        workspace_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Retrieve a saved sample by ``sample_id`` (optionally scoped to ``workspace_id``)."""
        with self._lock:
            if workspace_id:
                row = self._conn.execute(
                    "SELECT * FROM samples WHERE sample_id = ? AND workspace_id = ?",
                    (sample_id, workspace_id),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT * FROM samples WHERE sample_id = ?",
                    (sample_id,),
                ).fetchone()
            if row is None:
                return None
            return self._row_to_sample(row)

    def update_sample_notes(
        self,
        sample_id: str,
        notes: str | None = None,
        bookmarks: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """Update analyst notes and/or bookmarks for a saved sample."""
        with self._lock:
            existing = self.get_sample(sample_id)
            if existing is None:
                return None
            new_notes = existing["notes"] if notes is None else str(notes)
            new_bookmarks = (
                existing["bookmarks"] if bookmarks is None else _normalize_bookmarks(bookmarks)
            )
            now = _utc_now_iso()
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE samples
                    SET notes = ?, bookmarks_json = ?, updated_at = ?
                    WHERE sample_id = ?
                    """,
                    (new_notes, _safe_json_dumps(new_bookmarks), now, sample_id),
                )
                self._touch_workspace(existing["workspace_id"], now)
            return self.get_sample(sample_id)

    def delete_sample(self, sample_id: str) -> bool:
        """Delete a sample record by ``sample_id``."""
        with self._lock:
            row = self._conn.execute(
                "SELECT workspace_id FROM samples WHERE sample_id = ?",
                (sample_id,),
            ).fetchone()
            if row is None:
                return False
            ws_id = str(row["workspace_id"])
            with self._conn:
                cur = self._conn.execute(
                    "DELETE FROM samples WHERE sample_id = ?",
                    (sample_id,),
                )
                self._touch_workspace(ws_id)
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Pipeline Run History
    # ------------------------------------------------------------------

    def save_pipeline_run(self, workspace_id: str, run_dict: dict[str, Any]) -> dict[str, Any]:
        """Persist or update a pipeline run entry in ``workspace_id``."""
        if not isinstance(run_dict, dict):
            raise ValueError("run_dict must be a dictionary.")

        with self._lock:
            ws_id = self._ensure_workspace_exists(workspace_id)
            now = _utc_now_iso()
            run_id = str(run_dict.get("id") or run_dict.get("run_id") or f"run_{uuid.uuid4().hex[:12]}")
            sample_id = run_dict.get("sample_id")
            if sample_id is not None:
                sample_id = str(sample_id)
            name = str(run_dict.get("name") or run_dict.get("kind") or "pipeline")
            stage = str(run_dict.get("stage") or "")
            status = str(run_dict.get("status") or "completed")
            started_at = str(run_dict.get("started_at") or now)
            finished_at = str(run_dict.get("finished_at") or "")
            duration_ms = int(run_dict.get("duration_ms") or 0)
            summary = str(run_dict.get("summary") or "")
            error = str(run_dict.get("error") or "")
            stages = run_dict.get("stages") if isinstance(run_dict.get("stages"), list) else []
            payload = dict(run_dict.get("payload") or {})
            # Preserve any extra caller-supplied fields inside payload
            known_keys = {
                "id", "run_id", "workspace_id", "sample_id", "name", "stage", "status",
                "started_at", "finished_at", "duration_ms", "summary", "error",
                "stages", "payload", "created_at",
            }
            for k, v in run_dict.items():
                if k not in known_keys and k not in payload:
                    payload[k] = v

            created_at = str(run_dict.get("created_at") or now)

            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO pipeline_runs
                    (id, workspace_id, sample_id, name, stage, status, started_at, finished_at,
                     duration_ms, summary, error, stages_json, payload_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        workspace_id = excluded.workspace_id,
                        sample_id = excluded.sample_id,
                        name = excluded.name,
                        stage = excluded.stage,
                        status = excluded.status,
                        started_at = excluded.started_at,
                        finished_at = excluded.finished_at,
                        duration_ms = excluded.duration_ms,
                        summary = excluded.summary,
                        error = excluded.error,
                        stages_json = excluded.stages_json,
                        payload_json = excluded.payload_json
                    """,
                    (
                        run_id,
                        ws_id,
                        sample_id,
                        name,
                        stage,
                        status,
                        started_at,
                        finished_at,
                        duration_ms,
                        summary,
                        error,
                        _safe_json_dumps(stages),
                        _safe_json_dumps(payload),
                        created_at,
                    ),
                )
                self._touch_workspace(ws_id, now)

            row = self._conn.execute(
                "SELECT * FROM pipeline_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
            assert row is not None
            return self._row_to_pipeline_run(row)

    def list_pipeline_runs(
        self,
        workspace_id: str | None = None,
        sample_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List pipeline runs filtered by ``workspace_id`` and/or ``sample_id``."""
        clauses: list[str] = []
        params: list[Any] = []
        if workspace_id:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if sample_id:
            clauses.append("sample_id = ?")
            params.append(sample_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        lim = max(1, int(limit))
        params.append(lim)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM pipeline_runs {where} ORDER BY created_at DESC LIMIT ?",
                tuple(params),
            ).fetchall()
            return [self._row_to_pipeline_run(r) for r in rows]

    # ------------------------------------------------------------------
    # AI Analysis History
    # ------------------------------------------------------------------

    def save_ai_analysis(
        self,
        workspace_id: str,
        sample_id: str | None,
        module: str,
        analysis_dict: dict[str, Any] | Any,
    ) -> dict[str, Any]:
        """Persist an AI analysis entry and mirror a summary onto the sample if present."""
        if hasattr(analysis_dict, "to_dict") and callable(analysis_dict.to_dict):
            data = dict(analysis_dict.to_dict())
        elif isinstance(analysis_dict, dict):
            data = dict(analysis_dict)
        else:
            raise ValueError("analysis_dict must be a dict or expose .to_dict().")

        clean_module = (module or data.get("module") or "general").strip()
        with self._lock:
            ws_id = self._ensure_workspace_exists(workspace_id)
            now = _utc_now_iso()
            aid = str(data.get("id") or f"ai_{uuid.uuid4().hex[:12]}")
            sid = str(sample_id) if sample_id is not None else None
            provider = str(data.get("provider") or "")
            model = str(data.get("model") or "")
            lang = str(data.get("lang") or "zh")
            title = str(data.get("title") or "")
            summary = str(data.get("summary") or "")
            markdown = str(data.get("markdown") or "")
            latency_ms = int(data.get("latency_ms") or 0)
            usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
            created_at = str(data.get("created_at") or now)

            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO ai_analyses
                    (id, workspace_id, sample_id, module, provider, model, lang,
                     title, summary, markdown, latency_ms, usage_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        workspace_id = excluded.workspace_id,
                        sample_id = excluded.sample_id,
                        module = excluded.module,
                        provider = excluded.provider,
                        model = excluded.model,
                        lang = excluded.lang,
                        title = excluded.title,
                        summary = excluded.summary,
                        markdown = excluded.markdown,
                        latency_ms = excluded.latency_ms,
                        usage_json = excluded.usage_json
                    """,
                    (
                        aid,
                        ws_id,
                        sid,
                        clean_module,
                        provider,
                        model,
                        lang,
                        title,
                        summary,
                        markdown,
                        latency_ms,
                        _safe_json_dumps(usage),
                        created_at,
                    ),
                )

                # Mirror compact reference into the sample's ai_analyses list when sample exists.
                if sid:
                    srow = self._conn.execute(
                        "SELECT ai_analyses_json FROM samples WHERE sample_id = ? AND workspace_id = ?",
                        (sid, ws_id),
                    ).fetchone()
                    if srow is not None:
                        existing_list = _normalize_ai_list(
                            _safe_json_loads(srow["ai_analyses_json"], [])
                        )
                        entry = {
                            "id": aid,
                            "module": clean_module,
                            "provider": provider,
                            "model": model,
                            "lang": lang,
                            "title": title,
                            "summary": summary,
                            "markdown": markdown,
                            "latency_ms": latency_ms,
                            "usage": usage,
                            "created_at": created_at,
                        }
                        filtered = [x for x in existing_list if x.get("id") != aid]
                        filtered.insert(0, entry)
                        # Keep up to 50 most recent inline snapshots per sample
                        self._conn.execute(
                            "UPDATE samples SET ai_analyses_json = ?, updated_at = ? WHERE sample_id = ?",
                            (_safe_json_dumps(filtered[:50]), now, sid),
                        )

                self._touch_workspace(ws_id, now)

            row = self._conn.execute(
                "SELECT * FROM ai_analyses WHERE id = ?",
                (aid,),
            ).fetchone()
            assert row is not None
            return self._row_to_ai_analysis(row)

    def list_ai_analyses(
        self,
        workspace_id: str | None = None,
        sample_id: str | None = None,
        module: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List stored AI analyses with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if workspace_id:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if sample_id:
            clauses.append("sample_id = ?")
            params.append(sample_id)
        if module:
            clauses.append("module = ?")
            params.append(module)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        lim = max(1, int(limit))
        params.append(lim)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM ai_analyses {where} ORDER BY created_at DESC LIMIT ?",
                tuple(params),
            ).fetchall()
            return [self._row_to_ai_analysis(r) for r in rows]

    # ------------------------------------------------------------------
    # Export / Import Snapshot
    # ------------------------------------------------------------------

    def export_workspace_json(self, workspace_id: str) -> dict[str, Any]:
        """Export a workspace and all of its samples, runs, and AI analyses as a portable dict."""
        with self._lock:
            ws = self.get_workspace(workspace_id)
            if ws is None:
                raise KeyError(f"Workspace not found: {workspace_id}")
            samples = self.list_samples(workspace_id=workspace_id)
            runs = self.list_pipeline_runs(workspace_id=workspace_id, limit=10000)
            analyses = self.list_ai_analyses(workspace_id=workspace_id, limit=10000)
            return {
                "schema_version": SCHEMA_VERSION,
                "exported_at": _utc_now_iso(),
                "workspace": ws,
                "samples": samples,
                "pipeline_runs": runs,
                "ai_analyses": analyses,
            }

    def import_workspace_json(
        self,
        bundle: dict[str, Any],
        *,
        name_override: str | None = None,
    ) -> dict[str, Any]:
        """Import a previously exported workspace bundle into a newly created workspace.

        Allocates fresh workspace/sample/run/analysis IDs while preserving all
        internal ``sample_id`` references so existing workspaces are never overwritten.
        """
        if not isinstance(bundle, dict):
            raise ValueError("Workspace bundle must be a JSON object.")
        ws_meta = bundle.get("workspace")
        if not isinstance(ws_meta, dict):
            raise ValueError("Workspace bundle is missing a valid 'workspace' object.")

        base_name = (name_override or ws_meta.get("name") or "Imported Workspace").strip()
        if not base_name:
            base_name = "Imported Workspace"

        samples_raw = bundle.get("samples") or []
        runs_raw = bundle.get("pipeline_runs") or []
        analyses_raw = bundle.get("ai_analyses") or []
        if not isinstance(samples_raw, list) or not isinstance(runs_raw, list) or not isinstance(analyses_raw, list):
            raise ValueError("Workspace bundle lists ('samples', 'pipeline_runs', 'ai_analyses') must be arrays.")

        with self._lock:
            restored_ws = self.create_workspace(
                name=base_name,
                description=str(ws_meta.get("description") or ""),
                tags=_normalize_tags(ws_meta.get("tags")),
                notes=str(ws_meta.get("notes") or ""),
                pinned=bool(ws_meta.get("pinned", False)),
            )
            new_ws_id = restored_ws["id"]

            sample_id_map: dict[str, str] = {}
            for item in samples_raw:
                if not isinstance(item, dict):
                    continue
                old_sid = str(item.get("sample_id") or item.get("id") or "")
                new_sid = f"smp_{uuid.uuid4().hex[:12]}"
                sample_copy = dict(item)
                sample_copy["sample_id"] = new_sid
                sample_copy.pop("id", None)
                saved = self.save_sample(new_ws_id, sample_copy)
                if old_sid:
                    sample_id_map[old_sid] = saved["sample_id"]

            for run in runs_raw:
                if not isinstance(run, dict):
                    continue
                run_copy = dict(run)
                run_copy["id"] = f"run_{uuid.uuid4().hex[:12]}"
                run_copy.pop("run_id", None)
                old_sid = run_copy.get("sample_id")
                if old_sid is not None:
                    run_copy["sample_id"] = sample_id_map.get(str(old_sid), str(old_sid))
                self.save_pipeline_run(new_ws_id, run_copy)

            for ana in analyses_raw:
                if not isinstance(ana, dict):
                    continue
                ana_copy = dict(ana)
                ana_copy["id"] = f"ai_{uuid.uuid4().hex[:12]}"
                old_sid = ana_copy.get("sample_id")
                mapped_sid = sample_id_map.get(str(old_sid), str(old_sid)) if old_sid is not None else None
                module = str(ana_copy.get("module") or "general")
                self.save_ai_analysis(new_ws_id, mapped_sid, module, ana_copy)

            final_ws = self.get_workspace(new_ws_id)
            assert final_ws is not None
            return final_ws


__all__ = [
    "SCHEMA_VERSION",
    "DEFAULT_WORKSPACE_ID",
    "DEFAULT_WORKSPACE_NAME",
    "resolve_unpack_home",
    "resolve_studio_dir",
    "WorkspaceRecord",
    "SampleRecord",
    "PipelineRunRecord",
    "AIAnalysisRecord",
    "WorkspaceStore",
]
