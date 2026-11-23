"""Unit tests for unpack.core.workspace_store."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from unpack.core.ai_engine import AIAnalysisResult
from unpack.core.workspace_store import (
    DEFAULT_WORKSPACE_ID,
    WorkspaceStore,
    resolve_studio_dir,
)


def test_resolve_studio_dir_env_and_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    custom_home = tmp_path / "custom_home"
    monkeypatch.setenv("UNPACK_HOME", str(custom_home))
    assert resolve_studio_dir() == custom_home / "studio"

    explicit = tmp_path / "explicit_studio"
    assert resolve_studio_dir(explicit) == explicit


def test_default_workspace_and_crud(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "studio")
    try:
        default_ws = store.ensure_default_workspace()
        assert default_ws["id"] == DEFAULT_WORKSPACE_ID
        assert default_ws["is_default"] is True
        assert default_ws["pinned"] is True

        # Idempotent call returns same workspace
        again = store.ensure_default_workspace()
        assert again["id"] == default_ws["id"]

        ws = store.create_workspace(
            "Malware Campaign Q4",
            description="Banking trojan samples",
            tags=["jiagu", "vmp", "jiagu"],
        )
        assert ws["id"].startswith("ws_")
        assert ws["name"] == "Malware Campaign Q4"
        assert ws["tags"] == ["jiagu", "vmp"]
        assert ws["pinned"] is False

        fetched = store.get_workspace(ws["id"])
        assert fetched is not None
        assert fetched["name"] == "Malware Campaign Q4"

        updated = store.update_workspace(
            ws["id"],
            name="Malware Campaign Q4 (Updated)",
            description="Updated desc",
            notes="## Findings\n- Packer: 360 Jiagu",
            tags=["360", "banking"],
            pinned=True,
        )
        assert updated is not None
        assert updated["name"] == "Malware Campaign Q4 (Updated)"
        assert updated["notes"].startswith("## Findings")
        assert updated["tags"] == ["360", "banking"]
        assert updated["pinned"] is True

        assert store.update_workspace("ws_nonexistent", name="x") is None
        with pytest.raises(ValueError):
            store.create_workspace("   ")
        with pytest.raises(ValueError):
            store.update_workspace(ws["id"], name="  ")

        listed = store.list_workspaces()
        assert len(listed) == 2
        # JSON serializability check
        json.dumps(listed)

        assert store.delete_workspace(ws["id"]) is True
        assert store.delete_workspace(ws["id"]) is False
        assert store.get_workspace(ws["id"]) is None
    finally:
        store.close()


def test_sample_upsert_merge_notes_bookmarks_and_isolation(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "studio")
    try:
        ws1 = store.create_workspace("WS-1")
        ws2 = store.create_workspace("WS-2")

        # Initial save with scan_result
        s1 = store.save_sample(
            ws1["id"],
            {
                "filename": "banking.apk",
                "sha256": "a" * 64,
                "kind": "apk",
                "size_bytes": 102400,
                "source_path": "/samples/banking.apk",
                "scan_result": {"packer_name": "360 Jiagu", "protection_level": "dex_encryption"},
                "notes": "Initial triage note",
                "bookmarks": [{"class": "Lcom/bank/Auth;", "method": "login"}],
            },
        )
        assert s1["sample_id"].startswith("smp_")
        assert s1["scan_result"]["packer_name"] == "360 Jiagu"
        assert s1["inspect_result"] is None

        # Upsert same (workspace_id, sha256) with inspect_result & vmp_result — preserves scan_result/notes/bookmarks!
        s1_updated = store.save_sample(
            ws1["id"],
            {
                "filename": "banking.apk",
                "sha256": "A" * 64,  # case-insensitive sha normalization
                "inspect_result": {"risk_score": 72, "risk_grade": "D"},
                "vmp_result": {"vmp_count": 12, "total_methods": 200},
                "xref_result": {"iocs": {"urls": ["https://c2.example/api"]}},
                "repair_result": {"resolved_issues": ["checksum_mismatch"]},
            },
        )
        assert s1_updated["sample_id"] == s1["sample_id"]
        assert s1_updated["scan_result"]["packer_name"] == "360 Jiagu"
        assert s1_updated["inspect_result"]["risk_grade"] == "D"
        assert s1_updated["vmp_result"]["vmp_count"] == 12
        assert s1_updated["xref_result"]["iocs"]["urls"] == ["https://c2.example/api"]
        assert s1_updated["repair_result"]["resolved_issues"] == ["checksum_mismatch"]
        assert s1_updated["notes"] == "Initial triage note"
        assert len(s1_updated["bookmarks"]) == 1

        # Same sha256 in a DIFFERENT workspace creates an isolated sample
        s2 = store.save_sample(
            ws2["id"],
            {
                "filename": "banking_copy.apk",
                "sha256": "a" * 64,
                "kind": "apk",
                "size_bytes": 102400,
            },
        )
        assert s2["sample_id"] != s1["sample_id"]
        assert s2["workspace_id"] == ws2["id"]
        assert len(store.list_samples(ws1["id"])) == 1
        assert len(store.list_samples(ws2["id"])) == 1
        assert len(store.list_samples()) == 2

        # Update sample notes & bookmarks
        noted = store.update_sample_notes(
            s1["sample_id"],
            notes="Confirmed C2 endpoint in Auth.login",
            bookmarks=[
                {"class": "Lcom/bank/Auth;", "method": "login", "label": "Auth entry"},
                {"class": "Lcom/bank/Net;", "method": "post"},
            ],
        )
        assert noted is not None
        assert noted["notes"] == "Confirmed C2 endpoint in Auth.login"
        assert len(noted["bookmarks"]) == 2
        assert store.update_sample_notes("smp_missing", notes="x") is None

        # Workspace scoping on get_sample
        assert store.get_sample(s1["sample_id"], workspace_id=ws1["id"]) is not None
        assert store.get_sample(s1["sample_id"], workspace_id=ws2["id"]) is None

        # Delete sample
        assert store.delete_sample(s2["sample_id"]) is True
        assert store.delete_sample(s2["sample_id"]) is False
        assert store.get_sample(s2["sample_id"]) is None
    finally:
        store.close()


def test_pipeline_runs_and_ai_history(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "studio")
    try:
        ws = store.ensure_default_workspace()
        smp = store.save_sample(
            ws["id"],
            {"filename": "target.apk", "sha256": "b" * 64, "size_bytes": 5000},
        )

        # Save pipeline runs (including upsert update of a run)
        r1 = store.save_pipeline_run(
            ws["id"],
            {
                "id": "run_001",
                "sample_id": smp["sample_id"],
                "name": "unpack_pipeline",
                "stage": "dump",
                "status": "running",
                "summary": "Dumping DEX via Frida",
            },
        )
        assert r1["status"] == "running"

        r1_done = store.save_pipeline_run(
            ws["id"],
            {
                "id": "run_001",
                "sample_id": smp["sample_id"],
                "name": "unpack_pipeline",
                "stage": "verify",
                "status": "succeeded",
                "duration_ms": 4210,
                "summary": "Recovered 4 DEX files",
                "stages": [{"stage": "scan", "ok": True}, {"stage": "dump", "ok": True}],
            },
        )
        assert r1_done["status"] == "succeeded"
        assert r1_done["duration_ms"] == 4210
        assert len(r1_done["stages"]) == 2

        store.save_pipeline_run(
            ws["id"],
            {"sample_id": None, "name": "doctor_check", "status": "succeeded"},
        )

        all_runs = store.list_pipeline_runs(workspace_id=ws["id"])
        assert len(all_runs) == 2
        sample_runs = store.list_pipeline_runs(workspace_id=ws["id"], sample_id=smp["sample_id"])
        assert len(sample_runs) == 1
        assert sample_runs[0]["id"] == "run_001"
        assert len(store.list_pipeline_runs(limit=1)) == 1

        # Save AI analyses from both dict and AIAnalysisResult dataclass
        ai_res = AIAnalysisResult(
            id="ai_scan_01",
            module="scan",
            provider="openai",
            model="gpt-4o-mini",
            lang="zh",
            title="加壳分析",
            summary="检测到 360 加固",
            markdown="## 判定\n检测到 360 加固。",
            latency_ms=812,
            usage={"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200},
        )
        saved_ai1 = store.save_ai_analysis(ws["id"], smp["sample_id"], "scan", ai_res)
        assert saved_ai1["id"] == "ai_scan_01"
        assert saved_ai1["usage"]["total_tokens"] == 200

        saved_ai2 = store.save_ai_analysis(
            ws["id"],
            smp["sample_id"],
            "security",
            {
                "provider": "ollama",
                "model": "qwen2.5-coder:7b",
                "lang": "en",
                "title": "Security Posture",
                "summary": "Debuggable flag enabled",
                "markdown": "## Executive Posture\nHigh risk.",
                "latency_ms": 1500,
            },
        )
        assert saved_ai2["module"] == "security"

        # Sample inline ai_analyses list is mirrored automatically
        refreshed_sample = store.get_sample(smp["sample_id"])
        assert refreshed_sample is not None
        assert len(refreshed_sample["ai_analyses"]) == 2

        assert len(store.list_ai_analyses(workspace_id=ws["id"])) == 2
        assert len(store.list_ai_analyses(sample_id=smp["sample_id"], module="scan")) == 1
        assert len(store.list_ai_analyses(sample_id=smp["sample_id"], module="security")) == 1

        ws_info = store.get_workspace(ws["id"])
        assert ws_info is not None
        assert ws_info["sample_count"] == 1
        assert ws_info["pipeline_run_count"] == 2
        assert ws_info["ai_analysis_count"] == 2
    finally:
        store.close()


def test_persistence_across_fresh_instances(tmp_path: Path) -> None:
    studio_dir = tmp_path / "studio_persist"

    with WorkspaceStore(studio_dir) as s1:
        ws = s1.create_workspace("Persist Case", description="Survives restart", tags=["case1"])
        smp = s1.save_sample(
            ws["id"],
            {
                "filename": "app.apk",
                "sha256": "c" * 64,
                "size_bytes": 9999,
                "scan_result": {"packer_name": "Bangcle"},
                "notes": "Keep this across restarts",
                "bookmarks": [{"label": "MainActivity"}],
            },
        )
        s1.save_pipeline_run(
            ws["id"],
            {"sample_id": smp["sample_id"], "name": "full_unpack", "status": "succeeded"},
        )
        s1.save_ai_analysis(
            ws["id"],
            smp["sample_id"],
            "method",
            {"provider": "deepseek", "model": "deepseek-chat", "markdown": "```java\nvoid f(){}\n```"},
        )
        ws_id = ws["id"]
        sample_id = smp["sample_id"]

    # Reopen brand-new WorkspaceStore instance on same path (simulating full process restart)
    with WorkspaceStore(studio_dir) as s2:
        ws_loaded = s2.get_workspace(ws_id)
        assert ws_loaded is not None
        assert ws_loaded["name"] == "Persist Case"
        assert ws_loaded["tags"] == ["case1"]
        assert ws_loaded["sample_count"] == 1
        assert ws_loaded["pipeline_run_count"] == 1
        assert ws_loaded["ai_analysis_count"] == 1

        smp_loaded = s2.get_sample(sample_id, workspace_id=ws_id)
        assert smp_loaded is not None
        assert smp_loaded["scan_result"]["packer_name"] == "Bangcle"
        assert smp_loaded["notes"] == "Keep this across restarts"
        assert smp_loaded["bookmarks"] == [{"label": "MainActivity"}]
        assert len(smp_loaded["ai_analyses"]) == 1

        runs = s2.list_pipeline_runs(workspace_id=ws_id)
        assert len(runs) == 1
        assert runs[0]["name"] == "full_unpack"

        analyses = s2.list_ai_analyses(workspace_id=ws_id, module="method")
        assert len(analyses) == 1
        assert "void f()" in analyses[0]["markdown"]


def test_export_import_snapshot_roundtrip_and_validation(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "studio")
    try:
        ws = store.create_workspace("Audit Export", description="Full bundle", tags=["audit"])
        store.update_workspace(ws["id"], notes="Workspace-level markdown notes")
        smp = store.save_sample(
            ws["id"],
            {
                "filename": "wallet.apk",
                "sha256": "d" * 64,
                "size_bytes": 4096,
                "scan_result": {"packer_name": "Tencent Legu"},
                "notes": "Sample note",
                "bookmarks": [{"label": "CryptoUtil"}],
            },
        )
        store.save_pipeline_run(
            ws["id"],
            {"sample_id": smp["sample_id"], "name": "repair", "status": "succeeded"},
        )
        store.save_ai_analysis(
            ws["id"],
            smp["sample_id"],
            "vmp_native",
            {"provider": "anthropic", "model": "claude-3-5-sonnet-latest", "markdown": "VMP summary"},
        )

        bundle = store.export_workspace_json(ws["id"])
        # Ensure pure JSON roundtrip
        wire = json.dumps(bundle)
        parsed = json.loads(wire)
        assert parsed["schema_version"] == 1
        assert len(parsed["samples"]) == 1
        assert len(parsed["pipeline_runs"]) == 1
        assert len(parsed["ai_analyses"]) == 1

        restored = store.import_workspace_json(parsed, name_override="Audit Restored")
        assert restored["id"] != ws["id"]
        assert restored["name"] == "Audit Restored"
        assert restored["notes"] == "Workspace-level markdown notes"
        assert restored["tags"] == ["audit"]
        assert restored["sample_count"] == 1
        assert restored["pipeline_run_count"] == 1
        assert restored["ai_analysis_count"] == 1

        restored_samples = store.list_samples(restored["id"])
        assert len(restored_samples) == 1
        new_sid = restored_samples[0]["sample_id"]
        assert new_sid != smp["sample_id"]
        assert restored_samples[0]["scan_result"]["packer_name"] == "Tencent Legu"

        # Foreign references inside runs and AI analyses were remapped to new_sid
        restored_runs = store.list_pipeline_runs(workspace_id=restored["id"])
        assert restored_runs[0]["sample_id"] == new_sid
        restored_ai = store.list_ai_analyses(workspace_id=restored["id"])
        assert restored_ai[0]["sample_id"] == new_sid

        # Original workspace unaffected
        assert store.get_workspace(ws["id"])["sample_count"] == 1

        # Deleting original cascades its children without touching restored workspace
        assert store.delete_workspace(ws["id"]) is True
        assert len(store.list_samples(ws["id"])) == 0
        assert len(store.list_samples(restored["id"])) == 1

        with pytest.raises(KeyError):
            store.export_workspace_json("ws_does_not_exist")
        with pytest.raises(ValueError):
            store.import_workspace_json({"bad": "bundle"})
    finally:
        store.close()


def test_corrupt_db_and_corrupt_json_graceful_recovery(tmp_path: Path) -> None:
    studio_dir = tmp_path / "corrupt_studio"
    studio_dir.mkdir(parents=True)
    db_file = studio_dir / "workspace.db"
    db_file.write_bytes(b"NOT A VALID SQLITE DATABASE !!!" * 20)
    (studio_dir / "studio_index.json").write_text("{corrupt json", encoding="utf-8")

    with WorkspaceStore(studio_dir) as store:
        ws = store.ensure_default_workspace()
        assert ws["id"] == DEFAULT_WORKSPACE_ID
        # Corrupt file was quarantined
        quarantined = list(studio_dir.glob("workspace.db.corrupt.*"))
        assert len(quarantined) >= 1

        smp = store.save_sample(
            ws["id"],
            {"filename": "ok.apk", "sha256": "e" * 64, "notes": "fine"},
        )
        # Manually corrupt a JSON column in SQLite and verify read still succeeds gracefully
        with store._conn:
            store._conn.execute(
                "UPDATE samples SET bookmarks_json = '{broken' WHERE sample_id = ?",
                (smp["sample_id"],),
            )
        reloaded = store.get_sample(smp["sample_id"])
        assert reloaded is not None
        assert reloaded["bookmarks"] == []


def test_concurrent_thread_safety(tmp_path: Path) -> None:
    store = WorkspaceStore(tmp_path / "concurrent_studio")
    errors: list[Exception] = []

    def worker(idx: int) -> None:
        try:
            ws = store.create_workspace(f"Thread-WS-{idx}", tags=[f"t{idx}"])
            for j in range(5):
                sha = f"{idx:02x}{j:02x}" + ("f" * 60)
                smp = store.save_sample(
                    ws["id"],
                    {
                        "filename": f"sample_{idx}_{j}.apk",
                        "sha256": sha,
                        "size_bytes": 100 + j,
                        "scan_result": {"packer_name": f"Packer-{j}"},
                    },
                )
                store.update_sample_notes(smp["sample_id"], notes=f"note-{idx}-{j}")
                store.save_pipeline_run(
                    ws["id"],
                    {"sample_id": smp["sample_id"], "name": "scan", "status": "succeeded"},
                )
                store.save_ai_analysis(
                    ws["id"],
                    smp["sample_id"],
                    "scan",
                    {"provider": "ollama", "model": "qwen2.5-coder:7b", "markdown": f"md-{idx}-{j}"},
                )
        except Exception as exc:  # pragma: no cover - captured for assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    try:
        assert not errors, f"Concurrency errors: {errors}"
        # 1 default + 8 worker workspaces
        assert len(store.list_workspaces()) == 9
        assert len(store.list_samples()) == 40
        assert len(store.list_pipeline_runs(limit=100)) == 40
        assert len(store.list_ai_analyses(limit=100)) == 40
    finally:
        store.close()
