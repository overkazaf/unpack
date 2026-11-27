"""Security hardening, input validation, bounded eviction, and frontend parity tests for UNPACK Studio."""

from __future__ import annotations

import io
import re
import struct
import zipfile
from pathlib import Path

import pytest

flask = pytest.importorskip("flask")

import unpack
from unpack.web import APP_VERSION, JobManager, create_app, main


def _build_synthetic_apk() -> bytes:
    """Build a minimal synthetic APK archive with a packer SO indicator."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 32)
        zf.writestr("res/values/strings.xml", b"<resources/>")
        elf_hdr = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 3, 183) + b"\x00" * 44
        zf.writestr("lib/arm64-v8a/libjiagu_a64.so", elf_hdr)
        zf.writestr("assets/.appkey", b"demo-key")
    return out.getvalue()


def test_facade_exports_and_version_ssot():
    assert APP_VERSION == unpack.__version__
    assert callable(create_app)
    assert callable(main)
    assert JobManager is not None


def test_security_headers_and_enriched_health(tmp_path):
    local_dir = tmp_path / "apks"
    local_dir.mkdir()
    app = create_app(local_roots=[local_dir], workspace_dir=tmp_path / "ws")
    app.config["TESTING"] = True
    try:
        with app.test_client() as client:
            for path in ("/", "/api/v1/health"):
                r = client.get(path)
                assert r.status_code == 200
                assert r.headers.get("X-Content-Type-Options") == "nosniff"
                assert r.headers.get("X-Frame-Options") == "SAMEORIGIN"
                assert r.headers.get("Referrer-Policy") == "no-referrer"
                assert "camera=()" in (r.headers.get("Permissions-Policy") or "")
                csp = r.headers.get("Content-Security-Policy") or ""
                assert "default-src 'self'" in csp
                assert "object-src 'none'" in csp

            health = client.get("/api/v1/health").get_json()
            assert health["status"] == "ok"
            assert health["version"] == unpack.__version__
            assert isinstance(health["uptime_seconds"], (int, float))
            assert health["started_at"].endswith("Z")
            assert health["active_jobs"] == 0
            assert health["total_jobs"] == 0
            assert health["artifact_count"] == 0
            assert health["workspace_count"] >= 1
            assert health["capabilities"]["sse_streaming"] is True
            assert health["capabilities"]["persistent_workspaces"] is True
            assert health["capabilities"]["local_library_enabled"] is True
    finally:
        app.config["UNPACK_CLEANUP"]()


def test_input_validation_and_standardized_error_envelopes(tmp_path):
    local_dir = tmp_path / "apks"
    local_dir.mkdir()
    apk_path = local_dir / "sample.apk"
    apk_path.write_bytes(_build_synthetic_apk())

    app = create_app(local_roots=[local_dir], workspace_dir=tmp_path / "ws")
    app.config["TESTING"] = True
    try:
        with app.test_client() as client:
            sid = client.post(
                "/api/v1/samples/import-local",
                json={"path": str(apk_path), "auto_scan": False},
            ).get_json()["sample"]["id"]

            # dex_names must be a list of traversal-free filenames
            for endpoint in ("verify", "repair", "export/fart"):
                r_bad_type = client.post(f"/api/v1/samples/{sid}/{endpoint}", json={"dex_names": "classes.dex"})
                assert r_bad_type.status_code == 400
                assert r_bad_type.get_json()["code"] == "BAD_REQUEST"

                r_bad_trav = client.post(f"/api/v1/samples/{sid}/{endpoint}", json={"dex_names": ["../evil.dex"]})
                assert r_bad_trav.status_code == 400
                assert r_bad_trav.get_json()["code"] == "BAD_REQUEST"

            # Legacy /api/dump validates engine allowlist
            r_eng = client.post(
                "/api/dump",
                data={"file": (io.BytesIO(_build_synthetic_apk()), "a.apk"), "engine": "evil_engine"},
                content_type="multipart/form-data",
            )
            assert r_eng.status_code == 400
            assert r_eng.get_json()["code"] == "BAD_REQUEST"

            # Workspace import enforces 10 MB payload cap
            oversized = b"{" + b" " * (10 * 1024 * 1024 + 64) + b"}"
            r_big = client.post(
                "/api/v1/workspaces/import",
                data={"file": (io.BytesIO(oversized), "huge.json")},
                content_type="multipart/form-data",
            )
            assert r_big.status_code == 413
            assert r_big.get_json()["code"] == "PAYLOAD_TOO_LARGE"
    finally:
        app.config["UNPACK_CLEANUP"]()


def test_snapshot_only_repack_and_report_guards(tmp_path):
    ws_dir = tmp_path / "ws"
    src_dir = tmp_path / "src_apks"
    src_dir.mkdir()
    apk_path = src_dir / "ephemeral.apk"
    apk_path.write_bytes(_build_synthetic_apk())

    app1 = create_app(local_roots=[src_dir], workspace_dir=ws_dir)
    c1 = app1.test_client()
    sid = c1.post(
        "/api/v1/samples/import-local",
        json={"path": str(apk_path), "auto_scan": True},
    ).get_json()["sample"]["id"]
    app1.config["UNPACK_CLEANUP"]()

    # Delete source APK -> session 2 restores snapshot-only sample
    apk_path.unlink()
    app2 = create_app(local_roots=[], workspace_dir=ws_dir)
    app2.config["TESTING"] = True
    try:
        with app2.test_client() as c2:
            # Repack returns clean 400 FILE_UNAVAILABLE instead of PathLike NoneType crash
            r_repack = c2.post(f"/api/v1/samples/{sid}/repack", json={})
            assert r_repack.status_code == 400
            assert r_repack.get_json()["code"] == "FILE_UNAVAILABLE"

            # Report still renders cleanly from saved snapshot
            r_rep = c2.get(f"/api/v1/samples/{sid}/reports?format=markdown&lang=zh")
            assert r_rep.status_code == 200
            assert "UNPACK" in r_rep.get_data(as_text=True)
    finally:
        app2.config["UNPACK_CLEANUP"]()


def test_bounded_artifact_and_lock_eviction(tmp_path):
    app = create_app(
        local_roots=[],
        workspace_dir=tmp_path / "ws",
        max_artifacts=2,
        max_inspect_locks=2,
    )
    try:
        ctx = app.config["UNPACK_CTX"]
        f1 = tmp_path / "a1.bin"
        f2 = tmp_path / "a2.bin"
        f3 = tmp_path / "a3.bin"
        for f in (f1, f2, f3):
            f.write_bytes(b"payload")

        a1 = ctx.register_artifact(f1, "a1.bin", "test")
        a2 = ctx.register_artifact(f2, "a2.bin", "test")
        a3 = ctx.register_artifact(f3, "a3.bin", "test")

        assert len(ctx.artifacts) == 2
        assert ctx.get_artifact(a1["token"]) is None
        assert ctx.get_artifact(a2["token"]) is not None
        assert ctx.get_artifact(a3["token"]) is not None

        ctx._get_inspect_lock("s1")
        ctx._get_inspect_lock("s2")
        ctx._get_inspect_lock("s3")
        assert len(ctx.inspect_locks) == 2
        assert "s1" not in ctx.inspect_locks
    finally:
        app.config["UNPACK_CLEANUP"]()


def test_frontend_hardening_and_i18n_parity():
    pkg_dir = Path(unpack.__file__).resolve().parent
    views_src = (pkg_dir / "static/js/views.js").read_text(encoding="utf-8")
    ws_src = (pkg_dir / "static/js/workspace.js").read_text(encoding="utf-8")
    css_src = (pkg_dir / "static/css/studio.css").read_text(encoding="utf-8")
    i18n_src = (pkg_dir / "static/js/i18n.js").read_text(encoding="utf-8")

    # Report iframe must not allow scripts
    assert 'sandbox=""' in views_src
    assert "allow-scripts" not in views_src

    # No native browser prompt/alert dialogs in workspace.js
    assert "window.prompt(" not in ws_src

    # Accessibility CSS present
    assert ":focus-visible" in css_src
    assert "prefers-reduced-motion" in css_src

    # Exact EN / ZH key parity in i18n.js
    en_match = re.search(r"\ben:\s*\{(.*?)\n    \},", i18n_src, re.S)
    zh_match = re.search(r"\bzh:\s*\{(.*?)\n    \},", i18n_src, re.S)
    assert en_match and zh_match
    key_re = re.compile(r'^\s*"([^"]+)"\s*:', re.M)
    en_keys = set(key_re.findall(en_match.group(1)))
    zh_keys = set(key_re.findall(zh_match.group(1)))
    assert en_keys == zh_keys, f"EN/ZH drift: en-zh={en_keys - zh_keys}, zh-en={zh_keys - en_keys}"
    assert len(en_keys) >= 530
