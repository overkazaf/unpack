"""Unit tests for unpack.core.pipeline (blueprint planner & offline runner)."""

from __future__ import annotations

import zipfile
from pathlib import Path

from unpack.core.pipeline import build_pipeline_plan, run_offline_pipeline


def _make_apk(path: Path, dex_bytes: bytes, *, packed: bool = False) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("AndroidManifest.xml", b"manifest")
        if packed:
            zf.writestr("lib/arm64-v8a/libjiagu.so", b"\x7fELF" + b"\x00" * 64)
            zf.writestr("assets/.appkey", b"key")
    return path


def test_build_pipeline_plan_auto_offline_and_packed_modes(tmp_path: Path, synthetic_dex_bytes: bytes) -> None:
    clean_apk = _make_apk(tmp_path / "clean.apk", synthetic_dex_bytes, packed=False)
    plan_clean = build_pipeline_plan(clean_apk, output=tmp_path / "out", check_devices=False, lang="en")
    assert plan_clean["mode"] == "offline"
    assert plan_clean["can_execute"] is True
    assert plan_clean["recommended_engine"] == "offline"
    assert any(s["id"] == "extract_dex" for s in plan_clean["stages"])

    packed_apk = _make_apk(tmp_path / "packed.apk", synthetic_dex_bytes, packed=True)
    plan_packed = build_pipeline_plan(packed_apk, output=tmp_path / "out2", check_devices=False, lang="zh")
    assert plan_packed["packer_name"] == "360加固保"
    assert plan_packed["mode"] in ("standard", "deep")
    assert plan_packed["can_execute"] is False
    assert any(c["id"] == "device" and c["status"] == "block" for c in plan_packed["preflight_checks"])


def test_build_pipeline_plan_invalid_apk_blocks(tmp_path: Path) -> None:
    bad = tmp_path / "corrupt.apk"
    bad.write_text("not a zip")
    plan = build_pipeline_plan(bad, mode="offline", check_devices=False, lang="en")
    assert plan["can_execute"] is False
    assert any(c["id"] == "apk" and c["status"] == "block" for c in plan["preflight_checks"])


def test_run_offline_pipeline_headless_and_events(tmp_path: Path, synthetic_dex_bytes: bytes) -> None:
    apk = _make_apk(tmp_path / "clean.apk", synthetic_dex_bytes, packed=False)
    out_dir = tmp_path / "offline_out"
    html_out = tmp_path / "custom_audit.html"

    events: list[str] = []
    summary = run_offline_pipeline(
        apk,
        output=out_dir,
        report_html=html_out,
        lang="en",
        on_event=lambda ev, _payload: events.append(ev),
    )

    assert summary["mode"] == "offline"
    assert summary["grade"] in ("A", "B", "C", "D", "F")
    assert summary["extracted_dex"] == ["classes.dex"]
    assert Path(summary["report_html"]) == html_out
    assert (out_dir / "classes.dex").exists()
    assert (out_dir / "report.json").exists()
    assert html_out.exists()
    assert html_out.read_text().startswith("<!DOCTYPE html>")

    for expected_event in (
        "stage_start",
        "scan_done",
        "inspect_done",
        "extract_done",
        "repair_done",
        "verify_done",
        "vmp_done",
        "report_done",
    ):
        assert expected_event in events
