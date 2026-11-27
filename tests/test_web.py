"""Comprehensive tests for UNPACK Studio Web UI & REST/SSE API."""

from __future__ import annotations

import hashlib
import io
import json
import struct
import time
import zipfile
import zlib
from pathlib import Path

import pytest

flask = pytest.importorskip("flask")

from unpack.web import create_app


# ---------------------------------------------------------------------------
# Synthetic DEX & APK builders (with real class/method/code_item for inspector)
# ---------------------------------------------------------------------------


def _uleb128_encode(val: int) -> bytes:
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _build_dex_with_class(
    class_desc: str = "Lcom/example/Demo;",
    method_name: str = "secret",
    literal: str = "https://api.example.com/v1",
    corrupt_checksum: bool = False,
) -> bytes:
    """Build a valid DEX 035 containing 1 class, 1 method with const-string + return-void."""
    # Strings (sorted lexicographically as required by DEX spec):
    strings = sorted(
        [
            class_desc,
            "Ljava/lang/Object;",
            "V",
            literal,
            method_name,
        ]
    )
    str_idx = {s: i for i, s in enumerate(strings)}

    # Types: class_desc, Object, V
    types = [class_desc, "Ljava/lang/Object;", "V"]
    type_idx = {t: i for i, t in enumerate(types)}

    # Layout offsets
    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)
    type_ids_off = string_ids_off + string_ids_size * 4
    type_ids_size = len(types)
    proto_ids_off = type_ids_off + type_ids_size * 4
    proto_ids_size = 1  # ()V
    field_ids_off = proto_ids_off + proto_ids_size * 12
    field_ids_size = 0
    method_ids_off = field_ids_off
    method_ids_size = 1
    class_defs_off = method_ids_off + method_ids_size * 8
    class_defs_size = 1
    data_off = class_defs_off + class_defs_size * 32

    buf = bytearray(data_off)

    # Write string data items
    string_data_offs: list[int] = []
    for s in strings:
        string_data_offs.append(len(buf))
        raw = s.encode("utf-8")
        buf.extend(_uleb128_encode(len(s)))
        buf.extend(raw)
        buf.append(0)

    # Align to 4 bytes for code_item
    while len(buf) % 4 != 0:
        buf.append(0)

    # Code item: const-string v0, literal (21c: 0x1a 0x00, idx_u16) + return-void (0x0e 0x00)
    code_off = len(buf)
    lit_idx = str_idx[literal]
    insns = struct.pack("<BBHBB", 0x1A, 0x00, lit_idx, 0x0E, 0x00)
    insns_size = len(insns) // 2  # 3 code units
    buf.extend(struct.pack("<HHHHII", 1, 0, 0, 0, 0, insns_size))
    buf.extend(insns)

    # class_data_item: 0 static fields, 0 inst fields, 1 direct method, 0 virtual methods
    class_data_off = len(buf)
    buf.extend(_uleb128_encode(0))  # static_fields
    buf.extend(_uleb128_encode(0))  # instance_fields
    buf.extend(_uleb128_encode(1))  # direct_methods
    buf.extend(_uleb128_encode(0))  # virtual_methods
    buf.extend(_uleb128_encode(0))  # method_idx_diff = 0
    buf.extend(_uleb128_encode(0x0009))  # access_flags = public static
    buf.extend(_uleb128_encode(code_off))

    # Fill string_ids
    for i, off in enumerate(string_data_offs):
        struct.pack_into("<I", buf, string_ids_off + i * 4, off)

    # Fill type_ids
    for i, t in enumerate(types):
        struct.pack_into("<I", buf, type_ids_off + i * 4, str_idx[t])

    # Fill proto_id 0: shorty="V", return_type="V", params_off=0
    struct.pack_into("<III", buf, proto_ids_off, str_idx["V"], type_idx["V"], 0)

    # Fill method_id 0: class_idx=0, proto_idx=0, name_idx=str_idx[method_name]
    struct.pack_into("<HHI", buf, method_ids_off, type_idx[class_desc], 0, str_idx[method_name])

    # Fill class_def 0
    struct.pack_into(
        "<IIIIIIII",
        buf,
        class_defs_off,
        type_idx[class_desc],  # class_idx
        0x0001,  # access_flags = public
        type_idx["Ljava/lang/Object;"],  # superclass_idx
        0,  # interfaces_off
        0xFFFFFFFF,  # source_file_idx (NO_INDEX)
        0,  # annotations_off
        class_data_off,  # class_data_off
        0,  # static_values_off
    )

    # Fill header
    buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 32, len(buf))
    struct.pack_into("<I", buf, 36, header_size)
    struct.pack_into("<I", buf, 40, 0x12345678)
    struct.pack_into("<I", buf, 56, string_ids_size)
    struct.pack_into("<I", buf, 60, string_ids_off)
    struct.pack_into("<I", buf, 64, type_ids_size)
    struct.pack_into("<I", buf, 68, type_ids_off)
    struct.pack_into("<I", buf, 72, proto_ids_size)
    struct.pack_into("<I", buf, 76, proto_ids_off)
    struct.pack_into("<I", buf, 80, field_ids_size)
    struct.pack_into("<I", buf, 84, 0)
    struct.pack_into("<I", buf, 88, method_ids_size)
    struct.pack_into("<I", buf, 92, method_ids_off)
    struct.pack_into("<I", buf, 96, class_defs_size)
    struct.pack_into("<I", buf, 100, class_defs_off)
    struct.pack_into("<I", buf, 104, len(buf) - data_off)
    struct.pack_into("<I", buf, 108, data_off)

    sig = hashlib.sha1(bytes(buf[32:])).digest()
    buf[12:32] = sig
    checksum = zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF
    if corrupt_checksum:
        checksum ^= 0xDEADBEEF
    struct.pack_into("<I", buf, 8, checksum)
    return bytes(buf)


def _build_synthetic_apk(
    dex_bytes: bytes | None = None,
    *,
    add_packer_so: bool = True,
    add_meta_inf: bool = True,
) -> bytes:
    dex = dex_bytes or _build_dex_with_class()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 32)
        zf.writestr("classes.dex", dex)
        zf.writestr("res/values/strings.xml", b"<resources/>")
        if add_packer_so:
            # Minimal valid ELF64 header
            elf_hdr = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 3, 183) + b"\x00" * 44
            zf.writestr("lib/arm64-v8a/libjiagu_a64.so", elf_hdr)
            zf.writestr("assets/.appkey", b"demo-key")
        if add_meta_inf:
            zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
            zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\n")
    return out.getvalue()


@pytest.fixture
def studio_client(tmp_path):
    local_apks = tmp_path / "local_apks"
    local_dexs = tmp_path / "local_dexs" / "sample_dump"
    local_apks.mkdir(parents=True)
    local_dexs.mkdir(parents=True)

    (local_apks / "demo_packed.apk").write_bytes(_build_synthetic_apk())
    (local_dexs / "classes_000.dex").write_bytes(_build_dex_with_class(corrupt_checksum=True))

    app = create_app(local_roots=[local_apks, local_dexs.parent], workspace_dir=tmp_path / "studio_home")
    app.config["TESTING"] = True
    try:
        with app.test_client() as client:
            yield client, local_apks, local_dexs
    finally:
        cleanup = app.config.get("UNPACK_CLEANUP")
        if cleanup:
            cleanup()


# ---------------------------------------------------------------------------
# 1. Zero-arg contract, UI shell & offline assets
# ---------------------------------------------------------------------------


def test_create_app_zero_args_and_shell(tmp_path, monkeypatch):
    monkeypatch.setenv("UNPACK_HOME", str(tmp_path / "unpack_home"))
    app = create_app()
    app.config["TESTING"] = True
    try:
        with app.test_client() as client:
            resp = client.get("/")
            assert resp.status_code == 200
            html_body = resp.get_data(as_text=True)
            assert "UNPACK" in html_body
            assert "STUDIO" in html_body
            assert "fonts.googleapis.com" not in html_body
            assert "onclick=" not in html_body

            for asset in (
                "/static/css/studio.css",
                "/static/js/i18n.js",
                "/static/js/api.js",
                "/static/js/state.js",
                "/static/js/components.js",
                "/static/js/workspace.js",
                "/static/js/ai.js",
                "/static/js/pipeline.js",
                "/static/js/onboarding.js",
                "/static/js/views.js",
                "/static/js/app.js",
            ):
                r = client.get(asset)
                assert r.status_code == 200, f"Missing static asset {asset}"
    finally:
        app.config["UNPACK_CLEANUP"]()


# ---------------------------------------------------------------------------
# 2. Security & Input Validation
# ---------------------------------------------------------------------------


def test_security_path_traversal_and_validation(studio_client, tmp_path):
    client, _, _ = studio_client

    # Outside allowlisted root must return 403
    secret_file = tmp_path / "outside.apk"
    secret_file.write_bytes(_build_synthetic_apk())
    r = client.post("/api/v1/samples/import-local", json={"path": str(secret_file)})
    assert r.status_code == 403
    assert r.get_json()["code"] == "FORBIDDEN_PATH"

    # Traversal filename on upload is sanitized to safe basename
    r = client.post(
        "/api/v1/samples/upload",
        data={"files": (io.BytesIO(_build_synthetic_apk()), "../../evil_traversal.apk")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 201
    item = r.get_json()["items"][0]
    assert "/" not in item["name"]
    assert ".." not in item["name"]
    assert item["name"] == "evil_traversal.apk"

    # Non-APK / invalid zip rejected
    r = client.post(
        "/api/v1/samples/upload",
        data={"files": (io.BytesIO(b"not a zip file"), "fake.apk")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 400

    # Invalid timeout returns clean 400 JSON (not 500)
    r = client.post(
        "/api/full",
        data={"file": (io.BytesIO(_build_synthetic_apk()), "a.apk"), "timeout": "notanint"},
        content_type="multipart/form-data",
    )
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_payload_too_large_returns_json(tmp_path):
    app = create_app(local_roots=[], max_content_length=1024, workspace_dir=tmp_path / "studio_home")
    app.config["TESTING"] = True
    try:
        with app.test_client() as client:
            r = client.post(
                "/api/v1/samples/upload",
                data={"files": (io.BytesIO(b"A" * 4096), "big.apk")},
                content_type="multipart/form-data",
            )
            assert r.status_code == 413
            assert r.get_json()["code"] == "PAYLOAD_TOO_LARGE"
    finally:
        app.config["UNPACK_CLEANUP"]()


# ---------------------------------------------------------------------------
# 3. Full Studio v1 Workbench End-to-End Flow
# ---------------------------------------------------------------------------


def test_studio_local_library_scan_inspect_dex_browser(studio_client):
    client, local_apks, _ = studio_client

    # Local library lists both APK and DEX dump dir
    lib = client.get("/api/v1/local-library").get_json()
    names = {i["name"] for i in lib["items"]}
    assert "demo_packed.apk" in names
    assert "sample_dump" in names

    # Import local APK zero-copy
    imp = client.post(
        "/api/v1/samples/import-local",
        json={"path": str(local_apks / "demo_packed.apk"), "auto_scan": True},
    )
    assert imp.status_code == 200
    sample = imp.get_json()["sample"]
    sid = sample["id"]
    assert sample["kind"] == "apk"
    assert sample["scan_result"]["packer_name"] == "360加固保"

    # Explicit deep scan
    sc = client.post(f"/api/v1/samples/{sid}/scan")
    assert sc.status_code == 200
    assert sc.get_json()["scan"]["packer_name"] == "360加固保"
    assert "recommended_engine" in sc.get_json()["scan"]

    # Deep APK inspect
    insp = client.get(f"/api/v1/samples/{sid}/inspect")
    assert insp.status_code == 200
    insp_data = insp.get_json()["inspect"]
    assert len(insp_data["dex_files"]) == 1
    assert len(insp_data["native_libs"]) == 1

    # DEX Browser: list DEX -> list classes -> inspect class -> disassemble -> search strings
    dex_list = client.get(f"/api/v1/samples/{sid}/dex").get_json()["dex_files"]
    assert dex_list[0]["name"] == "classes.dex"

    cls_page = client.get(f"/api/v1/samples/{sid}/dex/classes.dex/classes?q=Demo&health=ok").get_json()
    assert cls_page["total"] == 1
    cls_name = cls_page["classes"][0]["name"]
    assert cls_name == "Lcom/example/Demo;"
    assert cls_page["classes"][0]["health"] == "ok"

    cls_detail = client.get(f"/api/v1/samples/{sid}/dex/classes.dex/class?name={cls_name}").get_json()
    assert cls_detail["name"] == cls_name
    assert len(cls_detail["methods"]) == 1
    assert cls_detail["methods"][0]["name"] == "secret"
    assert cls_detail["methods"][0]["kind"] == "direct"

    disasm = client.get(
        f"/api/v1/samples/{sid}/dex/classes.dex/disasm?class={cls_name}&method=secret"
    ).get_json()
    assert "code_off" in disasm
    mnemonics = [i["mnemonic"] for i in disasm["instructions"]]
    assert "const-string" in mnemonics
    assert "return-void" in mnemonics
    assert all(i.get("hex") for i in disasm["instructions"])
    assert any("https://api.example.com/v1" in (i.get("operand") or "") for i in disasm["instructions"])

    strings = client.get(f"/api/v1/samples/{sid}/dex/classes.dex/strings?q=https").get_json()["strings"]
    assert any("https://api.example.com/v1" in s["value"] for s in strings)
    assert all("index" in s and "length" in s for s in strings)

    # VMP & Xref
    vmp = client.post(f"/api/v1/samples/{sid}/vmp", json={}).get_json()["vmp"]
    assert vmp["total_methods"] == 1
    assert vmp["vmp_count"] == 0

    xref = client.post(f"/api/v1/samples/{sid}/xref", json={}).get_json()["xref"]
    url_vals = [u["value"] if isinstance(u, dict) else u for u in xref["iocs"]["urls"]]
    assert "https://api.example.com/v1" in url_vals


def test_studio_repair_diff_repack_fart_and_reports(studio_client):
    client, local_apks, local_dexs = studio_client

    # Import corrupt DEX dump dir
    imp_dir = client.post(
        "/api/v1/samples/import-local",
        json={"path": str(local_dexs)},
    ).get_json()["sample"]
    dir_id = imp_dir["id"]

    # Verify finds checksum issue
    ver = client.post(f"/api/v1/samples/{dir_id}/verify", json={}).get_json()
    assert ver["total"] == 1
    assert ver["invalid_count"] == 1

    # Repair resolves checksum issue and provides downloadable ZIP artifact
    rep = client.post(f"/api/v1/samples/{dir_id}/repair", json={}).get_json()
    assert rep["total"] == 1
    diff = rep["diffs"][0]
    assert diff["before"]["valid"] is False
    assert diff["after"]["valid"] is True
    assert len(diff["resolved_issues"]) >= 1
    dl = client.get(rep["artifact"]["download_url"])
    assert dl.status_code == 200
    assert dl.mimetype == "application/zip"

    # Import APK and repack using the DEX dump sample
    apk_sample = client.post(
        "/api/v1/samples/import-local",
        json={"path": str(local_apks / "demo_packed.apk")},
    ).get_json()["sample"]
    apk_id = apk_sample["id"]

    repack = client.post(
        f"/api/v1/samples/{apk_id}/repack",
        json={"dex_sample_id": dir_id, "strip_signatures": True},
    )
    assert repack.status_code == 200
    art_url = repack.get_json()["artifact"]["download_url"]
    dl_apk = client.get(art_url)
    assert dl_apk.status_code == 200
    with zipfile.ZipFile(io.BytesIO(dl_apk.data), "r") as zf:
        assert "classes.dex" in zf.namelist()

    # FART export
    fart = client.post(f"/api/v1/samples/{apk_id}/export/fart", json={})
    assert fart.status_code == 200
    assert fart.get_json()["total_methods"] == 1

    # Commercial Reports in all 4 formats
    for fmt, expected_token in (
        ("html", "<!DOCTYPE html>"),
        ("markdown", "# UNPACK Security Audit"),
        ("sarif", '"version": "2.1.0"'),
        ("json", '"risk_grade"'),
    ):
        r = client.get(f"/api/v1/reports/{apk_id}?format={fmt}&download=1")
        assert r.status_code == 200
        assert "attachment;" in r.headers.get("Content-Disposition", "")
        text = r.get_data(as_text=True)
        assert expected_token in text


def test_studio_async_pipeline_sse_and_doctor(studio_client):
    client, local_apks, _ = studio_client

    # Doctor (fast mode without ADB probing)
    doc = client.get("/api/v1/doctor?check_devices=false")
    assert doc.status_code == 200
    doc_data = doc.get_json()
    assert "checks" in doc_data and "engines" in doc_data

    # Launch scan_only async pipeline and verify SSE stream
    apk_sample = client.post(
        "/api/v1/samples/import-local",
        json={"path": str(local_apks / "demo_packed.apk"), "auto_scan": False},
    ).get_json()["sample"]
    sid = apk_sample["id"]

    launch = client.post(f"/api/v1/samples/{sid}/pipeline", json={"start_from": "scan_only"})
    assert launch.status_code == 202
    job_id = launch.get_json()["job_id"]

    # Read SSE stream until terminal event
    sse = client.get(f"/api/v1/jobs/{job_id}/events")
    assert sse.status_code == 200
    assert "text/event-stream" in sse.content_type
    body = sse.get_data(as_text=True)
    assert "event: snapshot" in body
    assert ("event: done" in body) or ('"status": "done"' in body)

    # Job detail & list
    job = client.get(f"/api/v1/jobs/{job_id}").get_json()
    assert job["status"] == "done"
    assert job["phases"]["scan"]["packer_name"] == "360加固保"

    jobs_list = client.get("/api/v1/jobs").get_json()["jobs"]
    assert any(j["id"] == job_id for j in jobs_list)


# ---------------------------------------------------------------------------
# 4. Backward-Compatible Legacy /api/* Endpoints
# ---------------------------------------------------------------------------


def test_legacy_api_compatibility(studio_client):
    client, _, _ = studio_client

    # /api/scan
    r = client.post(
        "/api/scan",
        data={"file": (io.BytesIO(_build_synthetic_apk()), "legacy.apk")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 200
    assert r.get_json()["packer_name"] == "360加固保"

    # /api/verify & /api/repair with traversal filename sanitized
    corrupt = _build_dex_with_class(corrupt_checksum=True)
    r_ver = client.post(
        "/api/verify",
        data={"files": (io.BytesIO(corrupt), "../evil.dex")},
        content_type="multipart/form-data",
    )
    assert r_ver.status_code == 200
    ver_item = r_ver.get_json()["results"][0]
    assert ver_item["file"] == "evil.dex"
    assert ver_item["valid"] is False

    r_rep = client.post(
        "/api/repair",
        data={"files": (io.BytesIO(corrupt), "../evil.dex")},
        content_type="multipart/form-data",
    )
    assert r_rep.status_code == 200
    assert r_rep.get_json()["results"][0]["success"] is True

    # /api/full (scan_only) + /api/job/<id> + /api/job/<id>/export + /api/cache
    r_full = client.post(
        "/api/full",
        data={
            "file": (io.BytesIO(_build_synthetic_apk()), "legacy_full.apk"),
            "start_from": "scan_only",
        },
        content_type="multipart/form-data",
    )
    assert r_full.status_code == 200
    jid = r_full.get_json()["job_id"]

    for _ in range(30):
        j = client.get(f"/api/job/{jid}").get_json()
        if j["status"] in {"done", "failed"}:
            break
        time.sleep(0.05)
    assert j["status"] == "done"

    exp = client.get(f"/api/job/{jid}/export")
    assert exp.status_code == 200
    assert exp.get_json()["tool"] == "unpack"

    cache = client.get("/api/cache").get_json()["items"]
    assert any(c["filename"] == "legacy_full.apk" for c in cache)


# ---------------------------------------------------------------------------
# 5. Wave 2: Bilingual Reports, Deep Pipeline Planner & Offline E2E Telemetry
# ---------------------------------------------------------------------------


def test_bilingual_report_export_zh_and_en(studio_client):
    client, local_apks, _ = studio_client

    sample = client.post(
        "/api/v1/samples/import-local",
        json={"path": str(local_apks / "demo_packed.apk"), "auto_scan": True},
    ).get_json()["sample"]
    sid = sample["id"]

    # Chinese HTML & Markdown via /api/v1/samples/<id>/reports
    r_html_zh = client.get(f"/api/v1/samples/{sid}/reports?format=html&lang=zh")
    assert r_html_zh.status_code == 200
    body_zh = r_html_zh.get_data(as_text=True)
    assert "<!DOCTYPE html>" in body_zh
    assert "安全审计报告" in body_zh

    r_md_zh = client.get(f"/api/v1/samples/{sid}/reports?format=markdown&lang=zh")
    assert r_md_zh.status_code == 200
    md_zh = r_md_zh.get_data(as_text=True)
    assert "UNPACK 安全审计报告" in md_zh
    assert "安全与脱壳风险发现" in md_zh

    # English HTML & Markdown via /api/v1/samples/<id>/reports
    r_html_en = client.get(f"/api/v1/samples/{sid}/reports?format=html&lang=en")
    assert r_html_en.status_code == 200
    assert "<!DOCTYPE html>" in r_html_en.get_data(as_text=True)

    r_md_en = client.get(f"/api/v1/samples/{sid}/reports?format=markdown&lang=en")
    assert r_md_en.status_code == 200
    assert "# UNPACK Security Audit" in r_md_en.get_data(as_text=True)


def test_pipeline_plan_preflight_and_offline_end_to_end_telemetry(studio_client):
    client, local_apks, local_dexs = studio_client

    # Mount APK with corrupt DEX checksum so repair stage has real work to fix
    corrupt_apk_path = local_apks / "corrupt_packed.apk"
    corrupt_apk_path.write_bytes(
        _build_synthetic_apk(dex_bytes=_build_dex_with_class(corrupt_checksum=True))
    )
    sample = client.post(
        "/api/v1/samples/import-local",
        json={"path": str(corrupt_apk_path), "auto_scan": True},
    ).get_json()["sample"]
    sid = sample["id"]

    # 1. Plan offline_audit in zh
    plan_off = client.post(
        "/api/v1/pipeline/plan",
        json={
            "sample_id": sid,
            "mode": "offline_audit",
            "repack": True,
            "generate_report": True,
            "lang": "zh",
            "check_devices": False,
        },
    )
    assert plan_off.status_code == 200
    po = plan_off.get_json()
    assert po["mode"] == "offline_audit"
    assert po["recommended_mode"] == "offline_audit"
    assert po["can_run"] is True
    assert po["blocking_count"] == 0
    assert len(po["stages"]) == 6
    assert [s["id"] for s in po["stages"]] == [
        "intake",
        "scan_inspect",
        "extract_dex",
        "repair_verify",
        "vmp_xref",
        "repack_report",
    ]
    for st in po["stages"]:
        assert st["what_it_does"]
        assert st["why_it_matters"]
        assert isinstance(st["inputs"], list) and isinstance(st["outputs"], list)
        assert st["will_run"] is True

    # 2. Plan device_deep with 0 devices -> blocked with fallback_mode=offline_audit
    plan_dev = client.post(
        "/api/v1/pipeline/plan",
        json={
            "sample_id": sid,
            "mode": "device_deep",
            "lang": "en",
            "check_devices": False,
        },
    )
    assert plan_dev.status_code == 200
    pd = plan_dev.get_json()
    assert pd["can_run"] is False
    assert pd["blocking_count"] >= 1
    assert any(c.get("fallback_mode") == "offline_audit" for c in pd["preflight_checks"])

    # 3. Plan DEX dir -> recommends repair_repack
    dex_sample = client.post(
        "/api/v1/samples/import-local",
        json={"path": str(local_dexs)},
    ).get_json()["sample"]
    plan_dex = client.post(
        "/api/v1/pipeline/plan",
        json={"sample_id": dex_sample["id"], "lang": "zh", "check_devices": False},
    ).get_json()
    assert plan_dex["recommended_mode"] == "repair_repack"
    assert plan_dex["can_run"] is True

    # 4. Launch real Offline End-to-End Pipeline via POST /api/v1/jobs/pipeline
    launch = client.post(
        "/api/v1/jobs/pipeline",
        json={
            "sample_id": sid,
            "mode": "offline_audit",
            "repack": True,
            "generate_report": True,
            "lang": "zh",
        },
    )
    assert launch.status_code == 202
    job_id = launch.get_json()["job_id"]

    # Stream SSE until terminal event
    sse = client.get(f"/api/v1/jobs/{job_id}/events")
    assert sse.status_code == 200
    sse_body = sse.get_data(as_text=True)
    assert "event: snapshot" in sse_body
    assert ("event: stage" in sse_body) or ('"stages":' in sse_body)
    assert ("event: done" in sse_body) or ('"status": "done"' in sse_body)

    # Verify structured per-stage telemetry on completed job
    job = client.get(f"/api/v1/jobs/{job_id}").get_json()
    assert job["status"] == "done"
    assert job["mode"] == "offline_audit"
    stages_by_id = {st["id"]: st for st in job["stages"]}
    for stage_id in ("intake", "scan_inspect", "extract_dex", "repair_verify", "vmp_xref", "repack_report"):
        st = stages_by_id[stage_id]
        assert st["status"] == "done", f"Stage {stage_id} was {st['status']}"
        assert st["summary"]
        assert isinstance(st["metrics"], dict) and len(st["metrics"]) >= 1
        assert len(st["logs"]) >= 1

    # Repair stage resolved the corrupt checksum and produced downloadable artifacts
    assert stages_by_id["repair_verify"]["metrics"]["issues_resolved"] >= 1
    assert len(job["artifacts"]) >= 3  # repaired DEX zip + repacked APK + HTML report
    for art in job["artifacts"]:
        dl = client.get(art["download_url"])
        assert dl.status_code == 200
        assert len(dl.data) > 0

    # Sample record is enriched with scan, inspect, repair_diffs, vmp, and xref
    enriched = client.get(f"/api/v1/samples/{sid}").get_json()["sample"]
    assert enriched["scan_result"]["packer_name"] == "360加固保"
    assert enriched["inspect_result"] is not None
    assert enriched["vmp_result"]["total_methods"] == 1
    assert enriched["xref_result"] is not None
    assert len(enriched["repair_diffs"]) == 1


# ---------------------------------------------------------------------------
# 6. Wave 3: Persistent Workspaces, Notes/Bookmarks & Embedded AI Analysis
# ---------------------------------------------------------------------------


def test_workspace_persistence_across_restarts_and_crud_export_import(tmp_path):
    ws_dir = tmp_path / "persistent_home"
    local_apks = tmp_path / "local_apks"
    local_apks.mkdir(parents=True)
    apk_path = local_apks / "persist_demo.apk"
    apk_path.write_bytes(_build_synthetic_apk())

    # ── Session 1: import, scan, add notes/bookmarks, run offline pipeline ──
    app1 = create_app(local_roots=[local_apks], workspace_dir=ws_dir)
    app1.config["TESTING"] = True
    try:
        with app1.test_client() as c1:
            imp = c1.post(
                "/api/v1/samples/import-local",
                json={"path": str(apk_path), "auto_scan": True},
            )
            assert imp.status_code == 200
            sid = imp.get_json()["sample"]["id"]

            # Save analyst notes & method bookmark
            note_res = c1.patch(
                f"/api/v1/samples/{sid}/notes",
                json={
                    "notes": "Confirmed 360 packer; hook Demo.secret()",
                    "bookmarks": [
                        {
                            "key": "classes.dex::Lcom/example/Demo;->secret#0",
                            "dex_name": "classes.dex",
                            "class_name": "Lcom/example/Demo;",
                            "method_name": "secret",
                            "method_idx": 0,
                            "label": "Demo.secret",
                        }
                    ],
                },
            )
            assert note_res.status_code == 200
            assert note_res.get_json()["sample"]["notes"] == "Confirmed 360 packer; hook Demo.secret()"

            # Run quick offline pipeline so a pipeline run persists too
            launch = c1.post(
                "/api/v1/jobs/pipeline",
                json={"sample_id": sid, "mode": "offline_audit", "repack": False, "generate_report": False},
            )
            assert launch.status_code == 202
            jid = launch.get_json()["job_id"]
            sse_text = c1.get(f"/api/v1/jobs/{jid}/events").get_data(as_text=True)
            assert ("event: done" in sse_text) or ('"status": "done"' in sse_text)
    finally:
        app1.config["UNPACK_CLEANUP"]()

    # ── Session 2: brand-new Flask app on same workspace_dir auto-restores! ──
    app2 = create_app(local_roots=[local_apks], workspace_dir=ws_dir)
    app2.config["TESTING"] = True
    try:
        with app2.test_client() as c2:
            listed = c2.get("/api/v1/samples").get_json()["items"]
            assert any(item["id"] == sid and item["packer"] == "360加固保" for item in listed)

            detail = c2.get(f"/api/v1/samples/{sid}").get_json()["sample"]
            assert detail["notes"] == "Confirmed 360 packer; hook Demo.secret()"
            assert len(detail["bookmarks"]) == 1
            assert detail["bookmarks"][0]["method_name"] == "secret"

            hist = c2.get("/api/v1/workspaces/default/history").get_json()
            assert len(hist["samples"]) >= 1
            assert len(hist["pipeline_runs"]) >= 1

            # Workspace CRUD: create -> rename/pin -> export -> import -> delete
            created = c2.post(
                "/api/v1/workspaces",
                json={"name": "Bank Audit", "description": "Q4 mobile audit", "activate": True},
            )
            assert created.status_code == 201
            ws_id = created.get_json()["workspace"]["id"]

            patched = c2.patch(f"/api/v1/workspaces/{ws_id}", json={"name": "Bank Audit v2", "pinned": True})
            assert patched.status_code == 200
            assert patched.get_json()["workspace"]["name"] == "Bank Audit v2"
            assert patched.get_json()["workspace"]["pinned"] is True

            # Export default workspace as JSON and re-import into a new workspace
            exported = c2.get("/api/v1/workspaces/default/export")
            assert exported.status_code == 200
            assert "attachment;" in exported.headers.get("Content-Disposition", "")
            bundle = json.loads(exported.get_data(as_text=True))
            assert len(bundle["samples"]) >= 1

            imp_ws = c2.post("/api/v1/workspaces/import", json={"bundle": bundle, "name": "Restored Backup"})
            assert imp_ws.status_code == 201
            restored_id = imp_ws.get_json()["workspace"]["id"]
            assert imp_ws.get_json()["workspace"]["sample_count"] >= 1

            # Default workspace cannot be deleted; custom workspaces can
            assert c2.delete("/api/v1/workspaces/default").status_code == 400
            assert c2.delete(f"/api/v1/workspaces/{ws_id}").status_code == 200
            assert c2.delete(f"/api/v1/workspaces/{restored_id}").status_code == 200
    finally:
        app2.config["UNPACK_CLEANUP"]()


def test_ai_config_mask_preserve_test_and_embedded_module_analyses(studio_client, monkeypatch):
    client, local_apks, _ = studio_client

    # Import sample
    sample = client.post(
        "/api/v1/samples/import-local",
        json={"path": str(local_apks / "demo_packed.apk"), "auto_scan": True},
    ).get_json()["sample"]
    sid = sample["id"]

    # 1. Default config is unconfigured & exposes presets without raw key
    cfg_get = client.get("/api/v1/ai/config")
    assert cfg_get.status_code == 200
    body = cfg_get.get_json()
    assert len(body["presets"]) >= 7
    assert "api_key" not in body["config"]
    assert body["config"]["configured"] is False

    # Calling AI analyze while unconfigured returns clean 400 ENGINE_UNAVAILABLE
    unconf = client.post(f"/api/v1/samples/{sid}/ai/scan", json={"lang": "zh"})
    assert unconf.status_code == 400
    assert unconf.get_json()["code"] == "ENGINE_UNAVAILABLE"

    # 2. Save OpenAI key -> returned masked; updating model with blank/masked key preserves key!
    put1 = client.put(
        "/api/v1/ai/config",
        json={
            "provider": "openai",
            "model": "gpt-4o-mini",
            "api_key": "sk-secret-test-key-9876",
            "enabled": True,
        },
    )
    assert put1.status_code == 200
    c1 = put1.get_json()["config"]
    assert c1["configured"] is True
    assert c1["has_api_key"] is True
    assert "9876" in c1["api_key_masked"]
    assert "sk-secret-test-key-9876" not in json.dumps(c1)

    put2 = client.put(
        "/api/v1/ai/config",
        json={"provider": "openai", "model": "gpt-4o", "api_key": c1["api_key_masked"]},
    )
    assert put2.status_code == 200
    assert put2.get_json()["config"]["has_api_key"] is True
    assert put2.get_json()["config"]["model"] == "gpt-4o"

    # 3. Mock _invoke_chat_completion for deterministic offline test of connection & all 5 AI modules
    import unpack.core.ai_engine as ai_mod

    def _fake_invoke(cfg, *, system_prompt, user_prompt, lang="zh", max_tokens=None):
        return (
            f"## Mock AI Verdict ({lang})\n\n- Provider: `{cfg.provider}`\n- Model: `{cfg.model}`\n\n```java\npublic static void secret() {{ /* https://api.example.com/v1 */ }}\n```",
            {"prompt_tokens": 120, "completion_tokens": 64, "total_tokens": 184},
            42,
        )

    monkeypatch.setattr(ai_mod, "_invoke_chat_completion", _fake_invoke)

    # Test connection endpoint
    test_res = client.post("/api/v1/ai/test", json={"lang": "zh"})
    assert test_res.status_code == 200
    tj = test_res.get_json()
    assert tj["ok"] is True
    assert tj["latency_ms"] == 42

    # Run all 5 embedded AI modules and verify persisted AI history
    for mod, payload in (
        ("scan", {"lang": "zh"}),
        ("security", {"lang": "en"}),
        ("method", {"lang": "zh", "dex_name": "classes.dex", "class_name": "Lcom/example/Demo;", "method_name": "secret"}),
        ("vmp_native", {"lang": "zh"}),
        ("pipeline_issue", {"lang": "zh", "stage": {"name": "dynamic_dump"}, "error_text": "No ADB devices"}),
    ):
        r = client.post(f"/api/v1/samples/{sid}/ai/{mod}", json=payload)
        assert r.status_code == 200, f"AI module {mod} failed: {r.get_data(as_text=True)}"
        ana = r.get_json()["analysis"]
        assert ana["module"] == mod
        assert "Mock AI Verdict" in ana["markdown"]

    hist = client.get(f"/api/v1/samples/{sid}/ai").get_json()["analyses"]
    assert len(hist) == 5
    assert {h["module"] for h in hist} == {"scan", "security", "method", "vmp_native", "pipeline_issue"}

    # Clear API key works
    cleared = client.put("/api/v1/ai/config", json={"clear_api_key": True}).get_json()["config"]
    assert cleared["has_api_key"] is False
    assert cleared["configured"] is False


def test_pipeline_guards_snapshot_only_sample_and_auto_relocates(tmp_path):
    """Regression: moving repo or restarting on a snapshot-only sample must never raise PathLike NoneType."""
    ws_dir = tmp_path / "unpack_home"
    old_dir = tmp_path / "old_repo" / "test_apks"
    new_dir = tmp_path / "new_repo" / "test_apks"
    old_dir.mkdir(parents=True)
    new_dir.mkdir(parents=True)

    apk_bytes = _build_synthetic_apk()
    old_apk = old_dir / "moved_sample.apk"
    old_apk.write_bytes(apk_bytes)

    # Session 1: mount from old_dir & scan so it persists with old_dir source_path
    app1 = create_app(local_roots=[old_dir], workspace_dir=ws_dir)
    c1 = app1.test_client()
    mounted = c1.post(
        "/api/v1/samples/import-local",
        json={"path": str(old_apk), "auto_scan": True},
    ).get_json()["sample"]
    sid = mounted["id"]
    assert c1.post(f"/api/v1/samples/{sid}/scan").status_code == 200

    # Simulate repo directory moved away (old path deleted, no replacement yet -> snapshot-only)
    old_apk.unlink()
    app2 = create_app(local_roots=[new_dir], workspace_dir=ws_dir)
    c2 = app2.test_client()

    # Preflight plan blocks device mode clearly
    plan = c2.post(
        "/api/v1/pipeline/plan",
        json={"sample_id": sid, "mode": "device_standard", "lang": "zh", "check_devices": False},
    ).get_json()
    sample_check = next(ch for ch in plan["preflight_checks"] if ch["id"] == "sample_ready")
    assert sample_check["status"] == "block"

    # Launching device_standard fails gracefully in intake with helpful message (never TypeError NoneType)
    launch = c2.post(
        "/api/v1/jobs/pipeline",
        json={"sample_id": sid, "mode": "device_standard", "lang": "zh"},
    )
    assert launch.status_code == 202
    jid = launch.get_json()["job_id"]
    job = None
    for _ in range(40):
        job = c2.get(f"/api/v1/jobs/{jid}").get_json()
        if job["status"] in {"done", "failed"}:
            break
        time.sleep(0.05)
    assert job["status"] == "failed"
    assert "NoneType" not in (job.get("error") or "")
    assert "原路径" in (job.get("error") or "")

    # Offline pipeline reuses persisted snapshot cleanly without crashing
    launch_off = c2.post(
        "/api/v1/jobs/pipeline",
        json={"sample_id": sid, "mode": "offline_audit", "lang": "zh", "generate_report": True},
    )
    assert launch_off.status_code == 202
    jid_off = launch_off.get_json()["job_id"]
    job_off = None
    for _ in range(40):
        job_off = c2.get(f"/api/v1/jobs/{jid_off}").get_json()
        if job_off["status"] in {"done", "failed"}:
            break
        time.sleep(0.05)
    assert job_off["status"] == "done"

    # Now place the moved APK under new_dir -> Session 3 auto-relocates it by filename + SHA-256!
    (new_dir / "moved_sample.apk").write_bytes(apk_bytes)
    app3 = create_app(local_roots=[new_dir], workspace_dir=ws_dir)
    c3 = app3.test_client()
    restored = c3.get(f"/api/v1/samples/{sid}").get_json()["sample"]
    assert restored["file_available"] is True



