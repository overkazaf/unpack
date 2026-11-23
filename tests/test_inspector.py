from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from conftest import apk_path, has_apk
from unpack.core.errors import ApkValidationError, ErrorCode, UnpackError
from unpack.core.inspector import ApkInspector, ApkInspectResult, _detect_apk_sig_block_schemes
from unpack.core.scanner import PackerScanner, ProtectionLevel


def _build_apk_with_v2_sig_block(dest: Path, entries: dict[str, bytes]) -> Path:
    """Create a valid ZIP/APK and inject a minimal APK Signing Block (v2 + v3) before EOCD/CD."""
    raw_zip = dest.with_suffix(".tmp.apk")
    with zipfile.ZipFile(raw_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)

    blob = bytearray(raw_zip.read_bytes())
    raw_zip.unlink()

    eocd_pos = blob.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", blob, eocd_pos + 16)[0]

    # Build APK Signing Block with v2 (0x7109871a) and v3 (0xf05368c0) IDs
    pair_v2 = struct.pack("<QI", 4 + 4, 0x7109871A) + b"V2OK"
    pair_v3 = struct.pack("<QI", 4 + 4, 0xF05368C0) + b"V3OK"
    pairs = pair_v2 + pair_v3
    block_size = len(pairs) + 24
    sig_block = (
        struct.pack("<Q", block_size)
        + pairs
        + struct.pack("<Q", block_size)
        + b"APK Sig Block 42"
    )

    new_cd_offset = cd_offset + len(sig_block)
    new_blob = bytearray(blob[:cd_offset]) + sig_block + bytearray(blob[cd_offset:])
    new_eocd = new_blob.rfind(b"PK\x05\x06")
    struct.pack_into("<I", new_blob, new_eocd + 16, new_cd_offset)
    dest.write_bytes(bytes(new_blob))
    return dest


class TestApkInspectorSynthetic:
    def test_missing_apk_raises_unpack_error(self, tmp_path):
        with pytest.raises(UnpackError) as exc_info:
            ApkInspector().inspect(tmp_path / "missing.apk")
        assert exc_info.value.code == ErrorCode.FILE_NOT_FOUND
        assert exc_info.value.exit_code == 5

    def test_non_zip_raises_apk_validation_error(self, tmp_path):
        bad = tmp_path / "bad.apk"
        bad.write_text("definitely not a zip")
        with pytest.raises(ApkValidationError) as exc_info:
            ApkInspector().inspect(bad)
        assert exc_info.value.code == ErrorCode.INVALID_APK

    def test_inspect_synthetic_apk_with_v2_v3_signing(self, tmp_path, synthetic_dex_bytes):
        apk = _build_apk_with_v2_sig_block(
            tmp_path / "demo.apk",
            {
                "classes.dex": synthetic_dex_bytes,
                "assets/jiagu_stub.dat": b"\x01\x02\x03",
                "lib/armeabi-v7a/libhelper.so": b"not_elf",
                "META-INF/CERT.RSA": b"fake_der",
            },
        )
        v2, v3, v31 = _detect_apk_sig_block_schemes(apk)
        assert v2 is True
        assert v3 is True
        assert v31 is False

        res = ApkInspector().inspect(apk)
        assert isinstance(res, ApkInspectResult)
        assert res.file == "demo.apk"
        assert len(res.sha256) == 64
        assert res.signing.v1_signed is True
        assert res.signing.v2_signed is True
        assert res.signing.v3_signed is True
        assert "v2" in res.signing.schemes
        assert "v3" in res.signing.schemes
        assert res.assets_count == 1
        assert "assets/jiagu_stub.dat" in res.suspicious_assets
        assert len(res.native_libs) == 1
        assert res.native_libs[0].abi == "armeabi-v7a"
        assert len(res.dex_files) == 1
        assert res.dex_files[0].name == "classes.dex"
        assert 0 <= res.risk_score <= 100
        assert res.risk_grade in {"A", "B", "C", "D", "F"}

        d = res.to_dict()
        for key in (
            "file", "sha256", "size_bytes", "manifest", "signing",
            "permissions", "components", "native_libs", "dex_files",
            "assets_count", "suspicious_assets", "findings", "risk_score",
            "risk_grade", "warnings",
        ):
            assert key in d


class TestScannerPrecisionFixes:
    def test_tiny_unpacked_apk_does_not_false_positive_360(self, tmp_path, synthetic_dex_bytes):
        """Regression test: a tiny classes.dex alone must NOT trigger 360加固保."""
        apk = tmp_path / "tiny_clean.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", synthetic_dex_bytes)
        result = PackerScanner().scan(apk)
        assert result.packer_name is None
        assert result.protection_level == ProtectionLevel.NONE
        assert len(result.heuristic_anomalies) == 1
        assert "classes.dex" in result.heuristic_anomalies[0]

    def test_exact_so_basename_matching_and_evidence_chain(self, tmp_path, synthetic_dex_bytes):
        apk = tmp_path / "packed.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", synthetic_dex_bytes)
            zf.writestr("lib/arm64-v8a/libDexHelper.so", b"\x00" * 64)
            zf.writestr("lib/armeabi-v7a/libDexHelper.so", b"\x00" * 64)
            zf.writestr("assets/secData0.jar", b"payload")
        result = PackerScanner().scan(apk, verbose=True)
        assert result.packer_name == "梆梆安全"
        assert len(result.evidence) >= 2
        assert result.recommended_engine in ("memory", "ebpf", "frida")
        assert result.strategy_reason != ""
        assert result.risk_score >= 50
        assert "arm64-v8a" in result.all_so_by_abi
        assert "armeabi-v7a" in result.all_so_by_abi

        vd = result.to_verbose_dict()
        assert "evidence" in vd
        assert "all_so_by_abi" in vd
        assert "recommended_engine" in vd

    def test_substring_so_name_does_not_false_match(self, tmp_path):
        """libfake_libjiagu.so must NOT match libjiagu.so."""
        apk = tmp_path / "substring.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("lib/arm64-v8a/libfake_libjiagu.so", b"\x00" * 32)
        result = PackerScanner().scan(apk)
        assert result.packer_name is None


@pytest.mark.skipif(
    not has_apk("com.nemesis.droidcrypt.apk"),
    reason="sample test APK not available",
)
class TestApkInspectorRealSample:
    def test_inspect_real_apk(self):
        res = ApkInspector().inspect(apk_path("com.nemesis.droidcrypt.apk"))
        assert res.manifest.package != ""
        assert len(res.dex_files) >= 1
        assert res.risk_grade in {"A", "B", "C", "D", "F"}
