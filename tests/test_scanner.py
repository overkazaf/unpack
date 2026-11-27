from __future__ import annotations

from pathlib import Path

import pytest

from unpack.core.scanner import PackerScanner, ProtectionLevel
from conftest import has_apk, apk_path


@pytest.fixture
def scanner():
    return PackerScanner()


class TestScannerBasic:
    def test_non_zip_file(self, scanner, tmp_path):
        p = tmp_path / "not_an_apk.txt"
        p.write_text("hello world")
        result = scanner.scan(p)
        assert result.packer_name is None
        assert "Not a valid ZIP" in result.details

    def test_empty_zip(self, scanner, tmp_path):
        import zipfile
        p = tmp_path / "empty.apk"
        with zipfile.ZipFile(p, "w"):
            pass
        result = scanner.scan(p)
        assert result.packer_name is None
        assert result.protection_level == ProtectionLevel.NONE


@pytest.mark.skipif(
    not has_apk("com.netease.cloudmusic.apk"),
    reason="test APK not available",
)
class TestScannerNetease:
    def test_detect_netease(self, scanner):
        result = scanner.scan(apk_path("com.netease.cloudmusic.apk"))
        assert result.packer_name == "网易易盾"
        assert result.confidence > 0.3
        assert len(result.matched_signatures) >= 2

    def test_verbose_populates_fields(self, scanner):
        result = scanner.scan(apk_path("com.netease.cloudmusic.apk"), verbose=True)
        assert len(result.all_so_files) > 0
        assert len(result.all_dex_info) > 0
        assert result.apk_info.get("dex_count", 0) > 0

    def test_score_breakdown_populated(self, scanner):
        result = scanner.scan(apk_path("com.netease.cloudmusic.apk"))
        assert len(result.score_breakdown) == 6
        hit_dims = [b for b in result.score_breakdown if b["matched"]]
        assert len(hit_dims) >= 2


@pytest.mark.skipif(
    not has_apk("com.android.bankabc.apk"),
    reason="test APK not available",
)
class TestScannerBangbang:
    def test_detect_bangbang(self, scanner):
        result = scanner.scan(apk_path("com.android.bankabc.apk"))
        assert result.packer_name == "梆梆安全"
        assert result.confidence > 0.1
        assert any("libDexHelper" in s for s in result.matched_signatures)


@pytest.mark.skipif(
    not has_apk("com.tencent.mm.apk"),
    reason="test APK not available",
)
class TestScannerNoPacker:
    def test_wechat_no_packer(self, scanner):
        result = scanner.scan(apk_path("com.tencent.mm.apk"))
        assert result.packer_name is None
        assert result.protection_level == ProtectionLevel.NONE


class TestScanResultSerialization:
    def test_to_dict(self, scanner, tmp_path):
        import zipfile
        p = tmp_path / "fake.apk"
        with zipfile.ZipFile(p, "w"):
            pass
        result = scanner.scan(p)
        d = result.to_dict()
        assert "packer_name" in d
        assert "protection_level" in d
        assert "confidence" in d

    def test_to_report(self, scanner, tmp_path):
        import zipfile
        p = tmp_path / "fake.apk"
        with zipfile.ZipFile(p, "w"):
            pass
        result = scanner.scan(p, verbose=True)
        report = result.to_report()
        assert "UNPACK SCAN REPORT" in report


class TestSignaturesExtractionAndExitStack:
    def test_signatures_reexported_from_scanner(self):
        from unpack.core.scanner import PACKER_SIGNATURES as scanner_sigs
        from unpack.core.signatures import PACKER_SIGNATURES as sig_db

        assert scanner_sigs is sig_db
        assert len(sig_db) == 24

    def test_extra_apks_closed_on_exception(self, scanner, tmp_path, monkeypatch):
        import zipfile

        base_apk = tmp_path / "base.apk"
        split_apk = tmp_path / "split_arm64.apk"
        with zipfile.ZipFile(base_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"manifest")
        with zipfile.ZipFile(split_apk, "w") as zf:
            zf.writestr("lib/arm64-v8a/libjiagu.so", b"\x00" * 32)

        opened: list[zipfile.ZipFile] = []
        orig_zip = zipfile.ZipFile

        def _tracking_zip(*args, **kwargs):
            zf = orig_zip(*args, **kwargs)
            opened.append(zf)
            return zf

        monkeypatch.setattr("unpack.core.scanner.zipfile.ZipFile", _tracking_zip)
        monkeypatch.setattr(scanner, "_check_so", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))

        with pytest.raises(RuntimeError, match="boom"):
            scanner.scan(base_apk, extra_apks=[split_apk])

        assert len(opened) == 2
        assert all(zf.fp is None for zf in opened)
