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
