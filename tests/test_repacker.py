from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from unpack.repack.repacker import Repacker, RepackResult


def _build_mini_apk(path: Path, dex_data: bytes, manifest_app_class: str = "") -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", dex_data)
        zf.writestr("res/layout/main.xml", b"<LinearLayout/>")
        zf.writestr("AndroidManifest.xml", b"AndroidManifest:" + manifest_app_class.encode())


@pytest.fixture
def repacker() -> Repacker:
    return Repacker()


@pytest.fixture
def mini_apk(tmp_path, synthetic_dex_bytes) -> Path:
    apk_path = tmp_path / "original.apk"
    _build_mini_apk(apk_path, synthetic_dex_bytes)
    return apk_path


@pytest.fixture
def dumped_dex_dir(tmp_path) -> Path:
    d = tmp_path / "dumped"
    d.mkdir()
    (d / "classes.dex").write_bytes(b"DUMPED_DEX_CONTENT")
    return d


class TestRepack:
    def test_repack_replaces_dex(self, repacker, mini_apk, dumped_dex_dir, tmp_path):
        output_dir = tmp_path / "out"
        result = repacker.repack(mini_apk, dumped_dex_dir, output_dir)

        assert result.success
        with zipfile.ZipFile(result.output_path) as zf:
            assert zf.read("classes.dex") == b"DUMPED_DEX_CONTENT"

    def test_repack_preserves_resources(self, repacker, mini_apk, dumped_dex_dir, tmp_path):
        output_dir = tmp_path / "out"
        result = repacker.repack(mini_apk, dumped_dex_dir, output_dir)

        assert result.success
        with zipfile.ZipFile(result.output_path) as zf:
            names = zf.namelist()
            assert "res/layout/main.xml" in names
            assert "AndroidManifest.xml" in names
            assert zf.read("res/layout/main.xml") == b"<LinearLayout/>"

    def test_repack_result_fields(self, repacker, mini_apk, dumped_dex_dir, tmp_path):
        output_dir = tmp_path / "out"
        result = repacker.repack(mini_apk, dumped_dex_dir, output_dir)

        assert isinstance(result, RepackResult)
        assert result.success
        assert result.output_path is not None
        assert result.output_path.exists()
        assert result.dex_count == 1
        assert result.resources_preserved >= 2
        assert result.error is None

    def test_repack_multi_dex(self, repacker, mini_apk, tmp_path):
        dex_dir = tmp_path / "multidex"
        dex_dir.mkdir()
        (dex_dir / "classes.dex").write_bytes(b"DEX_ONE")
        (dex_dir / "classes2.dex").write_bytes(b"DEX_TWO")

        output_dir = tmp_path / "out"
        result = repacker.repack(mini_apk, dex_dir, output_dir)

        assert result.success
        assert result.dex_count == 2
        with zipfile.ZipFile(result.output_path) as zf:
            assert zf.read("classes.dex") == b"DEX_ONE"
            assert zf.read("classes2.dex") == b"DEX_TWO"

    def test_repack_missing_apk(self, repacker, dumped_dex_dir, tmp_path):
        missing_apk = tmp_path / "does_not_exist.apk"
        output_dir = tmp_path / "out"
        result = repacker.repack(missing_apk, dumped_dex_dir, output_dir)

        assert not result.success
        assert result.error is not None
        assert "not found" in result.error.lower()
