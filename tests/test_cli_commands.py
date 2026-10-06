from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unpack.cli import app

runner = CliRunner()


def _build_mini_apk(path: Path, dex_data: bytes):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", dex_data)
        zf.writestr("AndroidManifest.xml", b"manifest")
        zf.writestr("res/layout/main.xml", b"<L/>")


class TestExportCommand:
    def test_export_fart(self, synthetic_dex_bytes, tmp_path):
        dex_dir = tmp_path / "dex"
        dex_dir.mkdir()
        (dex_dir / "classes.dex").write_bytes(synthetic_dex_bytes)
        result = runner.invoke(app, ["export", str(dex_dir), "-o", str(tmp_path / "out")])
        assert result.exit_code == 0
        assert "Exported" in result.stdout or "methods" in result.stdout

    def test_export_no_dex(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        result = runner.invoke(app, ["export", str(empty)])
        assert result.exit_code != 0

    def test_export_unknown_format(self, tmp_path):
        result = runner.invoke(app, ["export", str(tmp_path), "-f", "unknown"])
        assert result.exit_code != 0


class TestRepackCommand:
    def test_repack_success(self, synthetic_dex_bytes, tmp_path):
        apk = tmp_path / "test.apk"
        _build_mini_apk(apk, b"original")
        dex_dir = tmp_path / "dex"
        dex_dir.mkdir()
        (dex_dir / "classes_000.dex").write_bytes(synthetic_dex_bytes)
        result = runner.invoke(app, ["repack", str(apk), str(dex_dir), "-o", str(tmp_path / "out")])
        assert result.exit_code == 0
        assert "Repacked" in result.stdout

    def test_repack_missing_apk(self, tmp_path):
        result = runner.invoke(app, ["repack", str(tmp_path / "nope.apk"), str(tmp_path)])
        assert result.exit_code != 0


class TestReassembleCommand:
    def test_reassemble_success(self, synthetic_dex_bytes, tmp_path):
        apk = tmp_path / "test.apk"
        _build_mini_apk(apk, synthetic_dex_bytes)
        dex_dir = tmp_path / "dex"
        dex_dir.mkdir()
        (dex_dir / "classes_000.dex").write_bytes(synthetic_dex_bytes)
        result = runner.invoke(app, ["reassemble", str(apk), str(dex_dir)])
        assert result.exit_code == 0

    def test_reassemble_missing_apk(self, tmp_path):
        result = runner.invoke(app, ["reassemble", str(tmp_path / "nope.apk"), str(tmp_path)])
        assert result.exit_code != 0


class TestVmpCommand:
    def test_vmp_on_dex(self, synthetic_dex_bytes, tmp_path):
        dex_dir = tmp_path / "dex"
        dex_dir.mkdir()
        (dex_dir / "classes.dex").write_bytes(synthetic_dex_bytes)
        result = runner.invoke(app, ["vmp", str(dex_dir)])
        assert result.exit_code == 0

    def test_vmp_missing_path(self, tmp_path):
        result = runner.invoke(app, ["vmp", str(tmp_path / "nope")])
        assert result.exit_code != 0
