from __future__ import annotations

import json
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from unpack.cli import (
    app,
    EXIT_NO_DEVICE,
    EXIT_NOT_FOUND,
)

runner = CliRunner()


class TestScanBatch:
    def test_batch_empty_dir(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path), "--batch"])
        assert result.exit_code == 0  # no APKs = no output, not an error

    def test_batch_requires_dir(self, tmp_path):
        f = tmp_path / "fake.apk"
        f.write_bytes(b"not an apk")
        result = runner.invoke(app, ["scan", str(f), "--batch"])
        assert result.exit_code != 0

    def test_batch_outputs_jsonl_per_apk(self, tmp_path):
        # Two trivial (non-packed) zip "APKs" — batch mode should scan both
        # and emit exactly one JSON object per line, tagged with the
        # source filename, regardless of confidence (no suppression here —
        # batch is for bulk/automated consumption, not human display).
        for name in ("a.apk", "b.apk"):
            with zipfile.ZipFile(tmp_path / name, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"")

        result = runner.invoke(app, ["scan", str(tmp_path), "--batch"])
        assert result.exit_code == 0

        lines = [line for line in result.output.splitlines() if line.strip()]
        assert len(lines) == 2

        files_seen = set()
        for line in lines:
            d = json.loads(line)
            assert "packer_name" in d
            assert "file" in d
            files_seen.add(d["file"])
        assert files_seen == {"a.apk", "b.apk"}

    def test_batch_nonexistent_dir(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path / "nope"), "--batch"])
        assert result.exit_code != 0


class TestExitCodes:
    def test_scan_not_found(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path / "nope.apk")])
        assert result.exit_code != 0

    def test_scan_not_found_uses_not_found_code(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path / "nope.apk")])
        assert result.exit_code == EXIT_NOT_FOUND

    def test_verify_not_found(self, tmp_path):
        result = runner.invoke(app, ["verify", str(tmp_path / "nope")])
        assert result.exit_code != 0

    def test_repair_not_found(self, tmp_path):
        result = runner.invoke(app, ["repair", str(tmp_path / "nope")])
        assert result.exit_code != 0
        assert result.exit_code == EXIT_NOT_FOUND

    def test_dump_not_found(self, tmp_path):
        result = runner.invoke(app, ["dump", str(tmp_path / "nope.apk")])
        assert result.exit_code == EXIT_NOT_FOUND

    def test_dump_no_device(self, tmp_path, monkeypatch):
        # A real (if minimal) zip so we get past the "APK not found" check
        # and reach the device precondition.
        apk = tmp_path / "fake.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"")

        # Force "no device" deterministically — independent of whether the
        # machine running the suite happens to have adb/a phone attached.
        monkeypatch.setattr("unpack.utils.adb.get_device_serial", lambda *a, **kw: None)

        result = runner.invoke(app, ["dump", str(apk)])
        assert result.exit_code != 0
