from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unpack.cli import app
from conftest import has_apk, apk_path

runner = CliRunner()


class TestCliHelp:
    def test_main_help(self):
        result = runner.invoke(app, [])
        assert result.exit_code == 0

    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "APK" in result.output

    def test_dump_help(self):
        result = runner.invoke(app, ["dump", "--help"])
        assert result.exit_code == 0

    def test_repair_help(self):
        result = runner.invoke(app, ["repair", "--help"])
        assert result.exit_code == 0

    def test_verify_help(self):
        result = runner.invoke(app, ["verify", "--help"])
        assert result.exit_code == 0


class TestCliScan:
    def test_scan_nonexistent(self):
        result = runner.invoke(app, ["scan", "nonexistent.apk"])
        assert result.exit_code == 1

    @pytest.mark.skipif(
        not has_apk("com.android.bankabc.apk"),
        reason="test APK not available",
    )
    def test_scan_real_apk(self):
        result = runner.invoke(app, ["scan", str(apk_path("com.android.bankabc.apk"))])
        assert result.exit_code == 0
        assert "DETECTED" in result.output or "NO PACKER" in result.output

    @pytest.mark.skipif(
        not has_apk("com.android.bankabc.apk"),
        reason="test APK not available",
    )
    def test_scan_json_stdout(self):
        result = runner.invoke(app, [
            "scan", str(apk_path("com.android.bankabc.apk")), "--json", "-",
        ])
        assert result.exit_code == 0
        # The output mixes rich panels with JSON. Extract the JSON block.
        output = result.output
        start = output.find("{")
        end = output.rfind("}") + 1
        assert start >= 0 and end > start, f"No JSON found in output: {output[:200]}"
        data = json.loads(output[start:end])
        assert "packer_name" in data
        assert "protection_level" in data


class TestCliRepair:
    def test_repair_nonexistent(self):
        result = runner.invoke(app, ["repair", "nonexistent.dex"])
        assert result.exit_code != 0

    def test_repair_dir(self, tmp_dex_dir):
        result = runner.invoke(app, ["repair", str(tmp_dex_dir)])
        assert result.exit_code == 0
        assert "repaired" in result.output.lower()


class TestCliVerify:
    def test_verify_nonexistent(self):
        result = runner.invoke(app, ["verify", "nonexistent.dex"])
        assert result.exit_code != 0

    def test_verify_dir(self, tmp_dex_dir):
        result = runner.invoke(app, ["verify", str(tmp_dex_dir)])
        assert result.exit_code == 0
        assert "PASS" in result.output
