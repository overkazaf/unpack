from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from unpack.cli import app, EXIT_NO_PACKER, EXIT_OK, _gate_low_confidence
from unpack.core.scanner import PackerScanner, ScanResult

runner = CliRunner()


@pytest.fixture
def low_confidence_apk(tmp_path) -> Path:
    """A synthetic APK that trips exactly one weak signal: a substring
    match for a cert keyword ("tencent") in a META-INF/ entry *name*.

    This mirrors the real false positive the fix targets — a single
    matched cert keyword scoring 1.0/13.5 ~= 7.4% confidence for
    "腾讯乐固" — with no SO files, assets, app class, or DEX prefix hits.
    No other vendor signature matches, so it's the unique top candidate.
    """
    p = tmp_path / "weak.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("META-INF/tencent.SF", b"")
    return p


class TestConfidenceGateUnit:
    """Direct unit tests of the gating function, independent of display."""

    def test_passes_through_high_confidence(self):
        result = ScanResult(packer_name="X", confidence=0.9)
        assert _gate_low_confidence(result, verbose=False) is result

    def test_suppresses_sub_10pct_when_not_verbose(self):
        result = ScanResult(packer_name="X", confidence=0.07)
        gated = _gate_low_confidence(result, verbose=False)
        assert gated.packer_name is None
        assert "use -v" in gated.details

    def test_verbose_bypasses_suppression(self):
        result = ScanResult(packer_name="X", confidence=0.07)
        assert _gate_low_confidence(result, verbose=True) is result

    def test_15pct_is_not_suppressed(self):
        # Between the 10% hide threshold and the 20% POSSIBLE threshold:
        # still shown (just framed as POSSIBLE at the display layer).
        result = ScanResult(packer_name="X", confidence=0.15)
        assert _gate_low_confidence(result, verbose=False) is result


class TestScanConfidenceCli:
    def test_confirms_real_scanner_yields_sub_10pct(self, low_confidence_apk):
        # Sanity-check the fixture against the real scanner (not a mock)
        # before relying on it to exercise the CLI threshold behavior.
        result = PackerScanner().scan(low_confidence_apk)
        assert result.packer_name == "腾讯乐固"
        assert 0.0 < result.confidence < 0.1

    def test_hidden_by_default(self, low_confidence_apk):
        result = runner.invoke(app, ["scan", str(low_confidence_apk)])
        assert "DETECTED" not in result.output
        assert "POSSIBLE" not in result.output
        assert "NO PACKER" in result.output
        assert "use -v" in result.output
        assert result.exit_code == EXIT_NO_PACKER

    def test_shown_as_possible_with_verbose(self, low_confidence_apk):
        result = runner.invoke(app, ["scan", str(low_confidence_apk), "-v"])
        assert "POSSIBLE" in result.output
        assert "DETECTED" not in result.output
        assert result.exit_code == EXIT_OK

    def test_json_stdout_is_suppressed_by_default(self, low_confidence_apk):
        result = runner.invoke(app, ["scan", str(low_confidence_apk), "-j", "-"])
        assert result.exit_code == EXIT_NO_PACKER
        start = result.output.find("{")
        end = result.output.rfind("}") + 1
        data = json.loads(result.output[start:end])
        assert data["packer_name"] is None

    def test_json_stdout_shows_data_with_verbose(self, low_confidence_apk):
        result = runner.invoke(app, ["scan", str(low_confidence_apk), "-j", "-", "-v"])
        assert result.exit_code == EXIT_OK
        start = result.output.find("{")
        end = result.output.rfind("}") + 1
        data = json.loads(result.output[start:end])
        assert data["packer_name"] == "腾讯乐固"
