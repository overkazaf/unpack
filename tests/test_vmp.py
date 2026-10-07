from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from unpack.analysis.vmp import MethodClassification, VmpDetector, VmpReport
from unpack.cli import app

runner = CliRunner()


@pytest.fixture
def detector():
    return VmpDetector()


class TestMethodClassification:
    def test_enum_values(self):
        assert MethodClassification.NORMAL.value == "normal"
        assert MethodClassification.NOP.value == "nop"
        assert MethodClassification.VMP_STUB.value == "vmp_stub"


class TestVmpDetector:
    def test_classify_nop_insns(self, detector):
        insns = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        assert detector.classify_insns(insns, insns_size=4) == MethodClassification.NOP

    def test_classify_normal_insns(self, detector):
        # A longer, non-trivial sequence of bytecode-shaped bytes - too
        # long to be a VMP stub and not all-zero, so it must be NORMAL.
        insns = bytes(
            [
                0x12, 0x00,  # const/4 v0, #0
                0x13, 0x01, 0x05, 0x00,  # const/16 v1, #5
                0x90, 0x00, 0x01, 0x02,  # add-int v0, v1, v2
                0x59, 0x00, 0x03, 0x00,  # iput v0, v3, field@0
                0x0e, 0x00,  # return-void
            ]
        )
        assert detector.classify_insns(insns, insns_size=8) == MethodClassification.NORMAL

    def test_classify_vmp_stub_short(self, detector):
        insns = b"\x71\x20\x05\x00\x10\x00"  # invoke-static
        assert detector.classify_insns(insns, insns_size=3) == MethodClassification.VMP_STUB

    def test_classify_vmp_stub_with_return(self, detector):
        # invoke-static followed only by return-void -> still a stub
        insns = b"\x71\x10\x02\x00\x00\x00" + b"\x0e\x00"
        assert detector.classify_insns(insns, insns_size=4) == MethodClassification.VMP_STUB

    def test_classify_too_many_non_trivial_ops_is_normal(self, detector):
        # insns_size is within the VMP stub size limit (<=5) and an invoke
        # is present, but there are too many other non-trivial opcodes for
        # this to be considered a pure dispatcher stub.
        insns = bytes(
            [
                0x71, 0x10,  # invoke-static
                0x02, 0x00,  # non-trivial op
                0x13, 0x00,  # non-trivial op (const/16-shaped)
                0x90, 0x00,  # non-trivial op (add-int-shaped)
                0x0e, 0x00,  # return-void
            ]
        )
        assert detector.classify_insns(insns, insns_size=5) == MethodClassification.NORMAL

    def test_classify_no_invoke_short_is_normal(self, detector):
        # Short body but no invoke opcode at all -> NORMAL, not VMP_STUB.
        insns = b"\x0e\x00\x00\x00"
        assert detector.classify_insns(insns, insns_size=2) == MethodClassification.NORMAL

    def test_classify_empty_insns(self, detector):
        assert detector.classify_insns(b"", insns_size=0) == MethodClassification.NORMAL

    def test_report_from_empty_dex(self, detector, synthetic_dex_bytes):
        report = detector.analyze_dex(synthetic_dex_bytes)
        assert isinstance(report, VmpReport)
        assert report.total_methods == 0
        assert report.normal_count == 0
        assert report.nop_count == 0
        assert report.vmp_count == 0
        assert report.vmp_methods == []
        assert report.call_graph == []

    def test_analyze_file_from_disk(self, detector, tmp_dex):
        report = detector.analyze_file(tmp_dex)
        assert report.total_methods == 0

    def test_report_to_dict(self, detector):
        report = VmpReport(
            total_methods=10,
            normal_count=7,
            nop_count=1,
            vmp_count=2,
            vmp_methods=[{"class_name": "LFoo;", "method_name": "bar"}],
            call_graph=[{"caller": "LFoo;->bar", "callee": "LDispatch;->exec"}],
        )
        d = report.to_dict()
        assert d == {
            "total_methods": 10,
            "normal_count": 7,
            "nop_count": 1,
            "vmp_count": 2,
            "vmp_methods": [{"class_name": "LFoo;", "method_name": "bar"}],
            "call_graph": [{"caller": "LFoo;->bar", "callee": "LDispatch;->exec"}],
        }


class TestVmpCli:
    def test_vmp_help(self):
        result = runner.invoke(app, ["vmp", "--help"])
        assert result.exit_code == 0

    def test_vmp_nonexistent(self):
        result = runner.invoke(app, ["vmp", "nonexistent.dex"])
        assert result.exit_code != 0

    def test_vmp_dir(self, tmp_dex_dir):
        result = runner.invoke(app, ["vmp", str(tmp_dex_dir)])
        assert result.exit_code == 0
        assert "VMP" in result.output.upper()

    def test_vmp_json_output(self, tmp_dex_dir, tmp_path):
        out = tmp_path / "vmp.json"
        result = runner.invoke(app, ["vmp", str(tmp_dex_dir), "--json", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "total_methods" in data
        assert "vmp_methods" in data
        assert "call_graph" in data
