from __future__ import annotations

import json
import struct

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
        # A bare invoke (format 35c) is already 3 code units by itself, so
        # a trailing return-void pushes this to 4 units -- over the
        # tightened MAX_VMP_STUB_UNITS (3). Only a bare dispatcher invoke
        # with nothing else in the body qualifies now (see
        # test_classify_vmp_stub_short); this used to be a stub when the
        # cap was 5, which is exactly the headroom that let ordinary short
        # constructors (invoke-direct <init> + return-void, also 4 units)
        # false-positive as VMP stubs.
        insns = b"\x71\x10\x02\x00\x00\x00" + b"\x0e\x00"
        assert detector.classify_insns(insns, insns_size=4) == MethodClassification.NORMAL

    def test_classify_too_many_non_trivial_ops_is_normal(self, detector):
        # insns_size is within the VMP stub size limit (<=3) and an invoke
        # is present, but every code unit's opcode byte happens to be
        # non-trivial (none are nop/return), so there are too many
        # non-trivial opcodes for this to be considered a pure dispatcher
        # stub.
        insns = bytes(
            [
                0x71, 0x10,  # invoke-static
                0x02, 0x00,  # non-trivial op (method_idx low byte)
                0x05, 0x00,  # non-trivial op (args low byte)
            ]
        )
        assert detector.classify_insns(insns, insns_size=3) == MethodClassification.NORMAL

    def test_short_constructor_is_not_vmp(self, detector):
        """super.<init>() + return-void should be NORMAL, not a VMP stub.

        This is the false-positive case from real unprotected apps: every
        trivial constructor that just chains to its superclass compiles to
        exactly this shape (invoke-direct, 3 units + return-void, 1 unit =
        4 units total, 1 invoke, 1 non-trivial extra byte at most) -- which
        satisfied the old heuristic. method_name="<init>" must short-circuit
        before the byte-level heuristic ever runs.
        """
        insns = struct.pack("<HHH", 0x1070, 0x0000, 0x0000) + struct.pack("<H", 0x000e)
        classification = detector.classify_insns(insns, insns_size=4, method_name="<init>")
        assert classification == MethodClassification.NORMAL

    def test_short_static_initializer_is_not_vmp(self, detector):
        """<clinit> is excluded the same way <init> is."""
        insns = b"\x71\x20\x05\x00\x10\x00"  # same bytes as the VMP_STUB case
        classification = detector.classify_insns(insns, insns_size=3, method_name="<clinit>")
        assert classification == MethodClassification.NORMAL

    def test_framework_invoke_is_not_vmp(self, detector):
        """A short invoke into java.lang.Object is NORMAL, not a VMP stub.

        Real VMP stubs call into the packer's own native dispatcher class,
        never straight into a java./android./kotlin./androidx./dalvik.
        framework class.
        """
        insns = struct.pack("<HHH", 0x2071, 0x0003, 0x0010)
        classification = detector.classify_insns(
            insns,
            insns_size=3,
            method_name="doSomething",
            invoke_target_class="Ljava/lang/Object;",
        )
        assert classification == MethodClassification.NORMAL

    def test_non_framework_invoke_is_still_vmp(self, detector):
        """Sanity check: the same short invoke into an app-private/packer
        class (not a framework prefix) is still classified as a VMP stub."""
        insns = struct.pack("<HHH", 0x2071, 0x0003, 0x0010)
        classification = detector.classify_insns(
            insns,
            insns_size=3,
            method_name="doSomething",
            invoke_target_class="Lcom/example/packer/VmpDispatcher;",
        )
        assert classification == MethodClassification.VMP_STUB

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
