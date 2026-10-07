from __future__ import annotations

from unpack.repair.codeitem_merger import CodeItemMerger, CapturedCodeItem, MergeResult


class TestMergeResult:
    def test_default_fields(self):
        r = MergeResult(success=False)
        assert r.methods_merged == 0
        assert r.methods_still_nop == 0


class TestCapturedCodeItem:
    def test_fields(self):
        ci = CapturedCodeItem(insns=b"\x01\x02", insns_size=1, registers_size=2, ins_size=0, outs_size=0)
        assert ci.insns == b"\x01\x02"


class TestCodeItemMerger:
    def test_merge_empty_skeleton(self, tmp_dex, tmp_path):
        merger = CodeItemMerger()
        result = merger.merge(tmp_dex, [], tmp_path / "out.dex")
        assert result.success
        assert result.methods_merged == 0

    def test_merge_no_matching_code_items(self, tmp_dex, tmp_path):
        items = [{"method_idx": 999, "code_off": 0xFFFF, "insns": b"\x01\x02", "insns_size": 1, "registers_size": 1, "ins_size": 0, "outs_size": 0}]
        merger = CodeItemMerger()
        result = merger.merge(tmp_dex, items, tmp_path / "out.dex")
        assert result.success
        assert result.methods_merged == 0
