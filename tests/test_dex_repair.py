from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

import pytest

from unpack.repair.dex_repair import DexRepairPipeline, RepairResult


@pytest.fixture
def pipeline():
    return DexRepairPipeline()


class TestRepairValid:
    def test_valid_dex_no_major_repairs(self, pipeline, tmp_dex):
        result = pipeline.repair(tmp_dex)
        assert result.success
        assert result.output_path is not None
        assert result.output_path.exists()

    def test_output_is_repaired_suffix(self, pipeline, tmp_dex):
        result = pipeline.repair(tmp_dex, in_place=False)
        assert result.output_path.name.endswith("_repaired.dex")

    def test_in_place(self, pipeline, tmp_dex):
        result = pipeline.repair(tmp_dex, in_place=True)
        assert result.output_path == tmp_dex


class TestRepairCorrupt:
    def test_wrong_file_size(self, pipeline, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        struct.pack_into("<I", data, 32, 999999)
        p = tmp_path / "bad_size.dex"
        p.write_bytes(bytes(data))
        result = pipeline.repair(p)
        assert result.success
        assert any("file_size" in a for a in result.actions)

    def test_wrong_checksum(self, pipeline, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        struct.pack_into("<I", data, 8, 0xDEADBEEF)
        p = tmp_path / "bad_checksum.dex"
        p.write_bytes(bytes(data))
        result = pipeline.repair(p)
        assert result.success
        assert any("checksum" in a.lower() for a in result.actions)

    def test_wrong_signature(self, pipeline, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        data[12:32] = b"\x00" * 20
        p = tmp_path / "bad_sig.dex"
        p.write_bytes(bytes(data))
        result = pipeline.repair(p)
        assert result.success
        assert any("sha-1" in a.lower() or "signature" in a.lower() for a in result.actions)

    def test_corrupt_map_off(self, pipeline, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        struct.pack_into("<I", data, 52, 0xFFFFFFFF)
        p = tmp_path / "bad_map.dex"
        p.write_bytes(bytes(data))
        result = pipeline.repair(p)
        assert result.success
        assert any("map_off" in a for a in result.actions)

    def test_too_small(self, pipeline, tmp_path):
        p = tmp_path / "tiny.dex"
        p.write_bytes(b"dex\n035\x00" + b"\x00" * 10)
        result = pipeline.repair(p)
        assert not result.success
        assert any("too small" in a for a in result.actions)


class TestRepairSectionBounds:
    def test_section_off_past_eof(self, pipeline, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        struct.pack_into("<I", data, 60, 0xFFFFF)  # string_ids_off way past EOF
        struct.pack_into("<I", data, 56, 10)  # string_ids_size = 10
        p = tmp_path / "bad_section.dex"
        p.write_bytes(bytes(data))
        result = pipeline.repair(p)
        assert result.success
        assert any("section" in a.lower() or "bounds" in a.lower() for a in result.actions)


class TestRepairTruncation:
    def test_class_data_off_past_eof(self, pipeline, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        # Set class_defs to have 1 entry at offset 0x70
        struct.pack_into("<I", data, 96, 1)   # class_defs_size=1
        struct.pack_into("<I", data, 100, 0x70)  # class_defs_off=0x70
        # Write class_def with class_data_off=0xFFFF (past EOF of 256-byte file)
        struct.pack_into("<8I", data, 0x70, 0, 0, 0, 0, 0, 0, 0xFFFF, 0)
        p = tmp_path / "truncated.dex"
        p.write_bytes(bytes(data))
        result = pipeline.repair(p)
        assert result.success
        assert any(
            "class_def" in a.lower() or "eof" in a.lower() or "truncat" in a.lower() or "pointer" in a.lower()
            for a in result.actions
        )


class TestRepairDebugInfo:
    def test_debug_info_off_zeroed(self, pipeline):
        data = bytearray(256)
        # Put a fake code_item at offset 0x80 with debug_info_off=0xFFFF (at offset 0x80+8=0x88)
        struct.pack_into("<I", data, 0x88, 0xFFFF)
        actions = []
        data = pipeline._fix_debug_info_offsets(data, [(0x80, 20)], 256, actions)
        assert struct.unpack_from("<I", data, 0x88)[0] == 0
        assert any("debug" in a.lower() for a in actions)


class TestRepairOutputVerifiable:
    def test_repaired_checksum_valid(self, pipeline, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        struct.pack_into("<I", data, 32, 999999)
        struct.pack_into("<I", data, 8, 0xDEADBEEF)
        p = tmp_path / "broken.dex"
        p.write_bytes(bytes(data))
        result = pipeline.repair(p)
        repaired = result.output_path.read_bytes()
        stored_cs = struct.unpack_from("<I", repaired, 8)[0]
        computed_cs = zlib.adler32(repaired[12:]) & 0xFFFFFFFF
        assert stored_cs == computed_cs

    def test_repaired_signature_valid(self, pipeline, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        data[12:32] = b"\xFF" * 20
        p = tmp_path / "broken2.dex"
        p.write_bytes(bytes(data))
        result = pipeline.repair(p)
        repaired = result.output_path.read_bytes()
        stored_sig = repaired[12:32]
        computed_sig = hashlib.sha1(repaired[32:]).digest()
        assert stored_sig == computed_sig
