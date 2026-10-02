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
