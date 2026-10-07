from __future__ import annotations

import hashlib
import struct
import zlib

import pytest

from unpack.repair.dex_parser import CDEX_MAGIC, is_cdex
from unpack.repair.dex_repair import DexRepairPipeline


class TestCdexDetection:
    def test_is_cdex_true(self, synthetic_cdex_bytes):
        assert is_cdex(synthetic_cdex_bytes) is True

    def test_is_cdex_false(self, synthetic_dex_bytes):
        assert is_cdex(synthetic_dex_bytes) is False

    def test_is_cdex_too_small(self):
        assert is_cdex(b"cdex") is False


class TestCdexRepair:
    def test_cdex_detected_in_repair(self, tmp_cdex):
        pipeline = DexRepairPipeline()
        result = pipeline.repair(tmp_cdex)
        assert result.success
        assert any("cdex" in a.lower() or "compact" in a.lower() for a in result.actions)

    def test_cdex_converted_to_standard_dex(self, tmp_cdex):
        pipeline = DexRepairPipeline()
        result = pipeline.repair(tmp_cdex)
        assert result.success
        repaired = result.output_path.read_bytes()
        assert repaired[:4] == b"dex\n"

    def test_cdex_converted_checksum_valid(self, tmp_cdex):
        pipeline = DexRepairPipeline()
        result = pipeline.repair(tmp_cdex)
        repaired = result.output_path.read_bytes()
        stored = struct.unpack_from("<I", repaired, 8)[0]
        computed = zlib.adler32(repaired[12:]) & 0xFFFFFFFF
        assert stored == computed

    def test_cdex_converted_signature_valid(self, tmp_cdex):
        pipeline = DexRepairPipeline()
        result = pipeline.repair(tmp_cdex)
        repaired = result.output_path.read_bytes()
        stored_sig = repaired[12:32]
        computed_sig = hashlib.sha1(repaired[32:]).digest()
        assert stored_sig == computed_sig
