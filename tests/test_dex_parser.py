from __future__ import annotations

import struct

import pytest

from unpack.repair.dex_parser import (
    DexFile, DexHeader, HEADER_SIZE, VALID_MAGICS,
    _uleb128, _sleb128,
)


class TestUleb128:
    def test_zero(self):
        assert _uleb128(bytes([0x00]), 0) == (0, 1)

    def test_one(self):
        assert _uleb128(bytes([0x01]), 0) == (1, 1)

    def test_127(self):
        assert _uleb128(bytes([0x7F]), 0) == (127, 1)

    def test_128(self):
        assert _uleb128(bytes([0x80, 0x01]), 0) == (128, 2)

    def test_large(self):
        # 624485 = 0x98765 → encoded as E5 8E 26
        assert _uleb128(bytes([0xE5, 0x8E, 0x26]), 0) == (624485, 3)

    def test_offset(self):
        data = bytes([0xFF, 0x05, 0x01])
        assert _uleb128(data, 1) == (5, 2)


class TestSleb128:
    def test_zero(self):
        assert _sleb128(bytes([0x00]), 0) == (0, 1)

    def test_minus_one(self):
        assert _sleb128(bytes([0x7F]), 0) == (-1, 1)

    def test_positive(self):
        assert _sleb128(bytes([0x01]), 0) == (1, 1)

    def test_minus_128(self):
        assert _sleb128(bytes([0x80, 0x7F]), 0) == (-128, 2)


class TestDexFileParse:
    def test_parse_minimal(self, synthetic_dex_bytes):
        dex = DexFile.parse(synthetic_dex_bytes)
        assert dex.header.magic in VALID_MAGICS
        assert dex.header.file_size == len(synthetic_dex_bytes)
        assert dex.header.header_size == 0x70
        assert dex.header.endian_tag == 0x12345678
        assert dex.header.class_defs_size == 0
        assert dex.class_defs == []

    def test_parse_too_small(self, corrupt_dex_too_small):
        with pytest.raises(ValueError, match="too small"):
            DexFile.parse(corrupt_dex_too_small)

    def test_checksum_roundtrip(self, synthetic_dex_bytes):
        dex = DexFile.parse(synthetic_dex_bytes)
        assert dex.compute_checksum() == dex.header.checksum

    def test_signature_roundtrip(self, synthetic_dex_bytes):
        dex = DexFile.parse(synthetic_dex_bytes)
        assert dex.compute_signature() == dex.header.signature

    def test_all_methods_empty(self, synthetic_dex_bytes):
        dex = DexFile.parse(synthetic_dex_bytes)
        assert dex.all_methods == []

    def test_code_items_empty(self, synthetic_dex_bytes):
        dex = DexFile.parse(synthetic_dex_bytes)
        assert dex.code_items == []
