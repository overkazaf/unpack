from __future__ import annotations

import struct
from pathlib import Path

import pytest

from unpack.repair.oat_parser import OatParser, OatInfo, OAT_MAGIC


def _build_minimal_oat_with_dex(dex_data: bytes) -> bytearray:
    """Build a minimal OAT-like data blob containing one DEX."""
    oat = bytearray()
    oat += b"oat\n"           # magic (4)
    oat += b"131\x00"         # version (4)
    oat += struct.pack("<I", 0)   # checksum (4)
    oat += struct.pack("<I", 3)   # instruction_set = ARM64 (4)
    oat += struct.pack("<I", 0)   # instruction_set_features (4)
    oat += struct.pack("<I", 1)   # dex_file_count (4)
    oat += struct.pack("<I", 0)   # placeholder (4)
    # Pad to offset 64
    while len(oat) < 64:
        oat += b"\x00"
    # Embed the DEX
    oat += dex_data
    return oat


class TestOatDetection:
    def test_is_oat_true(self):
        data = b"oat\n131\x00" + b"\x00" * 100
        assert OatParser.is_oat(data) is True

    def test_is_oat_false_dex(self):
        data = b"dex\n035\x00" + b"\x00" * 100
        assert OatParser.is_oat(data) is False

    def test_is_oat_false_too_small(self):
        assert OatParser.is_oat(b"oat") is False

    def test_is_oat_false_empty(self):
        assert OatParser.is_oat(b"") is False


class TestOatInfo:
    def test_parse_info(self):
        data = _build_minimal_oat_with_dex(b"\x00" * 256)
        info = OatParser.parse_info(data)
        assert info.magic == b"oat\n"
        assert info.version == "131"
        assert info.dex_file_count == 1

    def test_parse_info_too_small(self):
        with pytest.raises(ValueError, match="too small"):
            OatParser.parse_info(b"oat\n" + b"\x00" * 10)


class TestOatExtractDex:
    def test_extract_dex_from_oat(self, synthetic_dex_bytes):
        oat_data = _build_minimal_oat_with_dex(synthetic_dex_bytes)
        parser = OatParser()
        dex_list = parser.extract_dex(bytes(oat_data))
        assert len(dex_list) == 1
        assert dex_list[0][:4] == b"dex\n"
        assert len(dex_list[0]) == len(synthetic_dex_bytes)

    def test_extract_no_dex(self):
        parser = OatParser()
        oat_data = b"oat\n131\x00" + b"\x00" * 200
        dex_list = parser.extract_dex(oat_data)
        assert len(dex_list) == 0

    def test_extract_multiple_dex(self, synthetic_dex_bytes):
        # Embed two DEX files with padding between
        oat = bytearray(b"oat\n131\x00" + b"\x00" * 56)  # 64 bytes header
        oat += synthetic_dex_bytes
        # Align to 4 bytes
        while len(oat) % 4 != 0:
            oat += b"\x00"
        oat += synthetic_dex_bytes
        parser = OatParser()
        dex_list = parser.extract_dex(bytes(oat))
        assert len(dex_list) == 2
