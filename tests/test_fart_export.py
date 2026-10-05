from __future__ import annotations

import struct
from pathlib import Path

import pytest

from unpack.export.fart import FartExporter, FartBinEntry, FartExportResult


class TestFartBinEntry:
    def test_serialize(self):
        entry = FartBinEntry(method_idx=42, code_off=0x100, insns_size=3, insns=b"\x01\x00\x02\x00\x03\x00")
        data = entry.to_bytes()
        assert len(data) == 12 + 6  # 3 uint32 header + 3*2 bytes insns
        idx, off, sz = struct.unpack_from("<III", data, 0)
        assert idx == 42
        assert off == 0x100
        assert sz == 3
        assert data[12:] == b"\x01\x00\x02\x00\x03\x00"

    def test_roundtrip(self):
        entry = FartBinEntry(method_idx=1, code_off=0x50, insns_size=2, insns=b"\xAA\xBB\xCC\xDD")
        data = entry.to_bytes()
        parsed = FartBinEntry.from_bytes(data)
        assert parsed.method_idx == entry.method_idx
        assert parsed.code_off == entry.code_off
        assert parsed.insns_size == entry.insns_size
        assert parsed.insns == entry.insns


class TestFartExporter:
    def test_export_from_dex(self, tmp_dex, tmp_path):
        exporter = FartExporter()
        out_dir = tmp_path / "fart_out"
        result = exporter.export(tmp_dex, out_dir)
        assert result.bin_path.exists()
        assert result.txt_path.exists()

    def test_export_empty_dex_produces_empty_files(self, tmp_dex, tmp_path):
        exporter = FartExporter()
        out_dir = tmp_path / "fart_out"
        result = exporter.export(tmp_dex, out_dir)
        assert result.method_count == 0
        assert result.bin_path.stat().st_size == 0

    def test_export_result_paths(self, tmp_dex, tmp_path):
        exporter = FartExporter()
        out_dir = tmp_path / "fart_out"
        result = exporter.export(tmp_dex, out_dir)
        assert result.bin_path.name == "test_fart.bin"
        assert result.txt_path.name == "test_fart.txt"
