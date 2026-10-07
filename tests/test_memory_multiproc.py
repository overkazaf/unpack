from __future__ import annotations

import struct
from unittest.mock import patch
import subprocess
import pytest

from unpack.engines.memory_engine import _find_child_pids, _sliding_dex_scan


class TestFindChildPids:
    def test_finds_children(self):
        with patch("unpack.engines.memory_engine.adb_shell") as mock:
            mock.return_value = "1234\n5678\n"
            pids = _find_child_pids("serial", "1000")
        assert pids == ["1234", "5678"]

    def test_no_children(self):
        with patch("unpack.engines.memory_engine.adb_shell") as mock:
            mock.return_value = ""
            pids = _find_child_pids("serial", "1000")
        assert pids == []

    def test_handles_error(self):
        with patch("unpack.engines.memory_engine.adb_shell",
                   side_effect=subprocess.CalledProcessError(1, "")):
            pids = _find_child_pids("serial", "1000")
        assert pids == []

    def test_filters_non_numeric(self):
        with patch("unpack.engines.memory_engine.adb_shell") as mock:
            mock.return_value = "1234\nnot_a_pid\n5678\n"
            pids = _find_child_pids("serial", "1000")
        assert pids == ["1234", "5678"]


class TestSlidingDexScan:
    def _make_dex_header(self) -> bytes:
        hdr = bytearray(112)
        hdr[0:8] = b"dex\n035\x00"
        struct.pack_into("<I", hdr, 32, 200)       # file_size
        struct.pack_into("<I", hdr, 36, 0x70)       # header_size
        struct.pack_into("<I", hdr, 40, 0x12345678) # endian_tag
        return bytes(hdr)

    def test_finds_dex_at_offset(self):
        buf = bytearray(1024)
        dex_hdr = self._make_dex_header()
        buf[100:100 + len(dex_hdr)] = dex_hdr
        offsets = _sliding_dex_scan(bytes(buf))
        assert 100 in offsets

    def test_no_dex_in_zeros(self):
        assert _sliding_dex_scan(bytes(1024)) == []

    def test_finds_multiple(self):
        buf = bytearray(2048)
        dex_hdr = self._make_dex_header()
        buf[50:50 + len(dex_hdr)] = dex_hdr
        buf[500:500 + len(dex_hdr)] = dex_hdr
        offsets = _sliding_dex_scan(bytes(buf))
        assert 50 in offsets and 500 in offsets

    def test_rejects_bad_header_size(self):
        buf = bytearray(256)
        buf[0:4] = b"dex\n"
        struct.pack_into("<I", buf, 32, 200)
        struct.pack_into("<I", buf, 36, 0x50)  # wrong header_size
        struct.pack_into("<I", buf, 40, 0x12345678)
        assert _sliding_dex_scan(bytes(buf)) == []

    def test_max_scan_limit(self):
        buf = bytearray(2048)
        dex_hdr = self._make_dex_header()
        buf[1500:1500 + len(dex_hdr)] = dex_hdr
        # max_scan=1000 should miss the DEX at offset 1500
        assert _sliding_dex_scan(bytes(buf), max_scan=1000) == []

    def test_empty_input(self):
        assert _sliding_dex_scan(b"") == []
