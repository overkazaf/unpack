from __future__ import annotations

import struct

import pytest

from unpack.repair.verifier import DexVerifier, VerifyResult


@pytest.fixture
def verifier():
    return DexVerifier()


class TestVerifyValid:
    def test_valid_dex_passes(self, verifier, tmp_dex):
        result = verifier.verify(tmp_dex)
        assert result.valid
        assert result.issues == []

    def test_stats_populated(self, verifier, tmp_dex):
        result = verifier.verify(tmp_dex)
        assert "file_size" in result.stats
        assert "class_count" in result.stats
        assert result.stats["class_count"] == 0
        assert result.stats["method_count"] == 0


class TestVerifyCorrupt:
    def test_too_small(self, verifier, tmp_path):
        p = tmp_path / "tiny.dex"
        p.write_bytes(b"dex\n035\x00" + b"\x00" * 10)
        result = verifier.verify(p)
        assert not result.valid
        assert any("too small" in i for i in result.issues)

    def test_bad_magic(self, verifier, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        data[0:8] = b"NOT_DEX!"
        p = tmp_path / "bad_magic.dex"
        p.write_bytes(bytes(data))
        result = verifier.verify(p)
        assert not result.valid
        assert any("magic" in i.lower() for i in result.issues)

    def test_wrong_file_size(self, verifier, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        struct.pack_into("<I", data, 32, 999999)
        p = tmp_path / "bad_size.dex"
        p.write_bytes(bytes(data))
        result = verifier.verify(p)
        assert not result.valid
        assert any("file_size" in i for i in result.issues)

    def test_wrong_checksum(self, verifier, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        struct.pack_into("<I", data, 8, 0xDEADBEEF)
        p = tmp_path / "bad_cs.dex"
        p.write_bytes(bytes(data))
        result = verifier.verify(p)
        assert not result.valid
        assert any("checksum" in i.lower() for i in result.issues)

    def test_wrong_signature(self, verifier, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        data[12:32] = b"\x00" * 20
        p = tmp_path / "bad_sig.dex"
        p.write_bytes(bytes(data))
        result = verifier.verify(p)
        assert not result.valid
        assert any("signature" in i.lower() for i in result.issues)
