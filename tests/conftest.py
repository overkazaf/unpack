from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_APKS_DIR = PROJECT_ROOT / "test_apks"


def _build_minimal_dex() -> bytearray:
    data = bytearray(256)
    data[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 32, len(data))  # file_size
    struct.pack_into("<I", data, 36, 0x70)  # header_size
    struct.pack_into("<I", data, 40, 0x12345678)  # endian_tag
    struct.pack_into("<I", data, 52, 0)  # map_off
    # string/type/proto/field/method/class ids all zero
    for off in range(56, 104, 4):
        struct.pack_into("<I", data, off, 0)
    struct.pack_into("<I", data, 104, len(data) - 0x70)  # data_size
    struct.pack_into("<I", data, 108, 0x70)  # data_off
    sig = hashlib.sha1(bytes(data[32:])).digest()
    data[12:32] = sig
    checksum = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", data, 8, checksum)
    return data


@pytest.fixture
def synthetic_dex() -> bytearray:
    return _build_minimal_dex()


@pytest.fixture
def synthetic_dex_bytes() -> bytes:
    return bytes(_build_minimal_dex())


@pytest.fixture
def corrupt_dex_too_small() -> bytes:
    return b"dex\n035\x00" + b"\x00" * 10


@pytest.fixture
def corrupt_dex_bad_magic() -> bytes:
    data = _build_minimal_dex()
    data[0:8] = b"NOT_DEX!"
    return bytes(data)


@pytest.fixture
def tmp_dex(synthetic_dex, tmp_path) -> Path:
    p = tmp_path / "test.dex"
    p.write_bytes(bytes(synthetic_dex))
    return p


@pytest.fixture
def tmp_dex_dir(synthetic_dex, tmp_path) -> Path:
    d = tmp_path / "dexdir"
    d.mkdir()
    (d / "classes_001.dex").write_bytes(bytes(synthetic_dex))
    (d / "classes_002.dex").write_bytes(bytes(synthetic_dex))
    return d


def apk_path(name: str) -> Path:
    return TEST_APKS_DIR / name


def has_apk(name: str) -> bool:
    return apk_path(name).exists()
