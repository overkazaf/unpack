from __future__ import annotations

import struct
from dataclasses import dataclass


OAT_MAGIC = b"oat\n"


@dataclass
class OatInfo:
    magic: bytes
    version: str
    dex_file_count: int


class OatParser:
    @staticmethod
    def is_oat(data: bytes) -> bool:
        return len(data) >= 8 and data[:4] == OAT_MAGIC

    @staticmethod
    def parse_info(data: bytes) -> OatInfo:
        if len(data) < 24:
            raise ValueError("Data too small for OAT header")
        magic = data[:4]
        version = data[4:7].decode("ascii", errors="replace")
        dex_count = struct.unpack_from("<I", data, 20)[0] if len(data) >= 24 else 0
        return OatInfo(magic=magic, version=version, dex_file_count=dex_count)

    def extract_dex(self, data: bytes) -> list[bytes]:
        """Scan OAT data for embedded DEX files by searching for DEX magic."""
        results = []
        search_start = 0
        while search_start < len(data) - 112:
            pos = data.find(b"dex\n", search_start)
            if pos < 0:
                break
            if pos + 40 > len(data):
                break
            try:
                file_size = struct.unpack_from("<I", data, pos + 32)[0]
                header_size = struct.unpack_from("<I", data, pos + 36)[0]
                endian_tag = struct.unpack_from("<I", data, pos + 40)[0]
            except struct.error:
                search_start = pos + 4
                continue

            if (header_size == 0x70 and
                file_size >= 112 and
                file_size <= 100 * 1024 * 1024 and
                endian_tag in (0x12345678, 0x78563412)):
                end = min(pos + file_size, len(data))
                results.append(data[pos:end])
                search_start = pos + file_size
            else:
                search_start = pos + 4

        return results
