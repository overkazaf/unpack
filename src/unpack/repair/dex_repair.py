from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from unpack.repair.dex_parser import DexFile, VALID_MAGICS, HEADER_SIZE


@dataclass
class RepairResult:
    success: bool
    actions: list[str] = field(default_factory=list)
    output_path: Path | None = None
    nop_method_count: int = 0


class DexRepairPipeline:
    def repair(self, dex_path: Path, in_place: bool = False) -> RepairResult:
        actions: list[str] = []
        data = bytearray(dex_path.read_bytes())

        if len(data) < HEADER_SIZE:
            return RepairResult(success=False, actions=["file too small for DEX header"])

        if bytes(data[:8]) not in VALID_MAGICS:
            fixed = self._try_fix_magic(data)
            if fixed:
                actions.append("fixed magic bytes")
            else:
                return RepairResult(success=False, actions=["invalid magic, unfixable"])

        try:
            dex = DexFile.parse(bytes(data))
        except Exception as e:
            return RepairResult(success=False, actions=[f"parse failed: {e}"])

        fmt = dex.fmt

        data = self._fix_file_size(data, dex.header, fmt, actions)
        data = self._fix_map_off(data, dex.header, fmt, actions)
        data = self._fix_code_item_alignment(data, dex, actions)

        nop_count = self._detect_nop_methods(dex, actions)

        data = self._fix_signature(data, actions)
        data = self._fix_checksum(data, fmt, actions)

        if not actions:
            actions.append("no repairs needed")

        out_path: Path
        if in_place:
            out_path = dex_path
        else:
            out_path = dex_path.with_name(dex_path.stem + "_repaired.dex")

        out_path.write_bytes(bytes(data))

        return RepairResult(
            success=True,
            actions=actions,
            output_path=out_path,
            nop_method_count=nop_count,
        )

    @staticmethod
    def _try_fix_magic(data: bytearray) -> bool:
        if data[:4] == b"dex\n" and len(data) >= 8:
            data[4:8] = b"035\x00"
            return True
        if len(data) >= 8:
            data[:8] = b"dex\n035\x00"
            return True
        return False

    @staticmethod
    def _fix_file_size(
        data: bytearray, header, fmt: str, actions: list[str]
    ) -> bytearray:
        actual = len(data)
        if header.file_size != actual:
            struct.pack_into(f"{fmt}I", data, 32, actual)
            actions.append(f"fixed file_size: {header.file_size} -> {actual}")

        expected_data_off = header.header_size
        expected_data_size = actual - expected_data_off
        if expected_data_size < 0:
            expected_data_size = 0

        if header.data_size != expected_data_size or header.data_off != expected_data_off:
            struct.pack_into(f"{fmt}I", data, 104, expected_data_size)
            struct.pack_into(f"{fmt}I", data, 108, expected_data_off)
            actions.append(
                f"fixed data_size/data_off: "
                f"{header.data_size}/{header.data_off} -> "
                f"{expected_data_size}/{expected_data_off}"
            )

        return data

    @staticmethod
    def _fix_map_off(
        data: bytearray, header, fmt: str, actions: list[str]
    ) -> bytearray:
        map_off = header.map_off
        if map_off == 0:
            return data

        file_len = len(data)
        if map_off >= file_len or map_off + 4 > file_len:
            struct.pack_into(f"{fmt}I", data, 52, 0)
            actions.append(f"zeroed invalid map_off: {map_off:#x}")
            return data

        map_size = struct.unpack_from(f"{fmt}I", data, map_off)[0]
        map_entry_size = 12
        expected_end = map_off + 4 + map_size * map_entry_size
        if map_size > 50 or expected_end > file_len:
            struct.pack_into(f"{fmt}I", data, 52, 0)
            actions.append(
                f"zeroed corrupt map_off: {map_off:#x} "
                f"(map_size={map_size}, would need {expected_end} bytes)"
            )

        return data

    @staticmethod
    def _detect_nop_methods(dex: DexFile, actions: list[str]) -> int:
        nop_count = 0
        for method in dex.all_methods:
            if method.code_item and method.code_item.insns_size > 0:
                if method.code_item.is_nop_only:
                    nop_count += 1

        if nop_count > 0:
            actions.append(
                f"detected {nop_count} NOP-only method(s) "
                f"(likely still-encrypted extracted methods)"
            )
        return nop_count

    @staticmethod
    def _fix_code_item_alignment(
        data: bytearray, dex: DexFile, actions: list[str]
    ) -> bytearray:
        misaligned = 0
        for item in dex.code_items:
            if item.offset % 4 != 0:
                misaligned += 1

        if misaligned > 0:
            actions.append(
                f"warning: {misaligned} CodeItem(s) not 4-byte aligned "
                f"(in-place alignment not applied — may need re-layout)"
            )
        return data

    @staticmethod
    def _fix_signature(data: bytearray, actions: list[str]) -> bytearray:
        current_sig = bytes(data[12:32])
        computed_sig = hashlib.sha1(bytes(data[32:])).digest()
        if current_sig != computed_sig:
            data[12:32] = computed_sig
            actions.append("fixed SHA-1 signature")
        return data

    @staticmethod
    def _fix_checksum(data: bytearray, fmt: str, actions: list[str]) -> bytearray:
        current = struct.unpack_from(f"{fmt}I", data, 8)[0]
        computed = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
        if current != computed:
            struct.pack_into(f"{fmt}I", data, 8, computed)
            actions.append(f"fixed Adler32 checksum: {current:#010x} -> {computed:#010x}")
        return data
