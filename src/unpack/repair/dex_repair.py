from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from unpack.repair.dex_parser import DexFile, VALID_MAGICS, HEADER_SIZE, is_cdex


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

        if is_cdex(bytes(data)):
            data, _ = self._convert_cdex(data, actions)

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
        data = self._fix_section_bounds(data, fmt, actions)
        data = self._fix_truncated_class_defs(data, fmt, actions)
        data = self._fix_map_off(data, dex.header, fmt, actions)
        data = self._fix_code_item_alignment(data, dex, actions)
        code_item_offsets = [(ci.offset, ci.insns_size) for ci in dex.code_items]
        data = self._fix_debug_info_offsets(data, code_item_offsets, len(data), actions)

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
    def _convert_cdex(data: bytearray, actions: list[str]) -> tuple[bytearray, bool]:
        version = bytes(data[4:7])
        actions.append(f"detected CompactDex (version {version.decode('ascii', errors='replace')})")
        data[0:8] = b"dex\n035\x00"
        actions.append("converted CDEX -> standard DEX (magic replacement)")
        return data, True

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

    # (size_off, off_off, entry_size) for each DEX header section that
    # points into the file via a (size, off) pair.
    _SECTION_FIELDS = (
        ("string_ids", 56, 60, 4),
        ("type_ids", 64, 68, 4),
        ("proto_ids", 72, 76, 12),
        ("field_ids", 80, 84, 8),
        ("method_ids", 88, 92, 8),
        ("class_defs", 96, 100, 32),
    )

    @staticmethod
    def _fix_section_bounds(
        data: bytearray, fmt: str, actions: list[str]
    ) -> bytearray:
        """Zero out any header section (size, off) pair whose span runs
        past the end of the file. Re-reads values from `data` directly
        since earlier steps (e.g. _fix_file_size) may have modified the
        header in place.
        """
        file_len = len(data)
        for name, size_off, off_off, entry_size in DexRepairPipeline._SECTION_FIELDS:
            size = struct.unpack_from(f"{fmt}I", data, size_off)[0]
            off = struct.unpack_from(f"{fmt}I", data, off_off)[0]
            if size == 0:
                continue

            end = off + size * entry_size
            if off >= file_len or end > file_len:
                struct.pack_into(f"{fmt}I", data, size_off, 0)
                struct.pack_into(f"{fmt}I", data, off_off, 0)
                actions.append(
                    f"zeroed out-of-bounds {name} section bounds: "
                    f"size={size}, off={off:#x} (needs {end} bytes, file_len={file_len})"
                )

        return data

    @staticmethod
    def _fix_truncated_class_defs(
        data: bytearray, fmt: str, actions: list[str]
    ) -> bytearray:
        """Walk class_defs entries and zero any class_data_off/annotations_off/
        static_values_off pointer that lies at or past EOF (truncated dump).
        Re-reads class_defs_size/off from `data` directly since earlier
        steps may have modified the header in place.
        """
        file_len = len(data)
        class_defs_size = struct.unpack_from(f"{fmt}I", data, 96)[0]
        class_defs_off = struct.unpack_from(f"{fmt}I", data, 100)[0]
        if class_defs_size == 0 or class_defs_off == 0:
            return data

        entry_size = 32
        pointer_fields = (
            ("annotations_off", 20),
            ("class_data_off", 24),
            ("static_values_off", 28),
        )

        for i in range(class_defs_size):
            entry_off = class_defs_off + i * entry_size
            if entry_off + entry_size > file_len:
                break

            for field_name, field_rel_off in pointer_fields:
                ptr_off = entry_off + field_rel_off
                value = struct.unpack_from(f"{fmt}I", data, ptr_off)[0]
                if value != 0 and value >= file_len:
                    struct.pack_into(f"{fmt}I", data, ptr_off, 0)
                    actions.append(
                        f"zeroed truncated class_def[{i}] {field_name} pointer: "
                        f"{value:#x} >= file_len {file_len}"
                    )

        return data

    @staticmethod
    def _fix_debug_info_offsets(
        data: bytearray,
        code_item_offsets: list[tuple[int, int]],
        file_len: int,
        actions: list[str],
    ) -> bytearray:
        """Zero any CodeItem's debug_info_off that points at or past EOF."""
        for ci_offset, _insns_size in code_item_offsets:
            debug_info_ptr = ci_offset + 8
            if debug_info_ptr + 4 > len(data):
                continue

            debug_info_off = struct.unpack_from("<I", data, debug_info_ptr)[0]
            if debug_info_off != 0 and debug_info_off >= file_len:
                struct.pack_into("<I", data, debug_info_ptr, 0)
                actions.append(
                    f"zeroed out-of-bounds debug_info_off at code_item {ci_offset:#x}: "
                    f"{debug_info_off:#x} >= file_len {file_len}"
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
