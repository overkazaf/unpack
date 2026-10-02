from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from unpack.repair.dex_parser import DexFile, VALID_MAGICS, HEADER_SIZE


@dataclass
class VerifyResult:
    valid: bool
    issues: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


class DexVerifier:
    def verify(self, dex_path: Path) -> VerifyResult:
        issues: list[str] = []
        stats: dict = {}

        data = dex_path.read_bytes()
        stats["file_size"] = len(data)

        if len(data) < HEADER_SIZE:
            issues.append(f"file too small: {len(data)} < {HEADER_SIZE}")
            return VerifyResult(valid=False, issues=issues, stats=stats)

        magic = data[:8]
        if magic not in VALID_MAGICS:
            issues.append(f"invalid magic: {magic!r}")

        endian_tag = struct.unpack_from("<I", data, 40)[0]
        fmt = "<"
        if endian_tag == 0x78563412:
            fmt = ">"
        elif endian_tag != 0x12345678:
            issues.append(f"invalid endian_tag: {endian_tag:#x}")

        header_file_size = struct.unpack_from(f"{fmt}I", data, 32)[0]
        if header_file_size != len(data):
            issues.append(
                f"file_size mismatch: header says {header_file_size}, actual {len(data)}"
            )

        stored_checksum = struct.unpack_from(f"{fmt}I", data, 8)[0]
        computed_checksum = zlib.adler32(data[12:]) & 0xFFFFFFFF
        if stored_checksum != computed_checksum:
            issues.append(
                f"checksum mismatch: stored {stored_checksum:#010x}, "
                f"computed {computed_checksum:#010x}"
            )

        stored_sig = data[12:32]
        computed_sig = hashlib.sha1(data[32:]).digest()
        if stored_sig != computed_sig:
            issues.append("SHA-1 signature mismatch")

        try:
            dex = DexFile.parse(data)
        except Exception as e:
            issues.append(f"parse error: {e}")
            return VerifyResult(valid=len(issues) == 0, issues=issues, stats=stats)

        h = dex.header

        section_checks = [
            ("string_ids", h.string_ids_off, h.string_ids_size, 4),
            ("type_ids", h.type_ids_off, h.type_ids_size, 4),
            ("proto_ids", h.proto_ids_off, h.proto_ids_size, 12),
            ("field_ids", h.field_ids_off, h.field_ids_size, 8),
            ("method_ids", h.method_ids_off, h.method_ids_size, 8),
            ("class_defs", h.class_defs_off, h.class_defs_size, 32),
        ]
        for name, off, size, entry_size in section_checks:
            if size > 0:
                end = off + size * entry_size
                if off >= len(data) or end > len(data):
                    issues.append(
                        f"{name} section out of bounds: "
                        f"off={off:#x}, size={size}, end={end:#x}, "
                        f"file_size={len(data):#x}"
                    )

        stats["class_count"] = h.class_defs_size
        stats["method_count"] = h.method_ids_size
        stats["string_count"] = h.string_ids_size
        stats["type_count"] = h.type_ids_size
        stats["field_count"] = h.field_ids_size
        stats["proto_count"] = h.proto_ids_size

        all_methods = dex.all_methods
        methods_with_code = sum(
            1 for m in all_methods if m.code_item and m.code_item.insns_size > 0
        )
        nop_methods = sum(
            1 for m in all_methods
            if m.code_item and m.code_item.insns_size > 0 and m.code_item.is_nop_only
        )

        stats["encoded_methods"] = len(all_methods)
        stats["methods_with_code"] = methods_with_code
        stats["nop_only_methods"] = nop_methods
        if methods_with_code > 0:
            stats["code_coverage"] = (methods_with_code - nop_methods) / methods_with_code
        else:
            stats["code_coverage"] = 0.0

        if nop_methods > 0:
            issues.append(
                f"{nop_methods} method(s) contain only NOP instructions "
                f"(likely still-encrypted)"
            )

        return VerifyResult(valid=len(issues) == 0, issues=issues, stats=stats)
