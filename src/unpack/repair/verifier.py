from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from unpack.repair.dex_parser import DexFile, VALID_MAGICS, HEADER_SIZE


@dataclass
class VerifyCheck:
    name: str
    status: str  # "pass" | "warn" | "fail"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass
class VerifyResult:
    valid: bool
    issues: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    health_score: float = 100.0
    checks: list[VerifyCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "issues": self.issues,
            "stats": self.stats,
            "health_score": round(self.health_score, 2),
            "checks": [c.to_dict() for c in self.checks],
        }


class DexVerifier:
    def verify(self, dex_path: Path) -> VerifyResult:
        data = dex_path.read_bytes()
        return self.verify_bytes(data)

    def verify_bytes(self, data: bytes) -> VerifyResult:
        issues: list[str] = []
        checks: list[VerifyCheck] = []
        stats: dict[str, Any] = {"file_size": len(data)}

        if len(data) < HEADER_SIZE:
            msg = f"file too small: {len(data)} < {HEADER_SIZE}"
            issues.append(msg)
            checks.append(VerifyCheck(name="header_size", status="fail", detail=msg))
            return VerifyResult(valid=False, issues=issues, stats=stats, health_score=0.0, checks=checks)

        magic = data[:8]
        if magic not in VALID_MAGICS:
            msg = f"invalid magic: {magic!r}"
            issues.append(msg)
            checks.append(VerifyCheck(name="magic", status="fail", detail=msg))
        else:
            version = magic[4:7].decode("ascii", errors="replace")
            stats["dex_version"] = version
            checks.append(VerifyCheck(name="magic", status="pass", detail=f"DEX v{version}"))

        if magic[:4] == b"cdex":
            msg = "file is CompactDex (CDEX) — run 'unpack repair' to convert to standard DEX"
            issues.append(msg)
            checks.append(VerifyCheck(name="cdex", status="fail", detail=msg))

        endian_tag = struct.unpack_from("<I", data, 40)[0]
        fmt = "<"
        if endian_tag == 0x78563412:
            fmt = ">"
            checks.append(VerifyCheck(name="endian_tag", status="pass", detail="big-endian"))
        elif endian_tag == 0x12345678:
            checks.append(VerifyCheck(name="endian_tag", status="pass", detail="little-endian"))
        else:
            msg = f"invalid endian_tag: {endian_tag:#x}"
            issues.append(msg)
            checks.append(VerifyCheck(name="endian_tag", status="fail", detail=msg))

        header_file_size = struct.unpack_from(f"{fmt}I", data, 32)[0]
        if header_file_size != len(data):
            msg = f"file_size mismatch: header says {header_file_size}, actual {len(data)}"
            issues.append(msg)
            checks.append(VerifyCheck(name="file_size", status="fail", detail=msg))
        else:
            checks.append(VerifyCheck(name="file_size", status="pass", detail=f"{len(data)} bytes"))

        stored_checksum = struct.unpack_from(f"{fmt}I", data, 8)[0]
        computed_checksum = zlib.adler32(data[12:]) & 0xFFFFFFFF
        if stored_checksum != computed_checksum:
            msg = (
                f"checksum mismatch: stored {stored_checksum:#010x}, "
                f"computed {computed_checksum:#010x}"
            )
            issues.append(msg)
            checks.append(VerifyCheck(name="checksum", status="fail", detail=msg))
        else:
            checks.append(VerifyCheck(name="checksum", status="pass", detail=f"{stored_checksum:#010x}"))

        stored_sig = data[12:32]
        computed_sig = hashlib.sha1(data[32:]).digest()
        if stored_sig != computed_sig:
            msg = "SHA-1 signature mismatch"
            issues.append(msg)
            checks.append(VerifyCheck(name="signature", status="fail", detail=msg))
        else:
            checks.append(VerifyCheck(name="signature", status="pass", detail=stored_sig.hex()[:16] + "..."))

        try:
            dex = DexFile.parse(data)
        except Exception as e:
            msg = f"parse error: {e}"
            issues.append(msg)
            checks.append(VerifyCheck(name="parse", status="fail", detail=msg))
            return VerifyResult(
                valid=False,
                issues=issues,
                stats=stats,
                health_score=self._compute_health(issues, 0.0),
                checks=checks,
            )

        h = dex.header

        # Map offset validation (only fail if non-zero and out-of-bounds/corrupt)
        if h.map_off != 0:
            if h.map_off >= len(data) or h.map_off + 4 > len(data):
                msg = f"map_off out of bounds: {h.map_off:#x} >= {len(data):#x}"
                issues.append(msg)
                checks.append(VerifyCheck(name="map_list", status="fail", detail=msg))
            else:
                map_size = struct.unpack_from(f"{fmt}I", data, h.map_off)[0]
                if map_size > 50 or h.map_off + 4 + map_size * 12 > len(data):
                    msg = f"corrupt map_list at {h.map_off:#x} (entries={map_size})"
                    issues.append(msg)
                    checks.append(VerifyCheck(name="map_list", status="fail", detail=msg))
                else:
                    checks.append(VerifyCheck(name="map_list", status="pass", detail=f"{map_size} entries"))

        section_checks = [
            ("string_ids", h.string_ids_off, h.string_ids_size, 4),
            ("type_ids", h.type_ids_off, h.type_ids_size, 4),
            ("proto_ids", h.proto_ids_off, h.proto_ids_size, 12),
            ("field_ids", h.field_ids_off, h.field_ids_size, 8),
            ("method_ids", h.method_ids_off, h.method_ids_size, 8),
            ("class_defs", h.class_defs_off, h.class_defs_size, 32),
        ]
        section_ok = True
        for name, off, size, entry_size in section_checks:
            if size > 0:
                end = off + size * entry_size
                if off >= len(data) or end > len(data):
                    section_ok = False
                    issues.append(
                        f"{name} section out of bounds: "
                        f"off={off:#x}, size={size}, end={end:#x}, "
                        f"file_size={len(data):#x}"
                    )
        checks.append(
            VerifyCheck(
                name="section_bounds",
                status="pass" if section_ok else "fail",
                detail="All DEX section tables within file bounds" if section_ok else "One or more section tables exceed EOF",
            )
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
        abstract_or_native = sum(1 for m in all_methods if m.code_off == 0)
        misaligned_ci = sum(1 for ci in dex.code_items if ci.offset % 4 != 0)

        stats["encoded_methods"] = len(all_methods)
        stats["methods_with_code"] = methods_with_code
        stats["abstract_or_native_methods"] = abstract_or_native
        stats["nop_only_methods"] = nop_methods
        stats["misaligned_code_items"] = misaligned_ci
        if methods_with_code > 0:
            stats["code_coverage"] = (methods_with_code - nop_methods) / methods_with_code
        else:
            stats["code_coverage"] = 0.0

        if nop_methods > 0:
            msg = (
                f"{nop_methods} method(s) contain only NOP instructions "
                f"(likely still-encrypted)"
            )
            issues.append(msg)
            checks.append(VerifyCheck(name="code_integrity", status="warn", detail=msg))
        else:
            checks.append(
                VerifyCheck(
                    name="code_integrity",
                    status="pass",
                    detail=f"{methods_with_code} concrete method(s), 0 NOP-only",
                )
            )

        if misaligned_ci > 0:
            checks.append(
                VerifyCheck(
                    name="code_alignment",
                    status="warn",
                    detail=f"{misaligned_ci} CodeItem(s) not 4-byte aligned",
                )
            )

        health_score = self._compute_health(
            issues,
            stats["code_coverage"] if methods_with_code > 0 else 1.0,
        )
        return VerifyResult(
            valid=len(issues) == 0,
            issues=issues,
            stats=stats,
            health_score=health_score,
            checks=checks,
        )

    @staticmethod
    def _compute_health(issues: list[str], code_coverage: float) -> float:
        score = 100.0
        for issue in issues:
            low = issue.lower()
            if "too small" in low or "parse error" in low or "magic" in low:
                score -= 40.0
            elif "out of bounds" in low or "corrupt" in low:
                score -= 25.0
            elif "file_size" in low or "checksum" in low or "signature" in low or "cdex" in low:
                score -= 15.0
            elif "nop" in low:
                score -= max(5.0, (1.0 - code_coverage) * 40.0)
            else:
                score -= 10.0
        return max(0.0, min(100.0, round(score, 2)))
