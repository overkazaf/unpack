from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class QualityReport:
    dex_count: int = 0
    total_classes: int = 0
    total_methods: int = 0
    methods_with_code: int = 0
    nop_methods: int = 0
    empty_methods: int = 0
    code_coverage: float = 0.0
    score: float = 0.0
    per_dex: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "dex_count": self.dex_count,
            "total_classes": self.total_classes,
            "total_methods": self.total_methods,
            "methods_with_code": self.methods_with_code,
            "nop_methods": self.nop_methods,
            "empty_methods": self.empty_methods,
            "code_coverage": round(self.code_coverage, 4),
            "score": round(self.score, 4),
            "per_dex": self.per_dex,
        }


DEX_MAGIC = b"dex\n"
HEADER_SIZE = 0x70
NOP_INSN = 0x0000


class Reporter:
    def evaluate(self, output_dir: Path, scan_result=None) -> QualityReport:
        report = QualityReport()
        dex_files = sorted(output_dir.glob("*.dex"))
        report.dex_count = len(dex_files)

        for dex_path in dex_files:
            stats = self._analyze_dex(dex_path)
            report.per_dex.append({"file": dex_path.name, **stats})
            report.total_classes += stats["classes"]
            report.total_methods += stats["methods"]
            report.methods_with_code += stats["methods_with_code"]
            report.nop_methods += stats["nop_methods"]
            report.empty_methods += stats["empty_methods"]

        if report.total_methods > 0:
            report.code_coverage = report.methods_with_code / report.total_methods
            nop_ratio = report.nop_methods / report.total_methods
            report.score = report.code_coverage * (1.0 - nop_ratio)
        elif report.dex_count > 0:
            report.score = 0.5

        return report

    def _analyze_dex(self, dex_path: Path) -> dict:
        data = dex_path.read_bytes()
        stats = {
            "classes": 0, "methods": 0, "methods_with_code": 0,
            "nop_methods": 0, "empty_methods": 0, "file_size": len(data),
        }

        if len(data) < HEADER_SIZE or data[:4] != DEX_MAGIC:
            return stats

        class_defs_size = struct.unpack_from("<I", data, 0x60)[0]
        class_defs_off = struct.unpack_from("<I", data, 0x64)[0]
        stats["classes"] = class_defs_size

        for i in range(class_defs_size):
            off = class_defs_off + i * 32
            if off + 32 > len(data):
                break
            class_data_off = struct.unpack_from("<I", data, off + 24)[0]
            if class_data_off == 0:
                continue
            self._scan_class_methods(data, class_data_off, stats)

        return stats

    def _scan_class_methods(self, data: bytes, offset: int, stats: dict):
        pos = offset
        if pos >= len(data):
            return

        static_fields_size, pos = _uleb128(data, pos)
        instance_fields_size, pos = _uleb128(data, pos)
        direct_methods_size, pos = _uleb128(data, pos)
        virtual_methods_size, pos = _uleb128(data, pos)

        for _ in range(static_fields_size + instance_fields_size):
            if pos >= len(data):
                return
            _, pos = _uleb128(data, pos)
            _, pos = _uleb128(data, pos)

        method_count = direct_methods_size + virtual_methods_size
        for _ in range(method_count):
            if pos >= len(data):
                return
            _, pos = _uleb128(data, pos)
            _, pos = _uleb128(data, pos)
            code_off, pos = _uleb128(data, pos)

            stats["methods"] += 1
            if code_off == 0:
                stats["empty_methods"] += 1
                continue

            stats["methods_with_code"] += 1

            insns_off = code_off + 16
            if insns_off + 4 > len(data):
                continue
            insns_size = struct.unpack_from("<I", data, code_off + 12)[0]
            if insns_size == 0:
                stats["nop_methods"] += 1
                continue

            insn_bytes = insns_size * 2
            if insns_off + insn_bytes > len(data):
                continue

            all_nop = True
            for j in range(0, min(insn_bytes, 64), 2):
                word = struct.unpack_from("<H", data, insns_off + j)[0]
                if word != NOP_INSN:
                    all_nop = False
                    break
            if all_nop and insns_size > 1:
                stats["nop_methods"] += 1


def _uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, pos
