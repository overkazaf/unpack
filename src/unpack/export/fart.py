from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from unpack.repair.dex_parser import DexFile


@dataclass
class FartBinEntry:
    method_idx: int
    code_off: int
    insns_size: int
    insns: bytes

    def to_bytes(self) -> bytes:
        header = struct.pack("<III", self.method_idx, self.code_off, self.insns_size)
        return header + self.insns

    @staticmethod
    def from_bytes(data: bytes) -> FartBinEntry:
        idx, off, sz = struct.unpack_from("<III", data, 0)
        insns = data[12:12 + sz * 2]
        return FartBinEntry(method_idx=idx, code_off=off, insns_size=sz, insns=insns)


@dataclass
class FartExportResult:
    bin_path: Path
    txt_path: Path
    method_count: int = 0


class FartExporter:
    def export(self, dex_path: Path, output_dir: Path) -> FartExportResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        bin_path = output_dir / f"{dex_path.stem}_fart.bin"
        txt_path = output_dir / f"{dex_path.stem}_fart.txt"

        dex = DexFile.parse(dex_path.read_bytes())
        entries: list[FartBinEntry] = []
        txt_lines: list[str] = []

        for cdef in dex.class_defs:
            if not cdef.class_data:
                continue
            class_name = dex.get_type_name(cdef.class_idx) or f"class_{cdef.class_idx}"
            all_methods = cdef.class_data.direct_methods + cdef.class_data.virtual_methods
            for method in all_methods:
                ci = method.code_item
                if not ci or ci.insns_size == 0:
                    continue
                if ci.is_nop_only:
                    continue
                entry = FartBinEntry(
                    method_idx=method.method_idx,
                    code_off=method.code_off,
                    insns_size=ci.insns_size,
                    insns=ci.insns,
                )
                entries.append(entry)

                method_name = dex.get_method_name(method.method_idx) or f"method_{method.method_idx}"
                txt_lines.append(
                    f"{class_name}->{method_name} "
                    f"code_off=0x{method.code_off:x} "
                    f"insns_size={ci.insns_size} "
                    f"registers={ci.registers_size}"
                )

        bin_path.write_bytes(b"".join(e.to_bytes() for e in entries))
        txt_path.write_text("\n".join(txt_lines) + ("\n" if txt_lines else ""))

        return FartExportResult(
            bin_path=bin_path,
            txt_path=txt_path,
            method_count=len(entries),
        )
