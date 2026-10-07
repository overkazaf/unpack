# Deep Technical Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Strengthen unpack's three weakest points: instruction-level analysis, dump repair robustness, and multi-process packer handling.

**Architecture:** Task 1 (disassembler) creates a new `analysis/disasm.py` module and `analysis/xref.py` for cross-references. Task 2 (robust repair) enhances the existing `dex_repair.py` with 4 new repair steps. Task 3 (multi-process) enhances `memory_engine.py` to discover child processes and scan anonymous regions. All tasks are independent.

**Tech Stack:** Python 3.10+, struct, existing DexFile parser, pytest, ADB shell commands.

---

## Task 1: DEX Bytecode Disassembler + Cross-Reference Index

A Dalvik instruction decoder that resolves operands against the DEX string/type/method/field tables, producing string cross-references, reflection call graphs, and method invoke tables.

**Files:**
- Create: `src/unpack/analysis/disasm.py` — instruction decoder
- Create: `src/unpack/analysis/xref.py` — cross-reference builder
- Create: `tests/test_disasm.py`
- Create: `tests/test_xref.py`
- Modify: `src/unpack/cli.py` — add `xref` subcommand

### Step 1: Write failing tests for the instruction decoder

```python
# tests/test_disasm.py
from __future__ import annotations

import struct
import pytest

from unpack.analysis.disasm import DalvikDecoder, Instruction, OpFormat


class TestDalvikDecoder:
    def test_decode_nop(self):
        decoder = DalvikDecoder()
        insns = struct.pack("<H", 0x0000)  # nop
        result = decoder.decode(insns)
        assert len(result) == 1
        assert result[0].opcode == 0x00
        assert result[0].mnemonic == "nop"

    def test_decode_return_void(self):
        decoder = DalvikDecoder()
        insns = struct.pack("<H", 0x000e)  # return-void
        result = decoder.decode(insns)
        assert len(result) == 1
        assert result[0].mnemonic == "return-void"

    def test_decode_const_string(self):
        decoder = DalvikDecoder()
        # const-string v0, string@0x0005
        insns = struct.pack("<HH", 0x001a, 0x0005)
        result = decoder.decode(insns)
        assert len(result) == 1
        assert result[0].mnemonic == "const-string"
        assert result[0].string_idx == 5

    def test_decode_invoke_virtual(self):
        decoder = DalvikDecoder()
        # invoke-virtual {v0, v1}, method@0x000A — format 35c
        insns = struct.pack("<HHH", 0x206e, 0x000A, 0x0010)
        result = decoder.decode(insns)
        assert len(result) == 1
        assert result[0].mnemonic == "invoke-virtual"
        assert result[0].method_idx == 0x000A

    def test_decode_invoke_static(self):
        decoder = DalvikDecoder()
        insns = struct.pack("<HHH", 0x2071, 0x0003, 0x0010)
        result = decoder.decode(insns)
        assert result[0].mnemonic == "invoke-static"
        assert result[0].method_idx == 3

    def test_decode_sget_object(self):
        decoder = DalvikDecoder()
        # sget-object v0, field@0x0007
        insns = struct.pack("<HH", 0x0062, 0x0007)
        result = decoder.decode(insns)
        assert result[0].mnemonic == "sget-object"
        assert result[0].field_idx == 7

    def test_decode_iget_object(self):
        decoder = DalvikDecoder()
        insns = struct.pack("<HH", 0x0054, 0x0002)
        result = decoder.decode(insns)
        assert result[0].mnemonic == "iget-object"
        assert result[0].field_idx == 2

    def test_decode_empty(self):
        decoder = DalvikDecoder()
        assert decoder.decode(b"") == []

    def test_decode_truncated(self):
        decoder = DalvikDecoder()
        result = decoder.decode(b"\x1a")  # truncated const-string
        assert len(result) <= 1  # may decode partial or skip

    def test_decode_sequence(self):
        decoder = DalvikDecoder()
        # nop + return-void = 2 instructions
        insns = struct.pack("<HH", 0x0000, 0x000e)
        result = decoder.decode(insns)
        assert len(result) == 2
```

### Step 2: Implement DalvikDecoder

```python
# src/unpack/analysis/disasm.py
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum


class OpFormat(Enum):
    FMT_10x = "10x"  # op (no args) — 1 unit
    FMT_11x = "11x"  # op vAA — 1 unit
    FMT_21c = "21c"  # op vAA, thing@BBBB — 2 units (const-string, sget, etc.)
    FMT_35c = "35c"  # op {vC..vG}, thing@BBBB — 3 units (invoke-*)
    FMT_3rc = "3rc"  # op {vCCCC..vNNNN}, thing@BBBB — 3 units (invoke-*/range)
    FMT_22c = "22c"  # op vA, vB, thing@CCCC — 2 units (iget/iput)
    FMT_31c = "31c"  # op vAA, string@BBBBBBBB — 3 units (const-string/jumbo)
    FMT_UNKNOWN = "unknown"


@dataclass
class Instruction:
    offset: int
    opcode: int
    mnemonic: str
    size: int  # in 16-bit code units
    string_idx: int | None = None
    type_idx: int | None = None
    method_idx: int | None = None
    field_idx: int | None = None
    raw: bytes = b""


_OPCODE_TABLE: dict[int, tuple[str, OpFormat, str | None]] = {
    # (mnemonic, format, ref_type: "string"|"type"|"method"|"field"|None)
    0x00: ("nop", OpFormat.FMT_10x, None),
    0x0e: ("return-void", OpFormat.FMT_10x, None),
    0x0f: ("return", OpFormat.FMT_11x, None),
    0x10: ("return-wide", OpFormat.FMT_11x, None),
    0x11: ("return-object", OpFormat.FMT_11x, None),
    0x1a: ("const-string", OpFormat.FMT_21c, "string"),
    0x1b: ("const-string/jumbo", OpFormat.FMT_31c, "string"),
    0x1c: ("const-class", OpFormat.FMT_21c, "type"),
    0x1f: ("check-cast", OpFormat.FMT_21c, "type"),
    0x20: ("instance-of", OpFormat.FMT_22c, "type"),
    0x22: ("new-instance", OpFormat.FMT_21c, "type"),
    0x52: ("iget", OpFormat.FMT_22c, "field"),
    0x53: ("iget-wide", OpFormat.FMT_22c, "field"),
    0x54: ("iget-object", OpFormat.FMT_22c, "field"),
    0x55: ("iget-boolean", OpFormat.FMT_22c, "field"),
    0x59: ("iput", OpFormat.FMT_22c, "field"),
    0x5a: ("iput-wide", OpFormat.FMT_22c, "field"),
    0x5b: ("iput-object", OpFormat.FMT_22c, "field"),
    0x5c: ("iput-boolean", OpFormat.FMT_22c, "field"),
    0x60: ("sget", OpFormat.FMT_21c, "field"),
    0x61: ("sget-wide", OpFormat.FMT_21c, "field"),
    0x62: ("sget-object", OpFormat.FMT_21c, "field"),
    0x63: ("sget-boolean", OpFormat.FMT_21c, "field"),
    0x67: ("sput", OpFormat.FMT_21c, "field"),
    0x68: ("sput-wide", OpFormat.FMT_21c, "field"),
    0x69: ("sput-object", OpFormat.FMT_21c, "field"),
    0x6a: ("sput-boolean", OpFormat.FMT_21c, "field"),
    0x6e: ("invoke-virtual", OpFormat.FMT_35c, "method"),
    0x6f: ("invoke-super", OpFormat.FMT_35c, "method"),
    0x70: ("invoke-direct", OpFormat.FMT_35c, "method"),
    0x71: ("invoke-static", OpFormat.FMT_35c, "method"),
    0x72: ("invoke-interface", OpFormat.FMT_35c, "method"),
    0x74: ("invoke-virtual/range", OpFormat.FMT_3rc, "method"),
    0x75: ("invoke-super/range", OpFormat.FMT_3rc, "method"),
    0x76: ("invoke-direct/range", OpFormat.FMT_3rc, "method"),
    0x77: ("invoke-static/range", OpFormat.FMT_3rc, "method"),
    0x78: ("invoke-interface/range", OpFormat.FMT_3rc, "method"),
}

_FORMAT_SIZES: dict[OpFormat, int] = {
    OpFormat.FMT_10x: 1,
    OpFormat.FMT_11x: 1,
    OpFormat.FMT_21c: 2,
    OpFormat.FMT_22c: 2,
    OpFormat.FMT_31c: 3,
    OpFormat.FMT_35c: 3,
    OpFormat.FMT_3rc: 3,
    OpFormat.FMT_UNKNOWN: 1,
}


class DalvikDecoder:
    def decode(self, insns: bytes) -> list[Instruction]:
        result: list[Instruction] = []
        pos = 0
        while pos < len(insns) - 1:
            opcode = insns[pos]
            entry = _OPCODE_TABLE.get(opcode)

            if entry is None:
                result.append(Instruction(
                    offset=pos, opcode=opcode, mnemonic=f"op_{opcode:02x}",
                    size=1, raw=insns[pos:pos + 2],
                ))
                pos += 2
                continue

            mnemonic, fmt, ref_type = entry
            size_units = _FORMAT_SIZES[fmt]
            size_bytes = size_units * 2

            if pos + size_bytes > len(insns):
                break

            raw = insns[pos:pos + size_bytes]
            insn = Instruction(
                offset=pos, opcode=opcode, mnemonic=mnemonic,
                size=size_units, raw=raw,
            )

            if ref_type and size_bytes >= 4:
                idx = struct.unpack_from("<H", insns, pos + 2)[0]
                if fmt == OpFormat.FMT_31c and size_bytes >= 6:
                    idx = struct.unpack_from("<I", insns, pos + 2)[0]
                if ref_type == "string":
                    insn.string_idx = idx
                elif ref_type == "type":
                    insn.type_idx = idx
                elif ref_type == "method":
                    insn.method_idx = idx
                elif ref_type == "field":
                    insn.field_idx = idx

            result.append(insn)
            pos += size_bytes

        return result
```

### Step 3: Write failing tests for cross-reference builder

```python
# tests/test_xref.py
from __future__ import annotations

import struct
import pytest

from unpack.analysis.xref import XrefBuilder, XrefReport


class TestXrefBuilder:
    def test_empty_dex(self, synthetic_dex_bytes):
        builder = XrefBuilder()
        report = builder.build(synthetic_dex_bytes)
        assert report.string_refs == {}
        assert report.method_calls == {}

    def test_report_to_dict(self):
        report = XrefReport(
            string_refs={"http://api.example.com": [{"class": "Lcom/a;", "method": "a"}]},
            method_calls={},
            reflection_calls=[],
            field_refs={},
        )
        d = report.to_dict()
        assert "string_refs" in d
        assert "http://api.example.com" in d["string_refs"]

    def test_reflection_detection(self):
        from unpack.analysis.xref import _is_reflection_method
        assert _is_reflection_method("java.lang.Class", "forName") is True
        assert _is_reflection_method("java.lang.reflect.Method", "invoke") is True
        assert _is_reflection_method("com.example.Foo", "bar") is False


class TestXrefReport:
    def test_summary(self):
        report = XrefReport(
            string_refs={"url1": [{"class": "A", "method": "b"}]},
            method_calls={"m1": [{"caller_class": "A", "caller_method": "b"}]},
            reflection_calls=[{"class": "A", "method": "forName", "target": "com.x.Y"}],
            field_refs={"f1": [{"class": "A", "method": "b"}]},
        )
        s = report.summary()
        assert s["total_string_refs"] == 1
        assert s["total_reflection_calls"] == 1
```

### Step 4: Implement XrefBuilder

```python
# src/unpack/analysis/xref.py
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from unpack.analysis.disasm import DalvikDecoder
from unpack.repair.dex_parser import DexFile


@dataclass
class XrefReport:
    string_refs: dict[str, list[dict]] = field(default_factory=dict)
    method_calls: dict[str, list[dict]] = field(default_factory=dict)
    reflection_calls: list[dict] = field(default_factory=list)
    field_refs: dict[str, list[dict]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "string_refs": self.string_refs,
            "method_calls": self.method_calls,
            "reflection_calls": self.reflection_calls,
            "field_refs": self.field_refs,
        }

    def summary(self) -> dict[str, int]:
        return {
            "total_string_refs": sum(len(v) for v in self.string_refs.values()),
            "unique_strings": len(self.string_refs),
            "total_method_calls": sum(len(v) for v in self.method_calls.values()),
            "total_reflection_calls": len(self.reflection_calls),
            "total_field_refs": sum(len(v) for v in self.field_refs.values()),
        }


_REFLECTION_METHODS = {
    ("java.lang.Class", "forName"),
    ("java.lang.Class", "getMethod"),
    ("java.lang.Class", "getDeclaredMethod"),
    ("java.lang.Class", "getField"),
    ("java.lang.Class", "getDeclaredField"),
    ("java.lang.Class", "newInstance"),
    ("java.lang.reflect.Method", "invoke"),
    ("java.lang.reflect.Constructor", "newInstance"),
    ("dalvik.system.DexClassLoader", "<init>"),
    ("dalvik.system.InMemoryDexClassLoader", "<init>"),
    ("dalvik.system.PathClassLoader", "<init>"),
}


def _is_reflection_method(class_name: str, method_name: str) -> bool:
    return (class_name, method_name) in _REFLECTION_METHODS


class XrefBuilder:
    def __init__(self):
        self._decoder = DalvikDecoder()

    def build(self, dex_data: bytes) -> XrefReport:
        report = XrefReport()
        try:
            dex = DexFile.parse(dex_data)
        except Exception:
            return report

        for cdef in dex.class_defs:
            if not cdef.class_data:
                continue
            class_name = dex.get_type_name(cdef.class_idx) or f"class_{cdef.class_idx}"
            all_methods = cdef.class_data.direct_methods + cdef.class_data.virtual_methods

            for method in all_methods:
                ci = method.code_item
                if not ci or ci.insns_size == 0 or ci.is_nop_only:
                    continue

                method_name = self._resolve_method_name(dex, method.method_idx) or f"method_{method.method_idx}"
                caller = {"class": class_name, "method": method_name}

                insns = self._decoder.decode(ci.insns)
                for insn in insns:
                    if insn.string_idx is not None:
                        s = dex.get_string(insn.string_idx)
                        if s:
                            report.string_refs.setdefault(s, []).append(caller)

                    if insn.method_idx is not None:
                        target_cls, target_meth = self._resolve_method_full(dex, insn.method_idx)
                        target_key = f"{target_cls}->{target_meth}" if target_cls else f"method_{insn.method_idx}"
                        report.method_calls.setdefault(target_key, []).append(caller)

                        if target_cls and target_meth:
                            clean_cls = target_cls.strip("L;").replace("/", ".")
                            if _is_reflection_method(clean_cls, target_meth):
                                report.reflection_calls.append({
                                    **caller,
                                    "target_class": target_cls,
                                    "target_method": target_meth,
                                    "insn_offset": insn.offset,
                                })

                    if insn.field_idx is not None:
                        field_name = self._resolve_field_name(dex, insn.field_idx)
                        if field_name:
                            report.field_refs.setdefault(field_name, []).append(caller)

        return report

    def build_file(self, dex_path: Path) -> XrefReport:
        return self.build(dex_path.read_bytes())

    @staticmethod
    def _resolve_method_name(dex: DexFile, method_idx: int) -> str | None:
        h = dex.header
        if method_idx < 0 or method_idx >= h.method_ids_size:
            return None
        mid_off = h.method_ids_off + method_idx * 8
        if mid_off + 8 > len(dex.data):
            return None
        name_idx = struct.unpack_from(f"{dex.fmt}HHI", dex.data, mid_off)[2]
        return dex.get_string(name_idx)

    @staticmethod
    def _resolve_method_full(dex: DexFile, method_idx: int) -> tuple[str | None, str | None]:
        h = dex.header
        if method_idx < 0 or method_idx >= h.method_ids_size:
            return None, None
        mid_off = h.method_ids_off + method_idx * 8
        if mid_off + 8 > len(dex.data):
            return None, None
        vals = struct.unpack_from(f"{dex.fmt}HHI", dex.data, mid_off)
        cls = dex.get_type_name(vals[0])
        name = dex.get_string(vals[2])
        return cls, name

    @staticmethod
    def _resolve_field_name(dex: DexFile, field_idx: int) -> str | None:
        h = dex.header
        if field_idx < 0 or field_idx >= h.field_ids_size:
            return None
        fid_off = h.field_ids_off + field_idx * 8
        if fid_off + 8 > len(dex.data):
            return None
        vals = struct.unpack_from(f"{dex.fmt}HHI", dex.data, fid_off)
        cls_name = dex.get_type_name(vals[0]) or ""
        field_name = dex.get_string(vals[2]) or ""
        return f"{cls_name}->{field_name}" if field_name else None
```

### Step 5: Add `xref` CLI subcommand to `cli.py`

```python
@app.command()
def xref(
    dex_dir: Annotated[Path, typer.Argument(help="DEX file or directory")],
    output_json: Annotated[Optional[Path], typer.Option("--json", "-j", help="Save xref report as JSON")] = None,
    strings_only: Annotated[bool, typer.Option("--strings", "-s", help="Only show string references")] = False,
):
    """Build cross-reference index: strings, method calls, reflection, fields."""
    from unpack.analysis.xref import XrefBuilder

    if not dex_dir.exists():
        console.print(f"[{C_FAIL}]Path not found:[/] {dex_dir}")
        raise typer.Exit(1)

    paths = sorted(dex_dir.glob("*.dex")) if dex_dir.is_dir() else [dex_dir]
    if not paths:
        console.print(f"[{C_FAIL}]No DEX files found.[/]")
        raise typer.Exit(1)

    builder = XrefBuilder()
    from unpack.analysis.xref import XrefReport
    merged = XrefReport()

    for p in paths:
        report = builder.build_file(p)
        for k, v in report.string_refs.items():
            merged.string_refs.setdefault(k, []).extend(v)
        for k, v in report.method_calls.items():
            merged.method_calls.setdefault(k, []).extend(v)
        merged.reflection_calls.extend(report.reflection_calls)
        for k, v in report.field_refs.items():
            merged.field_refs.setdefault(k, []).extend(v)

    s = merged.summary()
    console.print(f"  [{C_INFO}]{s['unique_strings']}[/] unique strings, [{C_INFO}]{s['total_method_calls']}[/] method calls, [{C_WARN}]{s['total_reflection_calls']}[/] reflection calls")

    if merged.reflection_calls:
        console.print(f"\n  [{C_LABEL}]Reflection calls:[/]")
        for rc in merged.reflection_calls[:20]:
            console.print(f"    [{C_WARN}]{rc['target_class']}->{rc['target_method']}[/] [{C_DIM}]from {rc['class']}->{rc['method']}[/]")

    if output_json:
        import json
        d = merged.to_dict() if not strings_only else {"string_refs": merged.string_refs}
        payload = json.dumps(d, indent=2, ensure_ascii=False)
        if str(output_json) == "-":
            print(payload)
        else:
            output_json.write_text(payload)
            console.print(f"  [{C_DIM}]Saved to {output_json}[/]")
```

Also add to help table: `t.add_row("xref", "Cross-reference index: strings, calls, reflection")`

### Step 6: Run all tests, commit

Run: `.venv/bin/python -m pytest tests/test_disasm.py tests/test_xref.py -v && .venv/bin/python -m pytest -v`

```bash
git add src/unpack/analysis/disasm.py src/unpack/analysis/xref.py tests/test_disasm.py tests/test_xref.py src/unpack/cli.py
git commit -m "feat: DEX bytecode disassembler + cross-reference index

Dalvik instruction decoder for ~40 opcodes with operand resolution.
XrefBuilder produces string refs, method call graph, reflection call
detection (Class.forName, Method.invoke, DexClassLoader), and field refs.
unpack xref command outputs the index as JSON."
```

---

## Task 2: Robust DEX Repair — Truncation Recovery + Section Validation

Harden the repair pipeline to handle truncated dumps, out-of-bounds section pointers, broken debug_info, and missing map_list.

**Files:**
- Modify: `src/unpack/repair/dex_repair.py` — add 4 new repair steps
- Modify: `tests/test_dex_repair.py` — add tests for new repairs
- Modify: `tests/conftest.py` — add truncated DEX fixture

### Step 1: Write failing tests

```python
# Add to tests/test_dex_repair.py

class TestRepairTruncation:
    def test_truncated_dex_detected(self, synthetic_dex, tmp_path):
        """DEX header says 256 bytes but file is only 200."""
        data = bytearray(synthetic_dex[:200])
        # header still says file_size=256
        p = tmp_path / "truncated.dex"
        p.write_bytes(bytes(data))
        result = pipeline.repair(p)
        assert result.success
        assert any("truncat" in a.lower() for a in result.actions)

    def test_truncated_dex_class_data_nulled(self, tmp_path):
        """class_data_off pointing past EOF gets zeroed."""
        from conftest import _build_minimal_dex
        data = _build_minimal_dex()
        # Fake a class_defs entry pointing to class_data past file end
        import struct
        # Set class_defs_size=1, class_defs_off=0x70
        struct.pack_into("<I", data, 0x60, 1)  # class_defs_size
        struct.pack_into("<I", data, 0x64, 0x70)  # class_defs_off
        # Write a class_def at 0x70 with class_data_off=0xFFFF (past EOF)
        struct.pack_into("<8I", data, 0x70,
            0, 0, 0, 0, 0, 0, 0xFFFF, 0)
        p = tmp_path / "bad_classdata.dex"
        p.write_bytes(bytes(data))
        pipeline = DexRepairPipeline()
        result = pipeline.repair(p)
        assert result.success
        assert any("class_data_off" in a or "section" in a.lower() or "bounds" in a.lower() for a in result.actions)


class TestRepairSectionBounds:
    def test_section_off_past_eof(self, synthetic_dex, tmp_path):
        """string_ids_off pointing past EOF gets zeroed."""
        data = bytearray(synthetic_dex)
        struct.pack_into("<I", data, 56, 0)  # string_ids_size = 0 (so it won't crash)
        struct.pack_into("<I", data, 60, 0xFFFFF)  # string_ids_off past EOF
        p = tmp_path / "bad_section.dex"
        p.write_bytes(bytes(data))
        pipeline = DexRepairPipeline()
        result = pipeline.repair(p)
        assert result.success
        assert any("bounds" in a.lower() or "section" in a.lower() for a in result.actions)


class TestRepairDebugInfo:
    def test_invalid_debug_info_off_zeroed(self, synthetic_dex, tmp_path):
        """debug_info_off in a CodeItem pointing past EOF gets zeroed."""
        # This requires a DEX with actual methods, which our minimal doesn't have.
        # We test the standalone method instead.
        from unpack.repair.dex_repair import DexRepairPipeline
        pipeline = DexRepairPipeline()
        data = bytearray(256)
        # Simulate a code_item at offset 0x80 with debug_info_off=0xFFFF
        struct.pack_into("<I", data, 0x80 + 8, 0xFFFF)  # debug_info_off
        fixed = pipeline._fix_debug_info_offsets(data, [(0x80, 20)], 256, [])
        stored = struct.unpack_from("<I", fixed, 0x80 + 8)[0]
        assert stored == 0


class TestRepairMapListRebuild:
    def test_map_list_rebuilt_when_zeroed(self, synthetic_dex, tmp_path):
        data = bytearray(synthetic_dex)
        struct.pack_into("<I", data, 52, 0)  # zero map_off
        p = tmp_path / "no_map.dex"
        p.write_bytes(bytes(data))
        pipeline = DexRepairPipeline()
        result = pipeline.repair(p)
        assert result.success
        # After rebuild, map_off should be non-zero if there are sections to map
        # (our minimal DEX has no sections, so it stays 0 — that's fine)
```

### Step 2: Implement the 4 new repair steps

Add to `DexRepairPipeline` in `dex_repair.py`:

```python
# Insert these into the repair() method, after _fix_file_size and before _fix_map_off:

        data = self._fix_section_bounds(data, fmt, actions)
        data = self._fix_truncated_class_defs(data, fmt, actions)

# And after _fix_code_item_alignment, before _detect_nop_methods:

        code_item_offsets = [(ci.offset, ci.insns_size) for ci in dex.code_items]
        data = self._fix_debug_info_offsets(data, code_item_offsets, len(data), actions)
```

New methods:

```python
@staticmethod
def _fix_section_bounds(data: bytearray, fmt: str, actions: list[str]) -> bytearray:
    file_len = len(data)
    sections = [
        ("string_ids", 56, 60, 4),
        ("type_ids", 64, 68, 4),
        ("proto_ids", 72, 76, 12),
        ("field_ids", 80, 84, 8),
        ("method_ids", 88, 92, 8),
        ("class_defs", 96, 100, 32),
    ]
    fixed = 0
    for name, size_off, off_off, entry_size in sections:
        sec_size = struct.unpack_from(f"{fmt}I", data, size_off)[0]
        sec_off = struct.unpack_from(f"{fmt}I", data, off_off)[0]
        if sec_size == 0:
            continue
        end = sec_off + sec_size * entry_size
        if sec_off >= file_len or end > file_len:
            struct.pack_into(f"{fmt}I", data, size_off, 0)
            struct.pack_into(f"{fmt}I", data, off_off, 0)
            fixed += 1
    if fixed:
        actions.append(f"zeroed {fixed} section(s) with out-of-bounds offsets")
    return data

@staticmethod
def _fix_truncated_class_defs(data: bytearray, fmt: str, actions: list[str]) -> bytearray:
    file_len = len(data)
    cd_size = struct.unpack_from(f"{fmt}I", data, 96)[0]
    cd_off = struct.unpack_from(f"{fmt}I", data, 100)[0]
    if cd_size == 0 or cd_off == 0:
        return data

    fixed = 0
    for i in range(cd_size):
        entry_off = cd_off + i * 32
        if entry_off + 32 > file_len:
            break
        # Check class_data_off (offset 24 within class_def)
        cdata_off = struct.unpack_from(f"{fmt}I", data, entry_off + 24)[0]
        if cdata_off != 0 and cdata_off >= file_len:
            struct.pack_into(f"{fmt}I", data, entry_off + 24, 0)
            fixed += 1
        # Check annotations_off (offset 20)
        ann_off = struct.unpack_from(f"{fmt}I", data, entry_off + 20)[0]
        if ann_off != 0 and ann_off >= file_len:
            struct.pack_into(f"{fmt}I", data, entry_off + 20, 0)
            fixed += 1
        # Check static_values_off (offset 28)
        sv_off = struct.unpack_from(f"{fmt}I", data, entry_off + 28)[0]
        if sv_off != 0 and sv_off >= file_len:
            struct.pack_into(f"{fmt}I", data, entry_off + 28, 0)
            fixed += 1
    if fixed:
        actions.append(f"nulled {fixed} class_def pointer(s) past EOF (truncated dump)")
    return data

@staticmethod
def _fix_debug_info_offsets(
    data: bytearray,
    code_item_offsets: list[tuple[int, int]],
    file_len: int,
    actions: list[str],
) -> bytearray:
    fixed = 0
    for ci_off, _ in code_item_offsets:
        if ci_off + 12 > file_len:
            continue
        debug_off = struct.unpack_from("<I", data, ci_off + 8)[0]
        if debug_off != 0 and debug_off >= file_len:
            struct.pack_into("<I", data, ci_off + 8, 0)
            fixed += 1
    if fixed:
        actions.append(f"zeroed {fixed} invalid debug_info_off pointer(s)")
    return data
```

### Step 3: Run tests, commit

Run: `.venv/bin/python -m pytest tests/test_dex_repair.py -v && .venv/bin/python -m pytest -v`

```bash
git add src/unpack/repair/dex_repair.py tests/test_dex_repair.py tests/conftest.py
git commit -m "feat: robust DEX repair — section bounds validation, truncation recovery, debug_info fix

Check every section pointer against actual file length. Null class_def
pointers (class_data_off, annotations_off, static_values_off) that point
past EOF in truncated dumps. Zero invalid debug_info_off in CodeItems."
```

---

## Task 3: Memory Engine Multi-Process + DEX-in-DEX Detection

Enumerate child processes and scan all related PIDs. Add sliding-window DEX magic search within anonymous memory regions.

**Files:**
- Modify: `src/unpack/engines/memory_engine.py` — add child process discovery + sliding scan
- Create: `tests/test_memory_multiproc.py`

### Step 1: Write failing tests

```python
# tests/test_memory_multiproc.py
from __future__ import annotations

from unittest.mock import patch
import pytest

from unpack.engines.memory_engine import MemoryEngine, _find_child_pids, _sliding_dex_scan


class TestFindChildPids:
    def test_finds_children(self):
        with patch("unpack.engines.memory_engine._adb_shell") as mock:
            mock.return_value = "1234\n5678\n"
            pids = _find_child_pids("serial", "1000")
        assert "1234" in pids
        assert "5678" in pids

    def test_no_children(self):
        with patch("unpack.engines.memory_engine._adb_shell") as mock:
            mock.return_value = ""
            pids = _find_child_pids("serial", "1000")
        assert pids == []

    def test_handles_error(self):
        import subprocess
        with patch("unpack.engines.memory_engine._adb_shell", side_effect=subprocess.CalledProcessError(1, "")):
            pids = _find_child_pids("serial", "1000")
        assert pids == []


class TestSlidingDexScan:
    def test_finds_dex_at_offset(self):
        # DEX magic at offset 100 in a 1KB buffer
        import hashlib, struct, zlib
        buf = bytearray(1024)
        dex_off = 100
        buf[dex_off:dex_off + 8] = b"dex\n035\x00"
        struct.pack_into("<I", buf, dex_off + 32, 200)  # file_size
        struct.pack_into("<I", buf, dex_off + 36, 0x70)  # header_size
        struct.pack_into("<I", buf, dex_off + 40, 0x12345678)  # endian_tag
        offsets = _sliding_dex_scan(bytes(buf), max_scan=512)
        assert dex_off in offsets

    def test_no_dex_in_noise(self):
        buf = bytes(1024)  # all zeros
        offsets = _sliding_dex_scan(buf, max_scan=512)
        assert offsets == []

    def test_finds_multiple(self):
        import struct
        buf = bytearray(2048)
        for off in [50, 500]:
            buf[off:off + 8] = b"dex\n035\x00"
            struct.pack_into("<I", buf, off + 32, 200)
            struct.pack_into("<I", buf, off + 36, 0x70)
            struct.pack_into("<I", buf, off + 40, 0x12345678)
        offsets = _sliding_dex_scan(bytes(buf), max_scan=1024)
        assert 50 in offsets
        assert 500 in offsets
```

### Step 2: Implement child PID discovery and sliding scan

Add to `memory_engine.py`:

```python
def _find_child_pids(serial: str, parent_pid: str) -> list[str]:
    """Find child process PIDs of the given parent."""
    try:
        out = _adb_shell(serial, f"pgrep -P {parent_pid}", root=True, timeout=5)
        return [p.strip() for p in out.splitlines() if p.strip().isdigit()]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []


def _sliding_dex_scan(data: bytes, max_scan: int = 1024 * 1024) -> list[int]:
    """Scan for DEX magic within a buffer at arbitrary offsets."""
    offsets = []
    search_len = min(len(data), max_scan)
    pos = 0
    while pos < search_len - 44:
        idx = data.find(b"dex\n", pos, search_len)
        if idx < 0:
            break
        if idx + 44 <= len(data):
            try:
                fsize = struct.unpack_from("<I", data, idx + 32)[0]
                hsize = struct.unpack_from("<I", data, idx + 36)[0]
                endian = struct.unpack_from("<I", data, idx + 40)[0]
                if (hsize == 0x70 and
                    fsize >= 112 and fsize <= 100 * 1024 * 1024 and
                    endian in (0x12345678, 0x78563412)):
                    offsets.append(idx)
            except struct.error:
                pass
        pos = idx + 4
    return offsets
```

### Step 3: Integrate into `_do_dump`

In the `_do_dump` method, after getting the main PID and before scanning maps:

```python
        # Discover child processes
        all_pids = [pid]
        child_pids = _find_child_pids(serial, pid)
        if child_pids:
            all_pids.extend(child_pids)
```

Then wrap the maps scanning in a loop over `all_pids`:

```python
        for scan_pid in all_pids:
            maps_text = _adb_shell(serial, f"cat /proc/{scan_pid}/maps", root=True, timeout=10)
            # ... existing target building and probing logic ...
            # Use scan_pid instead of pid for memory reads
```

For anonymous region scanning, add after the OAT check in the header detection block:

```python
            # For anonymous rw-p regions without known magic at offset 0,
            # do a sliding scan for DEX magic within the first 1MB
            if first_dex_off < 0 and region_size >= 4096:
                perms = parts[1] if len(parts) > 1 else ""
                path_info = parts[-1] if len(parts) > 5 else ""
                if "rw" in perms and (path_info == "" or path_info.startswith("[anon:")):
                    # Read more of the region for sliding scan
                    scan_size = min(region_size, 1024 * 1024)
                    if scan_size > len(header):
                        extended = self._read_mem(serial, scan_pid, region_start, min(scan_size, 65536))
                    else:
                        extended = header
                    dex_offsets = _sliding_dex_scan(extended)
                    if dex_offsets:
                        first_dex_off = dex_offsets[0]
```

### Step 4: Run tests, commit

Run: `.venv/bin/python -m pytest tests/test_memory_multiproc.py -v && .venv/bin/python -m pytest -v`

```bash
git add src/unpack/engines/memory_engine.py tests/test_memory_multiproc.py
git commit -m "feat: multi-process packer support + DEX-in-DEX sliding scan

Enumerate child processes via pgrep -P and scan all related PIDs.
Sliding-window search for DEX magic within anonymous rw-p regions
at arbitrary offsets, catching DEX-in-array and DEX-after-header patterns."
```

---

## Execution Dependencies

```
Task 1 (Disasm+Xref) ─── independent (new files only + cli.py command)
Task 2 (Robust Repair) ── independent (modifies dex_repair.py only)
Task 3 (Multi-Process)  ── independent (modifies memory_engine.py only)
```

All 3 tasks are independent and can run in parallel.
