"""VMP (virtualize-protect) method annotation.

Detects short "dispatcher stub" method bodies produced by VMP-style
packers: the original method body is replaced with a tiny shim that just
invokes a native dispatcher (passing an opcode / method id), which then
performs the real work inside a native VM interpreter.

These stubs look distinctive at the bytecode level:

- Very short (a handful of 16-bit code units).
- Their one meaningful operation is an ``invoke-*`` to another method
  (frequently ``invoke-static`` into a JNI-registered native method).
- Everything else is padding: ``nop`` and a trailing ``return-*``.

This module provides a lightweight, disassembler-free heuristic that scans
raw instruction bytes to classify methods as ``normal``, ``nop``
(still-encrypted / function-extracted), or ``vmp_stub``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from unpack.repair.dex_parser import CodeItem, DexFile

# Dalvik invoke-kind opcodes: invoke-virtual, invoke-super, invoke-direct,
# invoke-static, invoke-interface. All share the 35c instruction format
# where the second code unit holds the referenced method index.
INVOKE_VIRTUAL = 0x6E
INVOKE_SUPER = 0x6F
INVOKE_DIRECT = 0x70
INVOKE_STATIC = 0x71
INVOKE_INTERFACE = 0x72
INVOKE_OPCODES = frozenset(
    {INVOKE_VIRTUAL, INVOKE_SUPER, INVOKE_DIRECT, INVOKE_STATIC, INVOKE_INTERFACE}
)

# Dalvik return opcodes: return-void, return, return-wide, return-object.
RETURN_OPCODES = frozenset({0x0E, 0x0F, 0x10, 0x11})

NOP_OPCODE = 0x00


class MethodClassification(str, Enum):
    """Classification bucket for a single DEX method body."""

    NORMAL = "normal"
    NOP = "nop"
    VMP_STUB = "vmp_stub"


@dataclass
class VmpReport:
    """Aggregate result of classifying every method in one or more DEX files."""

    total_methods: int = 0
    normal_count: int = 0
    nop_count: int = 0
    vmp_count: int = 0
    vmp_methods: list[dict] = field(default_factory=list)
    call_graph: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_methods": self.total_methods,
            "normal_count": self.normal_count,
            "nop_count": self.nop_count,
            "vmp_count": self.vmp_count,
            "vmp_methods": self.vmp_methods,
            "call_graph": self.call_graph,
        }


class _MethodNameResolver:
    """Resolves a DEX method_idx to (class_name, method_name)."""

    def __init__(self, dex: DexFile):
        self._dex = dex
        self._cache: dict[int, tuple[str, str]] = {}

    def resolve(self, method_idx: int) -> tuple[str, str]:
        if method_idx in self._cache:
            return self._cache[method_idx]

        h = self._dex.header
        if method_idx < 0 or method_idx >= h.method_ids_size:
            return ("", "")

        # method_id_item: uint16 class_idx, uint16 proto_idx, uint32 name_idx
        mid_off = h.method_ids_off + method_idx * 8
        if mid_off + 8 > len(self._dex.data):
            return ("", "")

        vals = struct.unpack_from(f"{self._dex.fmt}HHI", self._dex.data, mid_off)
        type_idx = vals[0]
        name_idx = vals[2]

        cls_name = self._dex.get_type_name(type_idx) or ""
        meth_name = self._dex.get_string(name_idx) or ""

        result = (cls_name, meth_name)
        self._cache[method_idx] = result
        return result


class VmpDetector:
    """Classifies DEX method bodies as normal / NOP / VMP dispatcher stub."""

    # VMP stubs are tiny: at most this many 16-bit code units.
    MAX_VMP_STUB_UNITS = 5
    # At most this many opcodes that are neither invoke/nop/return.
    MAX_NON_TRIVIAL_OPS = 2

    def classify_insns(self, insns: bytes, insns_size: int) -> MethodClassification:
        """Classify a raw instruction stream.

        ``insns_size`` is the number of 16-bit code units, as stored in the
        DEX ``code_item`` header (``insns`` may be padded/truncated, so the
        scan is bounded by both the buffer length and this count).
        """
        if insns_size > 1 and len(insns) > 0 and all(b == 0 for b in insns):
            return MethodClassification.NOP

        if 0 < insns_size <= self.MAX_VMP_STUB_UNITS:
            has_invoke, non_trivial_ops, _ = self._scan(insns, insns_size)
            if has_invoke and non_trivial_ops <= self.MAX_NON_TRIVIAL_OPS:
                return MethodClassification.VMP_STUB

        return MethodClassification.NORMAL

    def _scan(self, insns: bytes, insns_size: int) -> tuple[bool, int, int | None]:
        """Scan code-unit-aligned opcode bytes.

        Returns ``(has_invoke, non_trivial_op_count, invoke_offset)``.
        This is a heuristic, not a full Dalvik disassembler: it looks at the
        first byte of every 16-bit code unit, which is where an opcode
        would start if that unit began an instruction. It is intentionally
        cheap since it only needs to be accurate for very short bodies.
        """
        has_invoke = False
        non_trivial_ops = 0
        invoke_offset: int | None = None

        limit = min(len(insns), insns_size * 2)
        offset = 0
        while offset < limit:
            opcode = insns[offset]
            if opcode in INVOKE_OPCODES:
                has_invoke = True
                if invoke_offset is None:
                    invoke_offset = offset
                non_trivial_ops += 1
            elif opcode == NOP_OPCODE or opcode in RETURN_OPCODES:
                pass
            else:
                non_trivial_ops += 1
            offset += 2

        return has_invoke, non_trivial_ops, invoke_offset

    def _invoke_target(self, insns: bytes, insns_size: int) -> int | None:
        """Return the method_idx referenced by the first invoke in insns, if any."""
        _, _, invoke_offset = self._scan(insns, insns_size)
        if invoke_offset is None:
            return None
        # Format 35c: op|A|G (code unit 0), BBBB method_idx (code unit 1), ...
        idx_off = invoke_offset + 2
        if idx_off + 2 > len(insns):
            return None
        return int.from_bytes(insns[idx_off:idx_off + 2], "little")

    def analyze_dex(self, dex_data: bytes) -> VmpReport:
        """Classify every method with a code body in a single DEX blob."""
        report = VmpReport()

        try:
            dex = DexFile.parse(dex_data)
        except Exception:
            return report

        resolver = _MethodNameResolver(dex)

        for cdef in dex.class_defs:
            if not cdef.class_data:
                continue
            class_name = dex.get_type_name(cdef.class_idx) or f"class#{cdef.class_idx}"
            methods = list(cdef.class_data.direct_methods) + list(cdef.class_data.virtual_methods)
            for method in methods:
                code_item: CodeItem | None = method.code_item
                if code_item is None:
                    continue

                report.total_methods += 1
                classification = self.classify_insns(code_item.insns, code_item.insns_size)

                if classification == MethodClassification.NORMAL:
                    report.normal_count += 1
                    continue
                if classification == MethodClassification.NOP:
                    report.nop_count += 1
                    continue

                report.vmp_count += 1
                _, method_name = resolver.resolve(method.method_idx)
                caller = f"{class_name}->{method_name}"

                target_idx = self._invoke_target(code_item.insns, code_item.insns_size)
                target_name = ""
                if target_idx is not None:
                    target_cls, target_meth = resolver.resolve(target_idx)
                    if target_cls or target_meth:
                        target_name = f"{target_cls}->{target_meth}"

                report.vmp_methods.append({
                    "class_name": class_name,
                    "method_name": method_name,
                    "method_idx": method.method_idx,
                    "insns_size": code_item.insns_size,
                    "target": target_name,
                })

                if target_name:
                    report.call_graph.append({"caller": caller, "callee": target_name})

        return report

    def analyze_file(self, dex_path: Path) -> VmpReport:
        """Classify every method with a code body in a DEX file on disk."""
        data = dex_path.read_bytes()
        return self.analyze_dex(data)
