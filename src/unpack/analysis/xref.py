"""Cross-reference index for DEX files.

Walks every method body in a DEX file with :class:`DalvikDecoder` and
builds a static cross-reference index: which methods reference which
string literals, which methods call which other methods, which methods
touch which fields, and — as a specific, higher-signal subset of the
method-call index — which call sites use Java reflection or dynamic
class loading APIs, since those are a common way packers/obfuscators
hide real behavior behind ``Class.forName`` / ``Method.invoke`` /
``DexClassLoader`` indirection.

This is static analysis of the raw instruction stream only: no
`register-level data-flow (e.g. "this `invoke-static` call's string
argument is *this* `const-string`") is attempted. Callers that need a
declared literal pool reference and the "is reflection used anywhere in
this method" signal get it from this module; anything requiring actual
taint tracking between instructions does not belong here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from unpack.analysis.disasm import DalvikDecoder, Instruction
from unpack.repair.dex_parser import DexFile

# (class_descriptor, method_name) pairs that are classic reflection /
# dynamic-loading sinks. Matching is on the raw signature pieces we can
# recover from a method_id (declaring type + name) — no argument/return
# type matching, since overload resolution isn't needed to flag intent.
REFLECTION_SIGNATURES: frozenset[tuple[str, str]] = frozenset({
    ("Ljava/lang/Class;", "forName"),
    ("Ljava/lang/Class;", "newInstance"),
    ("Ljava/lang/Class;", "getMethod"),
    ("Ljava/lang/Class;", "getDeclaredMethod"),
    ("Ljava/lang/Class;", "getField"),
    ("Ljava/lang/Class;", "getDeclaredField"),
    ("Ljava/lang/reflect/Method;", "invoke"),
    ("Ljava/lang/reflect/Constructor;", "newInstance"),
    ("Ljava/lang/reflect/Field;", "get"),
    ("Ljava/lang/reflect/Field;", "set"),
    ("Ljava/lang/reflect/AccessibleObject;", "setAccessible"),
    ("Ljava/lang/ClassLoader;", "loadClass"),
    ("Ldalvik/system/DexClassLoader;", "<init>"),
    ("Ldalvik/system/PathClassLoader;", "<init>"),
    ("Ldalvik/system/InMemoryDexClassLoader;", "<init>"),
    ("Ldalvik/system/BaseDexClassLoader;", "<init>"),
})


@dataclass
class CallerRef:
    """A single call-site location: which method a reference was found in."""

    class_name: str
    method_name: str

    def to_dict(self) -> dict:
        return {"class": self.class_name, "method": self.method_name}


@dataclass
class ReflectionCall:
    """A detected reflection / dynamic-class-loading call site."""

    caller: CallerRef
    target: str
    offset: int

    def to_dict(self) -> dict:
        return {"caller": self.caller.to_dict(), "target": self.target, "offset": self.offset}


@dataclass
class XrefReport:
    """Aggregate cross-reference index for one or more DEX files."""

    string_refs: dict[str, list[dict]] = field(default_factory=dict)
    method_calls: dict[str, list[dict]] = field(default_factory=dict)
    field_refs: dict[str, list[dict]] = field(default_factory=dict)
    reflection_calls: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "string_refs": self.string_refs,
            "method_calls": self.method_calls,
            "field_refs": self.field_refs,
            "reflection_calls": self.reflection_calls,
        }


class _NameResolver:
    """Resolves DEX method_idx / field_idx to (declaring_type, member_name)."""

    def __init__(self, dex: DexFile):
        self._dex = dex
        self._method_cache: dict[int, tuple[str, str]] = {}
        self._field_cache: dict[int, tuple[str, str]] = {}

    def resolve_method(self, method_idx: int) -> tuple[str, str]:
        if method_idx in self._method_cache:
            return self._method_cache[method_idx]

        h = self._dex.header
        result = ("", "")
        if 0 <= method_idx < h.method_ids_size:
            off = h.method_ids_off + method_idx * 8
            if off + 8 <= len(self._dex.data):
                # method_id_item: uint16 class_idx, uint16 proto_idx, uint32 name_idx
                class_idx, _proto_idx, name_idx = struct.unpack_from(
                    f"{self._dex.fmt}HHI", self._dex.data, off
                )
                cls_name = self._dex.get_type_name(class_idx) or ""
                meth_name = self._dex.get_string(name_idx) or ""
                result = (cls_name, meth_name)

        self._method_cache[method_idx] = result
        return result

    def resolve_field(self, field_idx: int) -> tuple[str, str]:
        if field_idx in self._field_cache:
            return self._field_cache[field_idx]

        h = self._dex.header
        result = ("", "")
        if 0 <= field_idx < h.field_ids_size:
            off = h.field_ids_off + field_idx * 8
            if off + 8 <= len(self._dex.data):
                # field_id_item: uint16 class_idx, uint16 type_idx, uint32 name_idx
                class_idx, _type_idx, name_idx = struct.unpack_from(
                    f"{self._dex.fmt}HHI", self._dex.data, off
                )
                cls_name = self._dex.get_type_name(class_idx) or ""
                field_name = self._dex.get_string(name_idx) or ""
                result = (cls_name, field_name)

        self._field_cache[field_idx] = result
        return result


class XrefBuilder:
    """Builds a cross-reference index across one or more DEX files."""

    def __init__(self):
        self._decoder = DalvikDecoder()

    def build_dex(self, dex: DexFile) -> XrefReport:
        """Build a cross-reference report for an already-parsed DexFile."""
        report = XrefReport()
        resolver = _NameResolver(dex)

        for cdef in dex.class_defs:
            if not cdef.class_data:
                continue
            class_name = dex.get_type_name(cdef.class_idx) or f"class#{cdef.class_idx}"
            methods = list(cdef.class_data.direct_methods) + list(cdef.class_data.virtual_methods)
            for method in methods:
                code_item = method.code_item
                if code_item is None:
                    continue

                _, method_name = resolver.resolve_method(method.method_idx)
                caller = CallerRef(class_name=class_name, method_name=method_name)

                instructions = self._decoder.decode(code_item.insns, code_item.insns_size)
                self._index_instructions(instructions, dex, resolver, caller, report)

        return report

    def _index_instructions(
        self,
        instructions: list[Instruction],
        dex: DexFile,
        resolver: _NameResolver,
        caller: CallerRef,
        report: XrefReport,
    ) -> None:
        for insn in instructions:
            if insn.string_idx is not None:
                value = dex.get_string(insn.string_idx)
                if value is not None:
                    report.string_refs.setdefault(value, []).append(caller.to_dict())

            if insn.method_idx is not None:
                target_cls, target_name = resolver.resolve_method(insn.method_idx)
                target_full = f"{target_cls}->{target_name}"
                report.method_calls.setdefault(target_full, []).append(caller.to_dict())

                if (target_cls, target_name) in REFLECTION_SIGNATURES:
                    report.reflection_calls.append(
                        ReflectionCall(caller=caller, target=target_full, offset=insn.offset).to_dict()
                    )

            if insn.field_idx is not None:
                field_cls, field_name = resolver.resolve_field(insn.field_idx)
                field_full = f"{field_cls}->{field_name}"
                report.field_refs.setdefault(field_full, []).append(caller.to_dict())

    def build(self, dex_data: bytes) -> XrefReport:
        """Build a cross-reference report from raw DEX bytes.

        Returns an empty report (rather than raising) if the data can't be
        parsed as a DEX file.
        """
        try:
            dex = DexFile.parse(dex_data)
        except Exception:
            return XrefReport()
        return self.build_dex(dex)

    def build_file(self, dex_path: Path) -> XrefReport:
        """Build a cross-reference report for a DEX file on disk."""
        data = dex_path.read_bytes()
        return self.build(data)

    @staticmethod
    def merge(reports: list[XrefReport]) -> XrefReport:
        """Merge multiple per-DEX reports into one combined report."""
        merged = XrefReport()
        for report in reports:
            for key, callers in report.string_refs.items():
                merged.string_refs.setdefault(key, []).extend(callers)
            for key, callers in report.method_calls.items():
                merged.method_calls.setdefault(key, []).extend(callers)
            for key, callers in report.field_refs.items():
                merged.field_refs.setdefault(key, []).extend(callers)
            merged.reflection_calls.extend(report.reflection_calls)
        return merged
