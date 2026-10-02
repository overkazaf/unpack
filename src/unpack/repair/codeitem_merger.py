from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from unpack.repair.dex_parser import DexFile, EncodedMethod, HEADER_SIZE


@dataclass
class CapturedCodeItem:
    """A CodeItem captured by Frida active invocation."""
    insns: bytes
    insns_size: int
    registers_size: int
    ins_size: int
    outs_size: int
    code_off: int = 0
    method_idx: int = -1
    class_name: str = ""
    method_name: str = ""


@dataclass
class MergeResult:
    success: bool
    output_path: Path | None = None
    methods_merged: int = 0
    methods_skipped: int = 0
    methods_still_nop: int = 0
    details: list[str] = field(default_factory=list)


class CodeItemMerger:
    """Merges captured CodeItems back into a NOP-filled skeleton DEX."""

    def merge(
        self,
        skeleton_dex: Path,
        code_items: list[dict | CapturedCodeItem],
        output_path: Path | None = None,
    ) -> MergeResult:
        result = MergeResult(success=False)
        data = bytearray(skeleton_dex.read_bytes())

        if len(data) < HEADER_SIZE:
            result.details.append("skeleton DEX too small")
            return result

        try:
            dex = DexFile.parse(bytes(data))
        except Exception as e:
            result.details.append(f"failed to parse skeleton DEX: {e}")
            return result

        captures = [self._normalize(c) for c in code_items]
        by_code_off, by_method_idx, by_name = self._build_lookups(captures)

        name_resolver = _MethodNameResolver(dex)

        for cdef in dex.class_defs:
            if not cdef.class_data:
                continue
            all_methods = (
                cdef.class_data.direct_methods + cdef.class_data.virtual_methods
            )
            for method in all_methods:
                if method.code_off == 0 or method.code_item is None:
                    continue

                ci = method.code_item
                if ci.insns_size == 0:
                    continue

                if not ci.is_nop_only:
                    result.methods_skipped += 1
                    continue

                captured, strategy = self._find_match(
                    method, cdef.class_idx, name_resolver,
                    by_code_off, by_method_idx, by_name,
                )

                if captured is None:
                    result.methods_still_nop += 1
                    continue

                if captured.insns_size != ci.insns_size:
                    result.methods_still_nop += 1
                    result.details.append(
                        f"size mismatch at code_off=0x{method.code_off:x}: "
                        f"skeleton={ci.insns_size} captured={captured.insns_size}"
                    )
                    continue

                insns_off = ci.offset + 16
                insns_byte_count = ci.insns_size * 2
                if insns_off + insns_byte_count > len(data):
                    result.methods_still_nop += 1
                    continue

                cap_bytes = captured.insns
                if len(cap_bytes) < insns_byte_count:
                    result.methods_still_nop += 1
                    continue

                data[insns_off : insns_off + insns_byte_count] = cap_bytes[:insns_byte_count]
                result.methods_merged += 1
                result.details.append(
                    f"merged method_idx={method.method_idx} "
                    f"code_off=0x{method.code_off:x} "
                    f"insns_size={ci.insns_size} via {strategy}"
                )

        data = self._fix_signature(data)
        data = self._fix_checksum(data, dex.fmt)

        if output_path is None:
            output_path = skeleton_dex.with_name(
                skeleton_dex.stem + "_merged.dex"
            )
        output_path.write_bytes(bytes(data))
        result.output_path = output_path
        result.success = True
        return result

    @staticmethod
    def _normalize(item: dict | CapturedCodeItem) -> CapturedCodeItem:
        if isinstance(item, CapturedCodeItem):
            return item
        insns = item.get("insns", b"")
        if isinstance(insns, list):
            insns = bytes(insns)
        return CapturedCodeItem(
            insns=insns,
            insns_size=item.get("insns_size", len(insns) // 2),
            registers_size=item.get("registers_size", 0),
            ins_size=item.get("ins_size", 0),
            outs_size=item.get("outs_size", 0),
            code_off=item.get("code_off", 0),
            method_idx=item.get("method_idx", -1),
            class_name=item.get("class_name", ""),
            method_name=item.get("method_name", ""),
        )

    @staticmethod
    def _build_lookups(
        captures: list[CapturedCodeItem],
    ) -> tuple[
        dict[int, CapturedCodeItem],
        dict[int, CapturedCodeItem],
        dict[tuple[str, str], CapturedCodeItem],
    ]:
        by_code_off: dict[int, CapturedCodeItem] = {}
        by_method_idx: dict[int, CapturedCodeItem] = {}
        by_name: dict[tuple[str, str], CapturedCodeItem] = {}

        for c in captures:
            if c.code_off > 0:
                by_code_off[c.code_off] = c
            if c.method_idx >= 0:
                by_method_idx[c.method_idx] = c
            if c.class_name and c.method_name:
                by_name[(c.class_name, c.method_name)] = c

        return by_code_off, by_method_idx, by_name

    @staticmethod
    def _find_match(
        method: EncodedMethod,
        class_idx: int,
        resolver: _MethodNameResolver,
        by_code_off: dict[int, CapturedCodeItem],
        by_method_idx: dict[int, CapturedCodeItem],
        by_name: dict[tuple[str, str], CapturedCodeItem],
    ) -> tuple[CapturedCodeItem | None, str]:
        if method.code_off in by_code_off:
            return by_code_off[method.code_off], "code_off"

        if method.method_idx in by_method_idx:
            return by_method_idx[method.method_idx], "method_idx"

        if by_name:
            cls_name, meth_name = resolver.resolve(method.method_idx)
            if cls_name and meth_name:
                key = (cls_name, meth_name)
                if key in by_name:
                    return by_name[key], "class+method_name"

        return None, ""

    @staticmethod
    def _fix_signature(data: bytearray) -> bytearray:
        computed = hashlib.sha1(bytes(data[32:])).digest()
        data[12:32] = computed
        return data

    @staticmethod
    def _fix_checksum(data: bytearray, fmt: str) -> bytearray:
        computed = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
        struct.pack_into(f"{fmt}I", data, 8, computed)
        return data


class _MethodNameResolver:
    """Resolves method_idx to (class_name, method_name) from the DEX tables."""

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
