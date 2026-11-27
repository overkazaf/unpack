"""DEX Inspector API for class/method browsing, health badges, and disassembly preview.

Designed for both CLI (`unpack inspect classes.dex`) and Web Studio (3-pane
DEX Inspector: package tree -> class/method list -> Dalvik disassembly preview
+ string/IOC search).
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from unpack.analysis.disasm import DecodedInstruction, FullDalvikDisassembler
from unpack.analysis.ioc import categorize_string
from unpack.analysis.native import shannon_entropy
from unpack.analysis.vmp import MethodClassification, VmpDetector
from unpack.logging_config import get_logger
from unpack.repair.dex_parser import (
    ClassDef,
    DexFile,
    EncodedMethod,
    decode_access_flags,
)
from unpack.repair.verifier import DexVerifier

log = get_logger(__name__)

_DEX_ENTRY_RE = re.compile(r"^classes\d*\.dex$")


def _descriptor_to_java(desc: str) -> str:
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")
    return desc


def _split_package(java_name: str) -> tuple[str, str]:
    if "." in java_name:
        pkg, simple = java_name.rsplit(".", 1)
        return pkg, simple
    return "(default)", java_name


@dataclass
class DexOverview:
    name: str
    size_bytes: int
    sha256: str
    dex_version: str
    valid: bool
    health_score: float
    entropy: float
    class_count: int
    method_count: int
    encoded_method_count: int
    methods_with_code: int
    nop_method_count: int
    vmp_stub_count: int
    abstract_or_native_count: int
    field_count: int
    string_count: int
    code_coverage: float
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "dex_version": self.dex_version,
            "valid": self.valid,
            "health_score": round(self.health_score, 2),
            "entropy": self.entropy,
            "class_count": self.class_count,
            "method_count": self.method_count,
            "encoded_method_count": self.encoded_method_count,
            "methods_with_code": self.methods_with_code,
            "nop_method_count": self.nop_method_count,
            "vmp_stub_count": self.vmp_stub_count,
            "abstract_or_native_count": self.abstract_or_native_count,
            "field_count": self.field_count,
            "string_count": self.string_count,
            "code_coverage": round(self.code_coverage, 4),
            "issues": self.issues,
        }


@dataclass
class PackageNode:
    package: str
    class_count: int
    method_count: int
    nop_count: int = 0
    vmp_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "class_count": self.class_count,
            "method_count": self.method_count,
            "nop_count": self.nop_count,
            "vmp_count": self.vmp_count,
        }


@dataclass
class ClassSummary:
    descriptor: str
    java_name: str
    package: str
    simple_name: str
    superclass: str
    access_flags: list[str]
    method_count: int
    field_count: int
    nop_count: int
    vmp_count: int
    health: str  # "normal" | "nop" | "vmp_stub" | "empty"

    def to_dict(self) -> dict[str, Any]:
        return {
            "descriptor": self.descriptor,
            "java_name": self.java_name,
            "package": self.package,
            "simple_name": self.simple_name,
            "superclass": self.superclass,
            "access_flags": self.access_flags,
            "method_count": self.method_count,
            "field_count": self.field_count,
            "nop_count": self.nop_count,
            "vmp_count": self.vmp_count,
            "health": self.health,
        }


@dataclass
class ClassPage:
    total: int
    offset: int
    limit: int
    items: list[ClassSummary] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "offset": self.offset,
            "limit": self.limit,
            "items": [c.to_dict() for c in self.items],
        }


@dataclass
class FieldSummary:
    field_idx: int
    name: str
    field_type: str
    is_static: bool
    access_flags: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "field_idx": self.field_idx,
            "name": self.name,
            "field_type": self.field_type,
            "is_static": self.is_static,
            "access_flags": self.access_flags,
        }


@dataclass
class MethodSummary:
    method_idx: int
    name: str
    signature: str
    is_direct: bool
    access_flags: list[str]
    code_off: int
    registers_size: int
    ins_size: int
    outs_size: int
    insns_size: int
    health: str  # "normal" | "nop" | "vmp_stub" | "abstract" | "native" | "empty"
    vmp_target: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method_idx": self.method_idx,
            "name": self.name,
            "signature": self.signature,
            "is_direct": self.is_direct,
            "access_flags": self.access_flags,
            "code_off": self.code_off,
            "registers_size": self.registers_size,
            "ins_size": self.ins_size,
            "outs_size": self.outs_size,
            "insns_size": self.insns_size,
            "health": self.health,
            "vmp_target": self.vmp_target,
        }


@dataclass
class ClassDetail:
    descriptor: str
    java_name: str
    package: str
    superclass: str
    interfaces: list[str]
    source_file: str
    access_flags: list[str]
    fields: list[FieldSummary] = field(default_factory=list)
    methods: list[MethodSummary] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "descriptor": self.descriptor,
            "java_name": self.java_name,
            "package": self.package,
            "superclass": self.superclass,
            "interfaces": self.interfaces,
            "source_file": self.source_file,
            "access_flags": self.access_flags,
            "fields": [f.to_dict() for f in self.fields],
            "methods": [m.to_dict() for m in self.methods],
        }


@dataclass
class MethodDisassembly:
    class_name: str
    method_name: str
    method_idx: int
    signature: str
    access_flags: list[str]
    registers_size: int
    ins_size: int
    outs_size: int
    insns_size: int
    health: str
    code_off: int = 0
    truncated: bool = False
    instructions: list[DecodedInstruction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "class_name": self.class_name,
            "method_name": self.method_name,
            "method_idx": self.method_idx,
            "signature": self.signature,
            "access_flags": self.access_flags,
            "code_off": self.code_off,
            "registers_size": self.registers_size,
            "ins_size": self.ins_size,
            "outs_size": self.outs_size,
            "insns_size": self.insns_size,
            "health": self.health,
            "truncated": self.truncated,
            "instructions": [i.to_dict() for i in self.instructions],
        }


@dataclass
class StringHit:
    string_idx: int
    value: str
    category: str  # "url" | "ip" | "secret" | "anti_analysis" | "plain"

    def to_dict(self) -> dict[str, Any]:
        return {
            "string_idx": self.string_idx,
            "value": self.value,
            "category": self.category,
        }


class DexInspector:
    """High-level query and disassembly interface over a single DEX binary."""

    def __init__(self, data: bytes, name: str = "classes.dex") -> None:
        self.name = name
        self.data = data
        self.dex = DexFile.parse(data)
        self._vmp = VmpDetector()
        self._disasm = FullDalvikDisassembler()
        self._class_index: dict[str, ClassDef] = {}
        self._class_summaries: list[ClassSummary] | None = None
        self._build_class_index()

    @classmethod
    def from_bytes(cls, data: bytes, name: str = "classes.dex") -> DexInspector:
        return cls(data=data, name=name)

    @classmethod
    def from_file(cls, dex_path: Path) -> DexInspector:
        return cls(data=dex_path.read_bytes(), name=dex_path.name)

    @classmethod
    def from_apk(cls, apk_path: Path) -> dict[str, DexInspector]:
        inspectors: dict[str, DexInspector] = {}
        if not zipfile.is_zipfile(apk_path):
            return inspectors
        with zipfile.ZipFile(apk_path, "r") as zf:
            dex_names = sorted(n for n in zf.namelist() if _DEX_ENTRY_RE.match(n))
            for name in dex_names:
                try:
                    inspectors[name] = cls.from_bytes(zf.read(name), name=name)
                except Exception as exc:
                    log.debug("DexInspector.from_apk skipping corrupt entry %s: %s", name, exc)
                    continue
        return inspectors

    def _build_class_index(self) -> None:
        for cdef in self.dex.class_defs:
            desc = self.dex.get_type_name(cdef.class_idx) or f"Lclass_{cdef.class_idx};"
            self._class_index[desc] = cdef
            self._class_index[_descriptor_to_java(desc)] = cdef

    def _classify_method(self, method: EncodedMethod) -> tuple[str, str]:
        flags = method.access_flags
        ci = method.code_item
        if method.code_off == 0 or ci is None:
            if flags & 0x0100:
                return "native", ""
            if flags & 0x0400:
                return "abstract", ""
            return "empty", ""

        method_name = self.dex.get_method_name(method.method_idx) or ""
        target_cls: str | None = None
        target_meth: str | None = None
        if 0 < ci.insns_size <= self._vmp.MAX_VMP_STUB_UNITS:
            t_idx = self._vmp.first_invoke_target(ci.insns, ci.insns_size)
            if t_idx is not None:
                target_cls, target_meth = self.dex.get_method_full(t_idx)

        cls_bucket = self._vmp.classify_insns(
            ci.insns,
            ci.insns_size,
            method_name=method_name,
            invoke_target_class=target_cls,
        )
        if cls_bucket == MethodClassification.NOP:
            return "nop", ""
        if cls_bucket == MethodClassification.VMP_STUB:
            target = f"{target_cls or ''}->{target_meth or ''}" if (target_cls or target_meth) else ""
            return "vmp_stub", target
        return "normal", ""

    def _ensure_summaries(self) -> list[ClassSummary]:
        if self._class_summaries is not None:
            return self._class_summaries

        summaries: list[ClassSummary] = []
        for cdef in self.dex.class_defs:
            desc = self.dex.get_type_name(cdef.class_idx) or f"Lclass_{cdef.class_idx};"
            java_name = _descriptor_to_java(desc)
            pkg, simple = _split_package(java_name)
            sup = (
                self.dex.get_type_name(cdef.superclass_idx) or ""
                if cdef.superclass_idx != 0xFFFFFFFF else ""
            )

            methods = (
                list(cdef.class_data.direct_methods) + list(cdef.class_data.virtual_methods)
                if cdef.class_data else []
            )
            field_count = (
                len(cdef.class_data.static_fields) + len(cdef.class_data.instance_fields)
                if cdef.class_data else 0
            )
            nop_c = 0
            vmp_c = 0
            for m in methods:
                health, _ = self._classify_method(m)
                if health == "nop":
                    nop_c += 1
                elif health == "vmp_stub":
                    vmp_c += 1

            if vmp_c > 0:
                cls_health = "vmp_stub"
            elif nop_c > 0:
                cls_health = "nop"
            elif not methods:
                cls_health = "empty"
            else:
                cls_health = "normal"

            summaries.append(
                ClassSummary(
                    descriptor=desc,
                    java_name=java_name,
                    package=pkg,
                    simple_name=simple,
                    superclass=_descriptor_to_java(sup) if sup else "",
                    access_flags=decode_access_flags(cdef.access_flags),
                    method_count=len(methods),
                    field_count=field_count,
                    nop_count=nop_c,
                    vmp_count=vmp_c,
                    health=cls_health,
                )
            )
        self._class_summaries = summaries
        return summaries

    def summary(self) -> DexOverview:
        vr = DexVerifier().verify_bytes(self.data)
        summaries = self._ensure_summaries()
        vmp_total = sum(c.vmp_count for c in summaries)
        nop_total = int(vr.stats.get("nop_only_methods", 0))
        with_code = int(vr.stats.get("methods_with_code", 0))
        abs_nat = int(vr.stats.get("abstract_or_native_methods", 0))
        encoded_total = int(vr.stats.get("encoded_methods", 0))

        version = self.dex.header.magic[4:7].decode("ascii", errors="replace")
        return DexOverview(
            name=self.name,
            size_bytes=len(self.data),
            sha256=hashlib.sha256(self.data).hexdigest(),
            dex_version=version,
            valid=vr.valid,
            health_score=vr.health_score,
            entropy=shannon_entropy(self.data[: 2 * 1024 * 1024]),
            class_count=self.dex.header.class_defs_size,
            method_count=self.dex.header.method_ids_size,
            encoded_method_count=encoded_total,
            methods_with_code=with_code,
            nop_method_count=nop_total,
            vmp_stub_count=vmp_total,
            abstract_or_native_count=abs_nat,
            field_count=self.dex.header.field_ids_size,
            string_count=self.dex.header.string_ids_size,
            code_coverage=float(vr.stats.get("code_coverage", 0.0)),
            issues=vr.issues,
        )

    def package_tree(self) -> list[PackageNode]:
        buckets: dict[str, list[int]] = {}
        for c in self._ensure_summaries():
            acc = buckets.setdefault(c.package, [0, 0, 0, 0])
            acc[0] += 1
            acc[1] += c.method_count
            acc[2] += c.nop_count
            acc[3] += c.vmp_count
        return [
            PackageNode(
                package=pkg,
                class_count=vals[0],
                method_count=vals[1],
                nop_count=vals[2],
                vmp_count=vals[3],
            )
            for pkg, vals in sorted(buckets.items())
        ]

    def list_classes(
        self,
        query: str = "",
        package: str = "",
        health: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> ClassPage:
        items = self._ensure_summaries()
        q = query.strip().lower()
        pkg = package.strip()
        h = health.strip().lower()

        filtered = items
        if pkg:
            filtered = [c for c in filtered if c.package == pkg or c.package.startswith(pkg + ".")]
        if h:
            filtered = [c for c in filtered if c.health == h]
        if q:
            filtered = [
                c for c in filtered
                if q in c.java_name.lower() or q in c.descriptor.lower()
            ]

        total = len(filtered)
        safe_offset = max(0, offset)
        safe_limit = max(1, min(limit, 1000))
        return ClassPage(
            total=total,
            offset=safe_offset,
            limit=safe_limit,
            items=filtered[safe_offset : safe_offset + safe_limit],
        )

    def inspect_class(self, class_name: str) -> ClassDetail | None:
        cdef = self._class_index.get(class_name)
        if cdef is None:
            return None

        desc = self.dex.get_type_name(cdef.class_idx) or f"Lclass_{cdef.class_idx};"
        java_name = _descriptor_to_java(desc)
        pkg, _ = _split_package(java_name)
        sup = (
            self.dex.get_type_name(cdef.superclass_idx) or ""
            if cdef.superclass_idx != 0xFFFFFFFF else ""
        )

        fields: list[FieldSummary] = []
        methods: list[MethodSummary] = []

        if cdef.class_data:
            for is_static, flist in (
                (True, cdef.class_data.static_fields),
                (False, cdef.class_data.instance_fields),
            ):
                for ef in flist:
                    _, fname, ftype = self.dex.get_field_detail(ef.field_idx)
                    fields.append(
                        FieldSummary(
                            field_idx=ef.field_idx,
                            name=fname or f"field_{ef.field_idx}",
                            field_type=ftype or "",
                            is_static=is_static,
                            access_flags=decode_access_flags(ef.access_flags, is_field=True),
                        )
                    )

            for is_direct, mlist in (
                (True, cdef.class_data.direct_methods),
                (False, cdef.class_data.virtual_methods),
            ):
                for em in mlist:
                    _, mname, proto = self.dex.get_method_signature(em.method_idx)
                    health, vmp_target = self._classify_method(em)
                    ci = em.code_item
                    methods.append(
                        MethodSummary(
                            method_idx=em.method_idx,
                            name=mname or f"method_{em.method_idx}",
                            signature=proto,
                            is_direct=is_direct,
                            access_flags=decode_access_flags(em.access_flags),
                            code_off=em.code_off,
                            registers_size=ci.registers_size if ci else 0,
                            ins_size=ci.ins_size if ci else 0,
                            outs_size=ci.outs_size if ci else 0,
                            insns_size=ci.insns_size if ci else 0,
                            health=health,
                            vmp_target=vmp_target,
                        )
                    )

        return ClassDetail(
            descriptor=desc,
            java_name=java_name,
            package=pkg,
            superclass=_descriptor_to_java(sup) if sup else "",
            interfaces=[_descriptor_to_java(i) for i in self.dex.get_interfaces(cdef)],
            source_file=self.dex.get_source_file(cdef) or "",
            access_flags=decode_access_flags(cdef.access_flags),
            fields=fields,
            methods=methods,
        )

    def disassemble_method(
        self,
        class_name: str,
        method_name: str,
        method_idx: int | None = None,
        max_insns: int = 500,
    ) -> MethodDisassembly | None:
        cdef = self._class_index.get(class_name)
        if cdef is None or not cdef.class_data:
            return None

        all_methods = list(cdef.class_data.direct_methods) + list(cdef.class_data.virtual_methods)
        target: EncodedMethod | None = None
        for em in all_methods:
            if method_idx is not None and em.method_idx == method_idx:
                target = em
                break
            mname = self.dex.get_method_name(em.method_idx) or ""
            if method_idx is None and mname == method_name:
                target = em
                break

        if target is None:
            return None

        desc = self.dex.get_type_name(cdef.class_idx) or class_name
        _, resolved_name, proto = self.dex.get_method_signature(target.method_idx)
        health, _ = self._classify_method(target)
        ci = target.code_item

        if ci is None or ci.insns_size == 0:
            return MethodDisassembly(
                class_name=_descriptor_to_java(desc),
                method_name=resolved_name or method_name,
                method_idx=target.method_idx,
                signature=proto,
                access_flags=decode_access_flags(target.access_flags),
                registers_size=0,
                ins_size=0,
                outs_size=0,
                insns_size=0,
                health=health,
                code_off=target.code_off,
                truncated=False,
                instructions=[],
            )

        insns = self._disasm.disassemble(
            ci.insns, ci.insns_size, dex=self.dex, max_insns=max_insns + 1
        )
        truncated = len(insns) > max_insns
        if truncated:
            insns = insns[:max_insns]

        return MethodDisassembly(
            class_name=_descriptor_to_java(desc),
            method_name=resolved_name or method_name,
            method_idx=target.method_idx,
            signature=proto,
            access_flags=decode_access_flags(target.access_flags),
            registers_size=ci.registers_size,
            ins_size=ci.ins_size,
            outs_size=ci.outs_size,
            insns_size=ci.insns_size,
            health=health,
            code_off=target.code_off,
            truncated=truncated,
            instructions=insns,
        )

    def search_strings(
        self,
        query: str = "",
        category: str = "",
        limit: int = 100,
    ) -> list[StringHit]:
        q = query.strip().lower()
        cat_filter = category.strip().lower()
        hits: list[StringHit] = []
        total_strings = min(self.dex.header.string_ids_size, 200_000)

        for idx in range(total_strings):
            val = self.dex.get_string(idx)
            if not val:
                continue
            cat = self._categorize_string(val)
            if cat_filter and cat != cat_filter:
                continue
            if q and q not in val.lower():
                continue
            hits.append(StringHit(string_idx=idx, value=val[:512], category=cat))
            if len(hits) >= limit:
                break
        return hits

    @staticmethod
    def _categorize_string(value: str) -> str:
        return categorize_string(value)
