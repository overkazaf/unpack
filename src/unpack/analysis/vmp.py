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

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from unpack.logging_config import get_logger
from unpack.repair.dex_parser import CodeItem, DexFile

log = get_logger(__name__)

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
        """Backward-compatible 6-key serialization."""
        return {
            "total_methods": self.total_methods,
            "normal_count": self.normal_count,
            "nop_count": self.nop_count,
            "vmp_count": self.vmp_count,
            "vmp_methods": self.vmp_methods,
            "call_graph": self.call_graph,
        }

    @property
    def vmp_ratio(self) -> float:
        return (self.vmp_count / self.total_methods) if self.total_methods > 0 else 0.0

    @property
    def nop_ratio(self) -> float:
        return (self.nop_count / self.total_methods) if self.total_methods > 0 else 0.0

    @property
    def dispatchers(self) -> list[dict]:
        """Group VMP stubs by shared native/Java dispatcher target."""
        counts: dict[str, int] = {}
        for m in self.vmp_methods:
            target = m.get("target") or "(unresolved)"
            counts[target] = counts.get(target, 0) + 1
        return [
            {"dispatcher": target, "stub_count": count}
            for target, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ]

    @property
    def class_density(self) -> list[dict]:
        """Top classes ranked by number of VMP-stubbed methods."""
        counts: dict[str, int] = {}
        for m in self.vmp_methods:
            cls = m.get("class_name") or "(unknown)"
            counts[cls] = counts.get(cls, 0) + 1
        return [
            {"class_name": cls, "vmp_count": count}
            for cls, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:50]
        ]

    @property
    def risk_score(self) -> int:
        if self.total_methods == 0:
            return 0
        score = int(min(100, self.vmp_ratio * 120 + self.nop_ratio * 60))
        if self.vmp_count >= 10:
            score = max(score, 65)
        elif self.vmp_count > 0:
            score = max(score, 30)
        return min(100, score)

    @property
    def verdict(self) -> str:
        if self.vmp_count == 0 and self.nop_count == 0:
            return "clean"
        if self.vmp_count >= 10 or (self.vmp_count >= 3 and self.vmp_ratio >= 0.05):
            return "heavy_vmp"
        if self.vmp_count > 0:
            return "partial_vmp"
        return "function_extracted"

    def to_detailed_dict(self) -> dict:
        """Extended report with dispatcher clustering, density, risk score & verdict."""
        d = self.to_dict()
        d["vmp_ratio"] = round(self.vmp_ratio, 4)
        d["nop_ratio"] = round(self.nop_ratio, 4)
        d["dispatchers"] = self.dispatchers
        d["class_density"] = self.class_density
        d["risk_score"] = self.risk_score
        d["verdict"] = self.verdict
        return d


class VmpDetector:
    """Classifies DEX method bodies as normal / NOP / VMP dispatcher stub."""

    # VMP stubs are tiny: at most this many 16-bit code units. A bare
    # invoke (format 35c) is already 3 code units by itself, so this cap
    # effectively means "a dispatcher call with nothing else in the body".
    # This used to be 5, which also matched the extremely common
    # "invoke-direct <init> + return-void" shape (3 + 1 = 4 units) emitted
    # for every trivial constructor that just chains to its superclass --
    # causing false positives on completely unprotected apps. Real VMP
    # stubs don't need the extra headroom, so this is deliberately tight.
    MAX_VMP_STUB_UNITS = 3
    # At most this many opcodes that are neither invoke/nop/return.
    MAX_NON_TRIVIAL_OPS = 2
    # Invoke targets in these packages are always ordinary framework/
    # runtime calls, never a VMP packer's own (app-private) native
    # dispatcher -- so a short invoke-only body that calls into one of
    # these is not a VMP stub, no matter how short it is.
    FRAMEWORK_PREFIXES = ("java.", "android.", "kotlin.", "androidx.", "dalvik.")

    def classify_insns(
        self,
        insns: bytes,
        insns_size: int,
        method_name: str | None = None,
        invoke_target_class: str | None = None,
    ) -> MethodClassification:
        """Classify a raw instruction stream.

        ``insns_size`` is the number of 16-bit code units, as stored in the
        DEX ``code_item`` header (``insns`` may be padded/truncated, so the
        scan is bounded by both the buffer length and this count).

        ``method_name`` and ``invoke_target_class`` are optional extra
        context (see ``analyze_dex``, which resolves both before calling
        this) used to rule out two shapes that are short and invoke-only
        but are *not* VMP dispatcher stubs:

        - Constructors (``<init>``/``<clinit>``): chaining to a
          superclass/this constructor via a short ``invoke-direct`` is
          completely ordinary codegen, not virtualization.
        - A short invoke whose target is a standard framework class: real
          VMP stubs call into the packer's own native dispatcher, not into
          the platform.
        """
        if method_name in ("<init>", "<clinit>"):
            return MethodClassification.NORMAL

        if insns_size > 1 and len(insns) > 0 and all(b == 0 for b in insns):
            return MethodClassification.NOP

        if 0 < insns_size <= self.MAX_VMP_STUB_UNITS:
            has_invoke, non_trivial_ops, _ = self._scan(insns, insns_size)
            if has_invoke and non_trivial_ops <= self.MAX_NON_TRIVIAL_OPS:
                is_framework = (
                    invoke_target_class is not None
                    and self._is_framework_class(invoke_target_class)
                )
                if is_framework:
                    return MethodClassification.NORMAL
                return MethodClassification.VMP_STUB

        return MethodClassification.NORMAL

    def _is_framework_class(self, type_descriptor: str) -> bool:
        """True if a DEX type descriptor (e.g. ``Ljava/lang/Object;``) names
        a standard framework class rather than app/packer code."""
        clean = type_descriptor.strip("L;").replace("/", ".")
        return any(clean.startswith(prefix) for prefix in self.FRAMEWORK_PREFIXES)

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

    def first_invoke_target(self, insns: bytes, insns_size: int) -> int | None:
        """Return the method_idx referenced by the first invoke in ``insns``, if any."""
        _, _, invoke_offset = self._scan(insns, insns_size)
        if invoke_offset is None:
            return None
        # Format 35c: op|A|G (code unit 0), BBBB method_idx (code unit 1), ...
        idx_off = invoke_offset + 2
        if idx_off + 2 > len(insns):
            return None
        return int.from_bytes(insns[idx_off : idx_off + 2], "little")

    def _invoke_target(self, insns: bytes, insns_size: int) -> int | None:
        return self.first_invoke_target(insns, insns_size)

    def analyze_dex(self, dex_data: bytes) -> VmpReport:
        """Classify every method with a code body in a single DEX blob."""
        report = VmpReport()

        try:
            dex = DexFile.parse(dex_data)
        except Exception as exc:
            log.debug("VmpDetector.analyze_dex parse failed: %s", exc)
            return report

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
                method_name = dex.get_method_name(method.method_idx) or ""

                # Resolve the first invoke's target class up front so the
                # classifier can rule out calls into standard framework
                # classes. Only bother for methods short enough to even be
                # a VMP-stub candidate -- classify_insns ignores this
                # context for anything past the size gate, so resolving it
                # for ordinary (long) methods would just be wasted work.
                target_cls: str | None = None
                target_meth: str | None = None
                if 0 < code_item.insns_size <= self.MAX_VMP_STUB_UNITS:
                    target_idx = self._invoke_target(code_item.insns, code_item.insns_size)
                    if target_idx is not None:
                        target_cls, target_meth = dex.get_method_full(target_idx)

                classification = self.classify_insns(
                    code_item.insns,
                    code_item.insns_size,
                    method_name=method_name,
                    invoke_target_class=target_cls,
                )

                if classification == MethodClassification.NORMAL:
                    report.normal_count += 1
                    continue
                if classification == MethodClassification.NOP:
                    report.nop_count += 1
                    continue

                report.vmp_count += 1
                caller = f"{class_name}->{method_name}"

                target_name = ""
                if target_cls or target_meth:
                    target_name = f"{target_cls or ''}->{target_meth or ''}"

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
