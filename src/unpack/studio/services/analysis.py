"""Core analysis, DEX browsing, verification, repair, and VMP/Xref services."""

from __future__ import annotations

import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def scan_apk_rich(apk_path: Path) -> dict[str, Any]:
    from unpack.core.scanner import PackerScanner

    return PackerScanner().scan(apk_path, verbose=True).to_detailed_dict()


def inspect_apk_rich(apk_path: Path) -> dict[str, Any]:
    from unpack.core.inspector import ApkInspector

    return ApkInspector().inspect(apk_path, deep_elf=True, include_dex_metrics=True).to_dict()


def run_doctor_rich(check_devices: bool = True) -> dict[str, Any]:
    from unpack.core.doctor import run_doctor

    return run_doctor(check_devices=check_devices).to_dict()


def verify_dex_rich(dex_path: Path) -> dict[str, Any]:
    from unpack.repair.verifier import DexVerifier

    data = DexVerifier().verify(dex_path).to_dict()
    data.setdefault("file", dex_path.name)
    return data


def repair_dex_with_diff(dex_path: Path, out_dir: Path) -> tuple[dict[str, Any], Path | None]:
    """Copy DEX to ``out_dir`` and run ``DexRepairPipeline.repair_with_diff``."""
    from unpack.repair.dex_repair import DexRepairPipeline

    work_copy = out_dir / dex_path.name
    shutil.copy2(dex_path, work_copy)
    diff = DexRepairPipeline().repair_with_diff(work_copy, in_place=True)
    data = diff.to_dict()
    data.setdefault("file", dex_path.name)
    out_path = Path(diff.repair.output_path) if getattr(diff.repair, "output_path", None) else work_copy
    return data, out_path


def analyze_vmp_dex_bytes(dex_bytes: bytes, dex_name: str) -> dict[str, Any]:
    from unpack.analysis.vmp import VmpDetector

    data = VmpDetector().analyze_dex(dex_bytes).to_detailed_dict()
    data["dex"] = dex_name
    return data


def aggregate_vmp_analysis(
    dex_items: Iterable[tuple[str, bytes]],
    *,
    total_dex: int,
) -> dict[str, Any]:
    """Deduplicated VMP aggregator shared by the REST API and offline pipeline."""
    total_methods = normal_count = nop_count = vmp_count = 0
    all_vmp_methods: list[dict[str, Any]] = []
    all_call_graph: list[dict[str, Any]] = []
    dispatcher_counts: dict[str, int] = {}
    class_counts: dict[str, int] = {}
    per_dex: list[dict[str, Any]] = []

    for dname, raw in dex_items:
        rep = analyze_vmp_dex_bytes(raw, dname)
        total_methods += rep["total_methods"]
        normal_count += rep["normal_count"]
        nop_count += rep["nop_count"]
        vmp_count += rep["vmp_count"]
        per_dex.append(
            {
                "dex": dname,
                "total_methods": rep["total_methods"],
                "normal_count": rep["normal_count"],
                "nop_count": rep["nop_count"],
                "vmp_count": rep["vmp_count"],
                "vmp_ratio": rep.get("vmp_ratio", 0.0),
            }
        )
        method_target_hits = 0
        for m in rep.get("vmp_methods", []):
            cls = m.get("class_name") or m.get("class") or "unknown"
            meth = m.get("method_name") or m.get("method") or ""
            if len(all_vmp_methods) < 300:
                all_vmp_methods.append(
                    {**m, "class": cls, "class_name": cls, "method": meth, "method_name": meth, "dex": dname}
                )
            class_counts[cls] = class_counts.get(cls, 0) + 1
            if m.get("target"):
                tgt = m["target"]
                dispatcher_counts[tgt] = dispatcher_counts.get(tgt, 0) + 1
                method_target_hits += 1
        for edge in rep.get("call_graph", []):
            if len(all_call_graph) < 300:
                all_call_graph.append({**edge, "dex": dname})
            if method_target_hits == 0:
                tgt = edge.get("target") or edge.get("callee") or "unknown"
                dispatcher_counts[tgt] = dispatcher_counts.get(tgt, 0) + 1

    vmp_ratio = round(vmp_count / max(1, total_methods), 4)
    risk_score = min(100, int(round(vmp_ratio * 250 + (20 if vmp_count > 0 else 0))))
    verdict = "heavy_vmp" if vmp_ratio >= 0.15 else "partial_vmp" if vmp_count > 0 else "clean"

    return {
        "dex_analyzed": len(per_dex),
        "total_dex": total_dex,
        "total_methods": total_methods,
        "normal_count": normal_count,
        "nop_count": nop_count,
        "vmp_count": vmp_count,
        "vmp_ratio": vmp_ratio,
        "risk_score": risk_score,
        "verdict": verdict,
        "vmp_methods": all_vmp_methods,
        "call_graph": all_call_graph,
        "dispatchers": [
            {"target": k, "call_count": v}
            for k, v in sorted(dispatcher_counts.items(), key=lambda x: -x[1])[:30]
        ],
        "class_density": [
            {"class": k, "vmp_methods": v}
            for k, v in sorted(class_counts.items(), key=lambda x: -x[1])[:30]
        ],
        "per_dex": per_dex,
    }


def analyze_xref_dex_bytes(dex_bytes: bytes, limit: int = 100) -> dict[str, Any]:
    from unpack.analysis.xref import XrefBuilder

    return XrefBuilder().build(dex_bytes).summary(limit=limit)


class DexBrowserSession:
    """Thin UI-normalized facade over ``unpack.analysis.dex_inspector.DexInspector``."""

    def __init__(self, dex_bytes: bytes, name: str):
        from unpack.analysis.dex_inspector import DexInspector

        self.name = name
        self._inspector = DexInspector.from_bytes(dex_bytes, name=name)

    def summary(self) -> dict[str, Any]:
        return self._inspector.summary().to_dict()

    def list_classes(
        self, query: str = "", package: str = "", health: str = "", offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        health_map = {"ok": "normal", "vmp": "vmp_stub", "nop": "nop", "empty": "empty"}
        mapped_health = health_map.get(health.strip().lower(), health.strip().lower())
        page = self._inspector.list_classes(
            query=query, package=package, health=mapped_health, offset=offset, limit=limit
        ).to_dict()
        norm_classes = []
        for c in page.get("items", []):
            raw_h = c.get("health", "normal")
            ui_h = "ok" if raw_h == "normal" else ("vmp" if raw_h == "vmp_stub" else raw_h)
            desc = c.get("descriptor") or c.get("name", "")
            norm_classes.append(
                {
                    **c,
                    "name": desc,
                    "descriptor": desc,
                    "nop_methods": c.get("nop_count", c.get("nop_methods", 0)),
                    "vmp_methods": c.get("vmp_count", c.get("vmp_methods", 0)),
                    "health": ui_h,
                }
            )
        page["classes"] = norm_classes
        page["packages"] = [p.to_dict() for p in self._inspector.package_tree()[:80]]
        return page

    def inspect_class(self, class_name: str) -> dict[str, Any] | None:
        res = self._inspector.inspect_class(class_name)
        if res is None:
            return None
        d = res.to_dict()
        desc = d.get("descriptor") or d.get("name", class_name)
        d["name"] = desc
        d["descriptor"] = desc
        d["methods"] = [
            {
                **m,
                "kind": m.get("kind") or ("direct" if m.get("is_direct") else "virtual"),
                "health": "ok" if m.get("health", "normal") == "normal" else m.get("health"),
            }
            for m in d.get("methods", [])
        ]
        d["fields"] = [
            {**f, "kind": f.get("kind") or ("static" if f.get("is_static") else "instance")}
            for f in d.get("fields", [])
        ]
        return d

    def disassemble_method(
        self,
        class_name: str,
        method_name: str,
        method_idx: int | None = None,
        max_insns: int = 500,
    ) -> dict[str, Any] | None:
        res = self._inspector.disassemble_method(
            class_name, method_name, method_idx=method_idx, max_insns=max_insns
        )
        if res is None:
            return None
        d = res.to_dict()
        if "code_off" not in d:
            cls_info = self._inspector.inspect_class(class_name)
            code_off = 0
            if cls_info is not None:
                for m in cls_info.methods:
                    if m.method_idx == d.get("method_idx") or (
                        method_idx is None and m.name == d.get("method_name")
                    ):
                        code_off = m.code_off
                        break
            d["code_off"] = code_off
        norm_insns = []
        for ins in d.get("instructions", []):
            raw_hex = ins.get("raw_hex") or ins.get("hex") or ""
            spaced_hex = (
                " ".join(raw_hex[i : i + 2] for i in range(0, len(raw_hex), 2))
                if raw_hex and " " not in raw_hex
                else raw_hex
            )
            off_hex = ins.get("offset_hex")
            off_str = (
                f"0x{off_hex}"
                if off_hex is not None
                else (ins["offset"] if isinstance(ins.get("offset"), str) else f"0x{int(ins.get('offset', 0)):04x}")
            )
            operand = ins.get("operands") or ins.get("operand") or ins.get("resolved_ref") or ""
            norm_insns.append(
                {
                    **ins,
                    "offset": off_str,
                    "offset_int": ins.get("offset", 0) if isinstance(ins.get("offset"), int) else 0,
                    "hex": spaced_hex,
                    "operand": operand,
                    "ref_kind": ins.get("ref_kind") or "",
                }
            )
        d["instructions"] = norm_insns
        return d

    def search_strings(self, query: str = "", limit: int = 100) -> list[dict[str, Any]]:
        out = []
        for hit in self._inspector.search_strings(query=query, limit=limit):
            h = hit.to_dict()
            val = h.get("value", "")
            idx = h.get("string_idx", h.get("index", 0))
            out.append(
                {
                    **h,
                    "index": idx,
                    "string_idx": idx,
                    "value": val,
                    "length": len(val),
                    "category": h.get("category", "plain"),
                }
            )
        return out
