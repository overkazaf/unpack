"""Quality evaluation and commercial audit report generation for UNPACK.

This module is intentionally free of Rich/TTY dependencies so it can be used
equally from the CLI, the Flask Web UI, and automated CI/CD pipelines.

Public API:
- ``QualityReport`` & ``Reporter.evaluate(output_dir, scan_result=None)``
  (100% backward-compatible DEX coverage & NOP evaluation).
- ``AuditFinding``, ``AuditReport``, ``Reporter.build_audit_report(...)``
  (unified commercial audit bundle accepting dataclasses or plain dicts).
- Pure renderers: ``render_html``, ``render_markdown``, ``render_sarif``,
  ``render_sarif_json``, ``render_json``, and ``ReportGenerator.render``.
"""

from __future__ import annotations

import dataclasses
import html
import json
import math
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from unpack import __version__
from unpack.repair.dex_parser import _uleb128

DEX_MAGIC = b"dex\n"
HEADER_SIZE = 0x70
NOP_INSN = 0x0000

AUDIT_SCHEMA_VERSION = "2.0"

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 18,
    "medium": 9,
    "low": 4,
    "info": 1,
}
SARIF_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
SARIF_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}


# ── Legacy / Core Quality Report (backward-compatible) ───────────────────────


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


# ── Commercial Audit Report Models ───────────────────────────────────────────


@dataclass
class AuditFinding:
    """Single actionable finding surfaced in an audit report."""

    id: str
    rule_id: str
    title: str
    severity: str = "info"  # critical | high | medium | low | info
    category: str = "general"  # packer | apk_security | dex_health | verify | vmp | xref
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    location: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "evidence": list(self.evidence),
            "location": self.location,
            "remediation": self.remediation,
        }


@dataclass
class AuditReport:
    """Unified audit report bundle consumable by HTML, Markdown, SARIF, and JSON renderers."""

    target: str
    title: str = "UNPACK Mobile Security & Unpacking Audit"
    schema_version: str = AUDIT_SCHEMA_VERSION
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    tool_version: str = __version__
    target_sha256: str | None = None
    grade: str = "A"
    risk_score: int = 0
    executive_summary: str = ""
    scan: dict[str, Any] | None = None
    inspect: dict[str, Any] | None = None
    quality: dict[str, Any] | None = None
    verify_results: list[dict[str, Any]] = field(default_factory=list)
    repair_results: list[dict[str, Any]] = field(default_factory=list)
    vmp: dict[str, Any] | None = None
    xref: dict[str, Any] | None = None
    findings: list[AuditFinding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in self.findings:
            sev = finding.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "title": self.title,
            "target": self.target,
            "target_sha256": self.target_sha256,
            "grade": self.grade,
            "risk_score": self.risk_score,
            "executive_summary": self.executive_summary,
            "severity_counts": self.severity_counts(),
            "scan": self.scan,
            "inspect": self.inspect,
            "quality": self.quality,
            "verify_results": self.verify_results,
            "repair_results": self.repair_results,
            "vmp": self.vmp,
            "xref": self.xref,
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": list(self.recommendations),
        }


# ── Normalization Helpers ────────────────────────────────────────────────────


def _normalize_obj(obj: Any) -> Any:
    """Convert dataclasses / domain objects into JSON-safe plain Python types."""
    if obj is None:
        return None
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): _normalize_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize_obj(v) for v in obj]
    if hasattr(obj, "to_detailed_dict") and callable(obj.to_detailed_dict):
        return _normalize_obj(obj.to_detailed_dict())
    if hasattr(obj, "to_verbose_dict") and callable(obj.to_verbose_dict):
        return _normalize_obj(obj.to_verbose_dict())
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return _normalize_obj(obj.to_dict())
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return _normalize_obj(dataclasses.asdict(obj))
    if hasattr(obj, "value") and not isinstance(obj, (str, bytes, int, float, bool)):
        return obj.value
    return obj


def _normalize_list(items: Any) -> list[dict[str, Any]]:
    if not items:
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        norm = _normalize_obj(item)
        if isinstance(norm, dict):
            out.append(norm)
    return out


def _score_to_grade(risk_score: int) -> str:
    if risk_score <= 15:
        return "A"
    if risk_score <= 35:
        return "B"
    if risk_score <= 55:
        return "C"
    if risk_score <= 75:
        return "D"
    return "F"


def _fmt_bytes(size: int | float | None) -> str:
    if size is None:
        return "—"
    n = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{size} B"


# ── Reporter ─────────────────────────────────────────────────────────────────


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
            "classes": 0,
            "methods": 0,
            "methods_with_code": 0,
            "nop_methods": 0,
            "empty_methods": 0,
            "file_size": len(data),
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

    # ── Commercial Audit Bundle Builder ──────────────────────────────────────

    def build_audit_report(
        self,
        target: str | Path,
        *,
        scan: Any = None,
        inspect: Any = None,
        quality: Any = None,
        verify_results: list[Any] | None = None,
        repair_results: list[Any] | None = None,
        vmp: Any = None,
        xref: Any = None,
        title: str | None = None,
    ) -> AuditReport:
        """Assemble a complete commercial ``AuditReport`` from any subset of stage outputs.

        All inputs accept either typed dataclasses (``ScanResult``, ``QualityReport``,
        ``ApkInspectResult``, ``VmpReport``, ``XrefReport``, ``VerifyResult``,
        ``RepairResult``) or plain JSON-decoded dicts (e.g. from Flask job state).
        """
        target_str = str(target.name if isinstance(target, Path) else target)
        scan_d = _normalize_obj(scan)
        inspect_d = _normalize_obj(inspect)
        quality_d = _normalize_obj(quality)
        verify_l = _normalize_list(verify_results)
        repair_l = _normalize_list(repair_results)
        vmp_d = _normalize_obj(vmp)
        xref_d = _normalize_obj(xref)

        target_sha256: str | None = None
        if isinstance(inspect_d, dict) and inspect_d.get("sha256"):
            target_sha256 = str(inspect_d["sha256"])
        elif isinstance(scan_d, dict) and isinstance(scan_d.get("apk_info"), dict):
            target_sha256 = scan_d["apk_info"].get("sha256")

        findings: list[AuditFinding] = []
        recommendations: list[str] = []
        seen_keys: set[tuple[str, str]] = set()
        counter = 0

        def add_finding(
            rule_id: str,
            finding_title: str,
            severity: str,
            category: str,
            description: str,
            evidence: list[str] | None = None,
            location: str | None = None,
            remediation: str | None = None,
        ) -> None:
            nonlocal counter
            key = (rule_id, finding_title)
            if key in seen_keys:
                return
            seen_keys.add(key)
            counter += 1
            sev = severity.lower() if severity and severity.lower() in SEVERITY_ORDER else "info"
            findings.append(
                AuditFinding(
                    id=f"F-{counter:03d}",
                    rule_id=rule_id,
                    title=finding_title,
                    severity=sev,
                    category=category,
                    description=description,
                    evidence=list(evidence or []),
                    location=location or target_str,
                    remediation=remediation,
                )
            )
            if remediation and remediation not in recommendations:
                recommendations.append(remediation)

        # 1. Packer Intelligence findings
        if isinstance(scan_d, dict) and scan_d.get("packer_name"):
            packer = str(scan_d["packer_name"])
            version = scan_d.get("packer_version")
            level = str(scan_d.get("protection_level") or "unknown")
            conf = float(scan_d.get("confidence") or 0.0)
            sigs = [str(s) for s in (scan_d.get("matched_signatures") or [])]
            label = f"{packer} ({version})" if version else packer

            if level in ("vmp", "dex2c"):
                add_finding(
                    "UNPACK-PACKER-001",
                    f"Advanced native/VM protection detected: {label}",
                    "high",
                    "packer",
                    (
                        f"Detected {label} with {level.upper()} protection "
                        f"({conf:.0%} confidence). Automated DEX dumping alone cannot recover "
                        "virtualized or native-compiled bytecode."
                    ),
                    evidence=sigs,
                    remediation=(
                        "Inspect native libraries and VMP stubs (`unpack vmp <dir>` / "
                        "`unpack inspect <apk>`) to locate interpreter or JNI dispatchers."
                    ),
                )
            elif level == "function_extraction":
                add_finding(
                    "UNPACK-PACKER-002",
                    f"Function-extraction packer detected: {label}",
                    "medium",
                    "packer",
                    (
                        f"Detected {label} ({conf:.0%} confidence). Method bodies may be "
                        "NOP-filled at rest and decrypted lazily at runtime."
                    ),
                    evidence=sigs,
                    remediation=(
                        "Use active invocation (`unpack dump <apk> --deep`) or incremental "
                        "component triggering (`unpack rescan <apk> <dir>`) to recover NOP methods."
                    ),
                )
            else:
                add_finding(
                    "UNPACK-PACKER-003",
                    f"DEX packer detected: {label}",
                    "low",
                    "packer",
                    (
                        f"Detected {label} using {level} protection ({conf:.0%} confidence). "
                        "Standard runtime memory dumping should recover the original DEX payload."
                    ),
                    evidence=sigs,
                    remediation="Run `unpack dump <apk>` with the memory engine to extract DEX.",
                )

            for anomaly in scan_d.get("heuristic_anomalies") or []:
                add_finding(
                    "UNPACK-PACKER-004",
                    "Heuristic packing anomaly",
                    "info",
                    "packer",
                    str(anomaly),
                )

        # 2. APK inspection findings (import core findings + synthesize key manifest checks)
        if isinstance(inspect_d, dict):
            for raw_f in inspect_d.get("findings") or []:
                if not isinstance(raw_f, dict):
                    continue
                ev_raw = raw_f.get("evidence")
                if isinstance(ev_raw, list):
                    ev_list = [str(x) for x in ev_raw]
                elif ev_raw:
                    ev_list = [str(ev_raw)]
                else:
                    ev_list = []
                add_finding(
                    str(raw_f.get("rule_id") or "UNPACK-APK-000"),
                    str(raw_f.get("title") or "APK Security Finding"),
                    str(raw_f.get("severity") or "info"),
                    str(raw_f.get("category") or "apk_security"),
                    str(raw_f.get("description") or ""),
                    evidence=ev_list,
                    location=raw_f.get("location") or target_str,
                    remediation=raw_f.get("remediation"),
                )

            manifest = inspect_d.get("manifest") or {}
            if isinstance(manifest, dict):
                if manifest.get("debuggable") is True:
                    add_finding(
                        "UNPACK-APK-001",
                        "Application is debuggable (android:debuggable=true)",
                        "high",
                        "apk_security",
                        "Debuggable builds allow JDWP attachment and trivial runtime inspection.",
                        evidence=["AndroidManifest.xml: android:debuggable=true"],
                        location="AndroidManifest.xml",
                        remediation="Disable android:debuggable in release builds.",
                    )
                if manifest.get("allow_backup") is True:
                    add_finding(
                        "UNPACK-APK-002",
                        "Application backup enabled (android:allowBackup=true)",
                        "medium",
                        "apk_security",
                        "Backup enabled allows extraction of app private data via ADB backup.",
                        evidence=["AndroidManifest.xml: android:allowBackup=true"],
                        location="AndroidManifest.xml",
                        remediation="Set android:allowBackup=\"false\" or restrict backup rules.",
                    )
                if manifest.get("uses_cleartext_traffic") is True:
                    add_finding(
                        "UNPACK-APK-003",
                        "Cleartext network traffic permitted",
                        "medium",
                        "apk_security",
                        "android:usesCleartextTraffic=true exposes traffic to MITM interception.",
                        evidence=["AndroidManifest.xml: android:usesCleartextTraffic=true"],
                        location="AndroidManifest.xml",
                        remediation="Disable cleartext traffic and enforce HTTPS via Network Security Config.",
                    )

            signing = inspect_d.get("signing") or {}
            if isinstance(signing, dict) and signing.get("is_debug_cert"):
                add_finding(
                    "UNPACK-APK-005",
                    "APK signed with Android debug certificate",
                    "high",
                    "apk_security",
                    "Debug signing keys are publicly known and must not be shipped to production.",
                    evidence=[str(signing.get("subject") or "CN=Android Debug")],
                    location="META-INF/",
                    remediation="Sign release artifacts with a protected production keystore.",
                )

        # 3. DEX quality findings
        if isinstance(quality_d, dict):
            total_methods = int(quality_d.get("total_methods") or 0)
            nop_methods = int(quality_d.get("nop_methods") or 0)
            coverage = float(quality_d.get("code_coverage") or 0.0)
            dex_count = int(quality_d.get("dex_count") or 0)

            if nop_methods > 0:
                nop_ratio = nop_methods / total_methods if total_methods else 0.0
                sev = "high" if nop_ratio >= 0.2 else "medium"
                add_finding(
                    "UNPACK-DEX-001",
                    f"{nop_methods:,} NOP-only (still encrypted) methods remain",
                    sev,
                    "dex_health",
                    (
                        f"{nop_methods:,} of {total_methods:,} methods ({nop_ratio:.1%}) "
                        "contain only NOP instructions, indicating incomplete function extraction recovery."
                    ),
                    evidence=[
                        f"{d.get('file')}: {d.get('nop_methods')} NOP method(s)"
                        for d in (quality_d.get("per_dex") or [])
                        if d.get("nop_methods", 0) > 0
                    ][:10],
                    remediation="Run `unpack dump <apk> --deep` or `unpack rescan <apk> <dir>` to trigger remaining methods.",
                )

            if total_methods > 0 and coverage < 0.8:
                add_finding(
                    "UNPACK-DEX-002",
                    f"Low DEX code coverage ({coverage:.1%})",
                    "medium",
                    "dex_health",
                    f"Only {coverage:.1%} of methods contain executable CodeItems across {dex_count} DEX file(s).",
                    remediation="Verify dump completeness and try re-dumping with a longer wait timeout or `--deep`.",
                )

        # 4. DEX verification findings
        for vr in verify_l:
            if vr.get("valid") is False:
                fname = str(vr.get("file") or "unknown.dex")
                issues = [str(i) for i in (vr.get("issues") or [])]
                add_finding(
                    "UNPACK-VERIFY-001",
                    f"DEX integrity verification failed: {fname}",
                    "high",
                    "verify",
                    f"{fname} failed {len(issues)} structural integrity check(s).",
                    evidence=issues[:10],
                    location=fname,
                    remediation=f"Run `unpack repair {fname}` to repair headers, bounds, and checksums.",
                )

        # 5. VMP findings
        if isinstance(vmp_d, dict) and int(vmp_d.get("vmp_count") or 0) > 0:
            vmp_count = int(vmp_d["vmp_count"])
            total_m = int(vmp_d.get("total_methods") or 0)
            ratio = (vmp_count / total_m) if total_m else 0.0
            sample_ev = [
                f"{m.get('class', '')}->{m.get('method', '')}"
                for m in (vmp_d.get("vmp_methods") or [])[:8]
            ]
            add_finding(
                "UNPACK-VMP-001",
                f"{vmp_count:,} VMP dispatcher stub method(s) identified",
                "high",
                "vmp",
                (
                    f"Classified {vmp_count:,} method(s) ({ratio:.1%} of {total_m:,}) "
                    "as virtualized VMP dispatcher stubs forwarding into a native VM."
                ),
                evidence=sample_ev,
                remediation="Trace the native VM dispatcher target(s) in IDA/Ghidra using the exported VMP call graph.",
            )

        # 6. Xref / reflection findings
        if isinstance(xref_d, dict):
            refl = xref_d.get("reflection_calls") or []
            if len(refl) > 0:
                sample_ev = []
                for call in refl[:8]:
                    caller = call.get("caller") or {}
                    sample_ev.append(
                        f"{caller.get('class', '?')}->{caller.get('method', '?')} => {call.get('target', '?')}"
                    )
                add_finding(
                    "UNPACK-XREF-001",
                    f"{len(refl):,} reflection / dynamic loading call site(s) detected",
                    "medium",
                    "xref",
                    (
                        "Dynamic class loading or Java reflection calls often hide secondary "
                        "payload loading, hidden API invocation, or anti-analysis hooks."
                    ),
                    evidence=sample_ev,
                    remediation="Review reflection call sites with `unpack xref <dir> -j xref.json`.",
                )

            iocs = xref_d.get("iocs") or {}
            if isinstance(iocs, dict) and any(iocs.values()):
                ioc_count = sum(len(v) for v in iocs.values() if isinstance(v, list))
                if ioc_count > 0:
                    add_finding(
                        "UNPACK-XREF-002",
                        f"{ioc_count:,} network/secret indicator(s) extracted from DEX strings",
                        "low",
                        "xref",
                        "Extracted hardcoded URLs, IP addresses, or credential-like tokens from DEX string pools.",
                        evidence=[f"{k}: {len(v)}" for k, v in iocs.items() if isinstance(v, list) and v],
                    )

        # Sort findings by severity
        sev_rank = {s: idx for idx, s in enumerate(SEVERITY_ORDER)}
        findings.sort(key=lambda f: (sev_rank.get(f.severity, 99), f.rule_id, f.title))

        # Compute overall risk score (0..100) and grade (A..F)
        finding_score = sum(SEVERITY_WEIGHTS.get(f.severity, 1) for f in findings)
        quality_penalty = 0
        if isinstance(quality_d, dict) and quality_d.get("dex_count", 0) > 0:
            q_score = float(quality_d.get("score") or 0.0)
            quality_penalty = int(round((1.0 - max(0.0, min(1.0, q_score))) * 20))
        computed_risk = min(100, finding_score + quality_penalty)

        if isinstance(inspect_d, dict) and isinstance(inspect_d.get("risk_score"), (int, float)):
            # Blend inspector risk score with computed unpacking/analysis risk
            risk_score = min(100, max(computed_risk, int(round(inspect_d["risk_score"]))))
        else:
            risk_score = computed_risk

        grade = _score_to_grade(risk_score)
        exec_summary = _build_executive_summary(
            target_str, scan_d, quality_d, verify_l, vmp_d, findings, grade, risk_score
        )

        if not recommendations:
            recommendations.append("No immediate remediation required; artifact passed automated checks.")

        return AuditReport(
            target=target_str,
            title=title or f"UNPACK Audit Report — {target_str}",
            target_sha256=target_sha256,
            grade=grade,
            risk_score=risk_score,
            executive_summary=exec_summary,
            scan=scan_d if isinstance(scan_d, dict) else None,
            inspect=inspect_d if isinstance(inspect_d, dict) else None,
            quality=quality_d if isinstance(quality_d, dict) else None,
            verify_results=verify_l,
            repair_results=repair_l,
            vmp=vmp_d if isinstance(vmp_d, dict) else None,
            xref=xref_d if isinstance(xref_d, dict) else None,
            findings=findings,
            recommendations=recommendations,
        )


def _build_executive_summary(
    target: str,
    scan_d: dict[str, Any] | None,
    quality_d: dict[str, Any] | None,
    verify_l: list[dict[str, Any]],
    vmp_d: dict[str, Any] | None,
    findings: list[AuditFinding],
    grade: str,
    risk_score: int,
) -> str:
    parts: list[str] = [f"Automated security & unpacking assessment for {target} (Grade {grade}, Risk {risk_score}/100)."]
    if isinstance(scan_d, dict):
        if scan_d.get("packer_name"):
            ver = f" {scan_d['packer_version']}" if scan_d.get("packer_version") else ""
            parts.append(
                f"Identified {scan_d['packer_name']}{ver} "
                f"({scan_d.get('protection_level', 'unknown')}, {float(scan_d.get('confidence', 0)):.0%} confidence)."
            )
        else:
            parts.append("No commercial packer signature matched.")
    if isinstance(quality_d, dict) and quality_d.get("dex_count", 0) > 0:
        parts.append(
            f"Evaluated {quality_d['dex_count']} DEX file(s) with "
            f"{float(quality_d.get('code_coverage', 0)):.1%} code coverage "
            f"and {int(quality_d.get('nop_methods', 0)):,} NOP method(s)."
        )
    if verify_l:
        passed = sum(1 for v in verify_l if v.get("valid"))
        parts.append(f"DEX integrity verification: {passed}/{len(verify_l)} passed.")
    if isinstance(vmp_d, dict) and vmp_d.get("total_methods", 0) > 0:
        parts.append(f"VMP analysis flagged {int(vmp_d.get('vmp_count', 0)):,} stub method(s).")
    if findings:
        high_plus = sum(1 for f in findings if f.severity in ("critical", "high"))
        parts.append(f"Total findings: {len(findings)} ({high_plus} critical/high).")
    return " ".join(parts)


# ── Pure Renderers (JSON, Markdown, SARIF 2.1.0, HTML5) ──────────────────────


def render_json(audit: AuditReport) -> str:
    """Render an ``AuditReport`` as formatted JSON."""
    return json.dumps(audit.to_dict(), indent=2, ensure_ascii=False)


def render_sarif(audit: AuditReport) -> dict[str, Any]:
    """Render an ``AuditReport`` as an OASIS SARIF 2.1.0 dictionary."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in audit.findings:
        sev = finding.severity.lower()
        level = SARIF_LEVEL_MAP.get(sev, "note")
        sec_sev = SARIF_SECURITY_SEVERITY.get(sev, "1.0")

        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id.replace("-", "_"),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "defaultConfiguration": {"level": level},
                "help": {
                    "text": finding.remediation or finding.description or finding.title,
                },
                "properties": {
                    "tags": ["security", "android", finding.category],
                    "security-severity": sec_sev,
                },
            }

        result_entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": level,
            "message": {
                "text": (
                    f"{finding.title}: {finding.description}"
                    if finding.description
                    else finding.title
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location or audit.target,
                        }
                    }
                }
            ],
            "properties": {
                "findingId": finding.id,
                "severity": sev,
                "category": finding.category,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            },
        }
        results.append(result_entry)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "UNPACK",
                        "version": audit.tool_version,
                        "informationUri": "https://github.com/overkazaf/unpack",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": audit.generated_at,
                    }
                ],
                "results": results,
                "properties": {
                    "target": audit.target,
                    "targetSha256": audit.target_sha256,
                    "grade": audit.grade,
                    "riskScore": audit.risk_score,
                },
            }
        ],
    }


def render_sarif_json(audit: AuditReport) -> str:
    """Render an ``AuditReport`` as a formatted SARIF 2.1.0 JSON string."""
    return json.dumps(render_sarif(audit), indent=2, ensure_ascii=False)


def render_markdown(audit: AuditReport) -> str:
    """Render an ``AuditReport`` as GitHub-Flavored Markdown."""
    lines: list[str] = []
    lines.append(f"# {audit.title}")
    lines.append("")
    lines.append(f"> {audit.executive_summary}")
    lines.append("")
    lines.append("## Assessment Metadata")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Target | `{audit.target}` |")
    if audit.target_sha256:
        lines.append(f"| SHA-256 | `{audit.target_sha256}` |")
    lines.append(f"| Grade / Risk Score | **{audit.grade}** ({audit.risk_score}/100) |")
    lines.append(f"| Generated | {audit.generated_at} |")
    lines.append(f"| Tool | UNPACK v{audit.tool_version} |")
    lines.append("")

    # Findings summary
    counts = audit.severity_counts()
    lines.append("## Security & Unpacking Findings")
    lines.append("")
    lines.append(
        f"Critical: **{counts['critical']}** · High: **{counts['high']}** · "
        f"Medium: **{counts['medium']}** · Low: **{counts['low']}** · Info: **{counts['info']}**"
    )
    lines.append("")
    if audit.findings:
        lines.append("| ID | Severity | Rule | Finding | Location |")
        lines.append("| --- | --- | --- | --- | --- |")
        for f in audit.findings:
            lines.append(
                f"| `{f.id}` | **{f.severity.upper()}** | `{f.rule_id}` | "
                f"{f.title} | `{f.location or audit.target}` |"
            )
        lines.append("")
        for f in audit.findings:
            lines.append(f"### {f.id} · [{f.severity.upper()}] {f.title}")
            lines.append("")
            if f.description:
                lines.append(f.description)
                lines.append("")
            if f.evidence:
                lines.append("**Evidence:**")
                for ev in f.evidence[:15]:
                    lines.append(f"- `{ev}`")
                lines.append("")
            if f.remediation:
                lines.append(f"**Remediation:** {f.remediation}")
                lines.append("")
    else:
        lines.append("_No findings reported._")
        lines.append("")

    # Packer Intelligence
    if audit.scan:
        lines.append("## Packer Intelligence")
        lines.append("")
        packer = audit.scan.get("packer_name") or "None detected"
        ver = audit.scan.get("packer_version") or "—"
        level = audit.scan.get("protection_level") or "none"
        conf = float(audit.scan.get("confidence") or 0.0)
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Packer | **{packer}** |")
        lines.append(f"| Version | {ver} |")
        lines.append(f"| Protection Level | `{level}` |")
        lines.append(f"| Confidence | {conf:.0%} |")
        sigs = audit.scan.get("matched_signatures") or []
        if sigs:
            lines.append(f"| Signatures | {', '.join(f'`{s}`' for s in sigs)} |")
        lines.append("")
        breakdown = audit.scan.get("score_breakdown") or []
        if breakdown:
            lines.append("| Dimension | Score | Max | Status |")
            lines.append("| --- | ---: | ---: | --- |")
            for b in breakdown:
                st = "HIT" if b.get("matched") else "—"
                lines.append(
                    f"| {b.get('dimension', '')} | {float(b.get('score', 0)):.1f} "
                    f"| {float(b.get('max', 0)):.1f} | {st} |"
                )
            lines.append("")

    # APK Inspection
    if audit.inspect:
        manifest = audit.inspect.get("manifest") or {}
        lines.append("## APK Static Inspection")
        lines.append("")
        if manifest:
            lines.append("| Attribute | Value |")
            lines.append("| --- | --- |")
            for key, label in (
                ("package_name", "Package"),
                ("version_name", "Version Name"),
                ("version_code", "Version Code"),
                ("min_sdk", "Min SDK"),
                ("target_sdk", "Target SDK"),
                ("application_class", "Application Class"),
                ("debuggable", "Debuggable"),
                ("allow_backup", "Allow Backup"),
            ):
                if key in manifest and manifest[key] is not None:
                    lines.append(f"| {label} | `{manifest[key]}` |")
            lines.append("")

        native_libs = audit.inspect.get("native_libs") or []
        if native_libs:
            lines.append(f"### Native Libraries ({len(native_libs)})")
            lines.append("")
            lines.append("| Library | ABI | Size | Flags |")
            lines.append("| --- | --- | ---: | --- |")
            for lib in native_libs[:25]:
                flags = []
                if lib.get("pie") is True:
                    flags.append("PIE")
                if lib.get("nx") is True:
                    flags.append("NX")
                if lib.get("relro"):
                    flags.append(f"RELRO:{lib['relro']}")
                if lib.get("canary") is True:
                    flags.append("CANARY")
                lines.append(
                    f"| `{lib.get('name') or lib.get('path', '')}` | {lib.get('abi', '—')} "
                    f"| {_fmt_bytes(lib.get('size') or lib.get('size_bytes'))} "
                    f"| {', '.join(flags) or '—'} |"
                )
            lines.append("")

    # DEX Quality
    if audit.quality:
        q = audit.quality
        lines.append("## DEX Quality & Coverage")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| --- | ---: |")
        lines.append(f"| DEX Files | {int(q.get('dex_count', 0)):,} |")
        lines.append(f"| Total Classes | {int(q.get('total_classes', 0)):,} |")
        lines.append(f"| Total Methods | {int(q.get('total_methods', 0)):,} |")
        lines.append(f"| Methods with Code | {int(q.get('methods_with_code', 0)):,} |")
        lines.append(f"| NOP-only Methods | {int(q.get('nop_methods', 0)):,} |")
        lines.append(f"| Code Coverage | {float(q.get('code_coverage', 0)):.1%} |")
        lines.append(f"| Quality Score | {float(q.get('score', 0)):.1%} |")
        lines.append("")
        per_dex = q.get("per_dex") or []
        if per_dex:
            lines.append("| File | Size | Classes | Methods | With Code | NOP |")
            lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
            for d in per_dex:
                lines.append(
                    f"| `{d.get('file', '')}` | {_fmt_bytes(d.get('file_size'))} "
                    f"| {int(d.get('classes', 0)):,} | {int(d.get('methods', 0)):,} "
                    f"| {int(d.get('methods_with_code', 0)):,} | {int(d.get('nop_methods', 0)):,} |"
                )
            lines.append("")

    # Verification
    if audit.verify_results:
        lines.append("## DEX Integrity Verification")
        lines.append("")
        lines.append("| File | Status | Issues |")
        lines.append("| --- | --- | --- |")
        for v in audit.verify_results:
            st = "PASS" if v.get("valid") else "FAIL"
            iss = "; ".join(v.get("issues") or []) or "—"
            lines.append(f"| `{v.get('file', '')}` | **{st}** | {iss} |")
        lines.append("")

    # VMP
    if audit.vmp:
        lines.append("## VMP Method Classification")
        lines.append("")
        lines.append(
            f"- Total: **{int(audit.vmp.get('total_methods', 0)):,}** · "
            f"Normal: **{int(audit.vmp.get('normal_count', 0)):,}** · "
            f"NOP: **{int(audit.vmp.get('nop_count', 0)):,}** · "
            f"VMP Stubs: **{int(audit.vmp.get('vmp_count', 0)):,}**"
        )
        lines.append("")

    # Xref
    if audit.xref:
        lines.append("## Cross-Reference Highlights")
        lines.append("")
        lines.append(
            f"- String refs: **{len(audit.xref.get('string_refs') or {}):,}** · "
            f"Method calls: **{len(audit.xref.get('method_calls') or {}):,}** · "
            f"Field refs: **{len(audit.xref.get('field_refs') or {}):,}** · "
            f"Reflection calls: **{len(audit.xref.get('reflection_calls') or []):,}**"
        )
        lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    lines.append("")
    for rec in audit.recommendations:
        lines.append(f"- {rec}")
    lines.append("")

    return "\n".join(lines)


# ── Self-Contained Commercial HTML5 Report Renderer ──────────────────────────


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _svg_risk_gauge(risk_score: int, grade: str) -> str:
    """Render an inline SVG semi-circular / ring gauge for the overall risk score."""
    score = max(0, min(100, int(risk_score)))
    radius = 40
    circ = 2 * math.pi * radius
    dash = circ * (score / 100.0)
    color = (
        "#10b981" if score <= 15 else
        "#38bdf8" if score <= 35 else
        "#f59e0b" if score <= 55 else
        "#f97316" if score <= 75 else
        "#ef4444"
    )
    return (
        f'<svg class="gauge" viewBox="0 0 100 100" width="96" height="96" aria-label="Risk Score {score}">'
        f'<circle cx="50" cy="50" r="{radius}" fill="none" stroke="var(--border)" stroke-width="8" />'
        f'<circle cx="50" cy="50" r="{radius}" fill="none" stroke="{color}" stroke-width="8" '
        f'stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}" '
        f'transform="rotate(-90 50 50)" />'
        f'<text x="50" y="47" text-anchor="middle" font-size="24" font-weight="700" fill="var(--text)">{_esc(grade)}</text>'
        f'<text x="50" y="65" text-anchor="middle" font-size="11" fill="var(--muted)">{score}/100</text>'
        f"</svg>"
    )


def _svg_method_donut(normal: int, nop: int, vmp: int, empty: int) -> str:
    """Render an inline SVG donut chart for method health composition."""
    total = normal + nop + vmp + empty
    if total <= 0:
        return ""
    radius = 38
    circ = 2 * math.pi * radius
    segments = [
        ("Normal", normal, "#10b981"),
        ("NOP", nop, "#f59e0b"),
        ("VMP Stub", vmp, "#ef4444"),
        ("Empty/Abstract", empty, "#64748b"),
    ]
    arcs: list[str] = []
    offset = 0.0
    legend: list[str] = []
    for label, count, color in segments:
        if count <= 0:
            continue
        frac = count / total
        seg_len = circ * frac
        arcs.append(
            f'<circle cx="50" cy="50" r="{radius}" fill="none" stroke="{color}" stroke-width="11" '
            f'stroke-dasharray="{seg_len:.2f} {circ:.2f}" stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 50 50)" />'
        )
        offset += seg_len
        legend.append(
            f'<div class="legend-item"><span class="dot" style="background:{color}"></span>'
            f'<span>{_esc(label)}</span><strong>{count:,}</strong>'
            f'<span class="muted">({frac:.1%})</span></div>'
        )
    return (
        '<div class="donut-wrap">'
        '<svg viewBox="0 0 100 100" width="128" height="128" aria-label="Method Composition">'
        f'<circle cx="50" cy="50" r="{radius}" fill="none" stroke="var(--border)" stroke-width="11" />'
        + "".join(arcs)
        + f'<text x="50" y="48" text-anchor="middle" font-size="13" font-weight="700" fill="var(--text)">{total:,}</text>'
        + '<text x="50" y="61" text-anchor="middle" font-size="8.5" fill="var(--muted)">methods</text>'
        + "</svg>"
        + f'<div class="legend">{"".join(legend)}</div>'
        + "</div>"
    )


def render_html(audit: AuditReport) -> str:
    """Render a self-contained, offline, print-ready commercial HTML5 audit report."""
    counts = audit.severity_counts()
    packer_label = "None"
    protection_label = "none"
    confidence_pct = "—"
    if audit.scan and audit.scan.get("packer_name"):
        packer_label = str(audit.scan["packer_name"])
        if audit.scan.get("packer_version"):
            packer_label += f" ({audit.scan['packer_version']})"
        protection_label = str(audit.scan.get("protection_level") or "unknown")
        confidence_pct = f"{float(audit.scan.get('confidence') or 0.0):.0%}"

    coverage_str = "—"
    dex_count_str = "—"
    methods_str = "—"
    if audit.quality:
        coverage_str = f"{float(audit.quality.get('code_coverage') or 0.0):.1%}"
        dex_count_str = f"{int(audit.quality.get('dex_count') or 0):,}"
        methods_str = f"{int(audit.quality.get('total_methods') or 0):,}"
    elif audit.inspect and audit.inspect.get("dex_files"):
        dex_count_str = f"{len(audit.inspect['dex_files']):,}"

    # Findings HTML cards
    if audit.findings:
        finding_cards: list[str] = []
        for f in audit.findings:
            ev_html = ""
            if f.evidence:
                ev_items = "".join(f"<li><code>{_esc(e)}</code></li>" for e in f.evidence[:20])
                ev_html = f'<div class="finding-sub"><strong>Evidence</strong><ul>{ev_items}</ul></div>'
            rem_html = ""
            if f.remediation:
                rem_html = f'<div class="finding-sub"><strong>Remediation</strong><p>{_esc(f.remediation)}</p></div>'
            finding_cards.append(
                f'<article class="finding-card" data-severity="{_esc(f.severity)}" '
                f'data-search="{_esc((f.title + " " + f.rule_id + " " + f.category + " " + f.description).lower())}">'
                f'<div class="finding-head">'
                f'<span class="badge sev-{_esc(f.severity)}">{_esc(f.severity.upper())}</span>'
                f'<code class="rule-id">{_esc(f.rule_id)}</code>'
                f'<span class="finding-title">{_esc(f.title)}</span>'
                f'<span class="chip">{_esc(f.category)}</span>'
                f"</div>"
                f'<p class="finding-desc">{_esc(f.description)}</p>'
                f'<div class="finding-meta">Location: <code>{_esc(f.location or audit.target)}</code> · ID: <code>{_esc(f.id)}</code></div>'
                f"{ev_html}{rem_html}"
                f"</article>"
            )
        findings_section_body = "".join(finding_cards)
    else:
        findings_section_body = '<p class="empty">No security or unpacking findings triggered.</p>'

    # Packer breakdown section
    packer_html = ""
    if audit.scan:
        bd_rows = ""
        for b in audit.scan.get("score_breakdown") or []:
            score = float(b.get("score") or 0.0)
            mx = float(b.get("max") or 1.0)
            pct = max(0.0, min(100.0, (score / mx * 100.0) if mx > 0 else 0.0))
            hit_cls = "badge sev-low" if b.get("matched") else "badge sev-info"
            hit_txt = "HIT" if b.get("matched") else "—"
            bd_rows += (
                f"<tr><td>{_esc(b.get('dimension', ''))}</td>"
                f'<td><div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%"></div></div></td>'
                f'<td class="num">{score:.1f} / {mx:.1f}</td>'
                f'<td><span class="{hit_cls}">{hit_txt}</span></td></tr>'
            )
        sigs = audit.scan.get("matched_signatures") or []
        sigs_html = (
            '<div class="tag-row">'
            + "".join(f'<code class="tag">{_esc(s)}</code>' for s in sigs)
            + "</div>"
            if sigs
            else '<p class="muted">No signature indicators matched.</p>'
        )
        bd_table = (
            '<table class="data-table"><thead><tr><th>Dimension</th><th>Weight</th>'
            '<th class="num">Score</th><th>Status</th></tr></thead>'
            f"<tbody>{bd_rows}</tbody></table>"
            if bd_rows
            else ""
        )
        packer_html = (
            '<section class="panel"><h2>Packer Intelligence</h2>'
            f'<div class="kv-grid">'
            f'<div><span class="k">Packer</span><span class="v">{_esc(packer_label)}</span></div>'
            f'<div><span class="k">Protection Level</span><span class="v"><code>{_esc(protection_label)}</code></span></div>'
            f'<div><span class="k">Confidence</span><span class="v">{_esc(confidence_pct)}</span></div>'
            f'<div><span class="k">Application Class</span><span class="v"><code>{_esc(audit.scan.get("app_class") or "—")}</code></span></div>'
            f"</div>{sigs_html}{bd_table}</section>"
        )

    # APK static inspection section
    inspect_html = ""
    if audit.inspect:
        manifest = audit.inspect.get("manifest") or {}
        signing = audit.inspect.get("signing") or {}
        perms = audit.inspect.get("permissions") or []
        native_libs = audit.inspect.get("native_libs") or []
        dangerous_perms = [p for p in perms if isinstance(p, dict) and p.get("dangerous")]

        manifest_kv = ""
        if manifest:
            manifest_kv = (
                '<div class="kv-grid">'
                f'<div><span class="k">Package</span><span class="v"><code>{_esc(manifest.get("package_name") or "—")}</code></span></div>'
                f'<div><span class="k">Version</span><span class="v">{_esc(manifest.get("version_name") or "—")} ({_esc(manifest.get("version_code") or "—")})</span></div>'
                f'<div><span class="k">SDK (min / target)</span><span class="v">{_esc(manifest.get("min_sdk") or "—")} / {_esc(manifest.get("target_sdk") or "—")}</span></div>'
                f'<div><span class="k">Debuggable / Backup</span><span class="v">{_esc(manifest.get("debuggable"))} / {_esc(manifest.get("allow_backup"))}</span></div>'
                f'<div><span class="k">Signing Schemes</span><span class="v">{_esc(", ".join(signing.get("schemes") or []) or "—")}</span></div>'
                f'<div><span class="k">Permissions</span><span class="v">{len(perms)} total ({len(dangerous_perms)} dangerous)</span></div>'
                "</div>"
            )

        lib_table = ""
        if native_libs:
            lib_rows = ""
            for lib in native_libs[:30]:
                flags = []
                if lib.get("pie") is True:
                    flags.append("PIE")
                if lib.get("nx") is True:
                    flags.append("NX")
                if lib.get("relro"):
                    flags.append(f"RELRO:{lib['relro']}")
                if lib.get("canary") is True:
                    flags.append("CANARY")
                lib_rows += (
                    f"<tr><td><code>{_esc(lib.get('name') or lib.get('path', ''))}</code></td>"
                    f"<td>{_esc(lib.get('abi') or '—')}</td>"
                    f'<td class="num">{_esc(_fmt_bytes(lib.get("size") or lib.get("size_bytes")))}</td>'
                    f"<td>{_esc(', '.join(flags) or '—')}</td></tr>"
                )
            lib_table = (
                f'<h3>Native Libraries ({len(native_libs)})</h3>'
                '<table class="data-table"><thead><tr><th>Library</th><th>ABI</th>'
                '<th class="num">Size</th><th>ELF Mitigations</th></tr></thead>'
                f"<tbody>{lib_rows}</tbody></table>"
            )
        inspect_html = f'<section class="panel"><h2>APK Static Profile</h2>{manifest_kv}{lib_table}</section>'

    # DEX Quality + Method Composition Donut
    quality_html = ""
    if audit.quality or audit.vmp:
        donut_svg = ""
        if audit.vmp and int(audit.vmp.get("total_methods") or 0) > 0:
            donut_svg = _svg_method_donut(
                int(audit.vmp.get("normal_count") or 0),
                int(audit.vmp.get("nop_count") or 0),
                int(audit.vmp.get("vmp_count") or 0),
                0,
            )
        elif audit.quality and int(audit.quality.get("total_methods") or 0) > 0:
            with_code = int(audit.quality.get("methods_with_code") or 0)
            nop = int(audit.quality.get("nop_methods") or 0)
            empty = int(audit.quality.get("empty_methods") or 0)
            donut_svg = _svg_method_donut(max(0, with_code - nop), nop, 0, empty)

        per_dex_html = ""
        if audit.quality and audit.quality.get("per_dex"):
            rows = ""
            for d in audit.quality["per_dex"]:
                m_total = int(d.get("methods") or 0)
                m_code = int(d.get("methods_with_code") or 0)
                m_nop = int(d.get("nop_methods") or 0)
                cov = (m_code / m_total) if m_total else 0.0
                rows += (
                    f"<tr><td><code>{_esc(d.get('file', ''))}</code></td>"
                    f'<td class="num">{_esc(_fmt_bytes(d.get("file_size")))}</td>'
                    f'<td class="num">{int(d.get("classes") or 0):,}</td>'
                    f'<td class="num">{m_total:,}</td>'
                    f'<td class="num">{m_code:,}</td>'
                    f'<td class="num">{m_nop:,}</td>'
                    f'<td class="num">{cov:.1%}</td></tr>'
                )
            per_dex_html = (
                '<div class="table-toolbar"><input id="dexSearch" class="search-input" '
                'type="search" placeholder="Filter DEX files..." aria-label="Filter DEX files" /></div>'
                '<table class="data-table" id="dexTable"><thead><tr><th>DEX File</th>'
                '<th class="num">Size</th><th class="num">Classes</th><th class="num">Methods</th>'
                '<th class="num">With Code</th><th class="num">NOP</th><th class="num">Coverage</th>'
                f"</tr></thead><tbody>{rows}</tbody></table>"
            )
        quality_html = (
            '<section class="panel"><h2>DEX Quality &amp; Method Health</h2>'
            f"{donut_svg}{per_dex_html}</section>"
        )

    # Verification & Repair section
    verify_html = ""
    if audit.verify_results or audit.repair_results:
        v_rows = ""
        for v in audit.verify_results:
            ok = bool(v.get("valid"))
            badge = '<span class="badge sev-pass">PASS</span>' if ok else '<span class="badge sev-high">FAIL</span>'
            issues = "; ".join(str(x) for x in (v.get("issues") or [])) or "No issues"
            v_rows += (
                f"<tr><td><code>{_esc(v.get('file', ''))}</code></td>"
                f"<td>{badge}</td><td>{_esc(issues)}</td></tr>"
            )
        r_rows = ""
        for r in audit.repair_results:
            ok = bool(r.get("success", True))
            badge = '<span class="badge sev-pass">OK</span>' if ok else '<span class="badge sev-high">FAIL</span>'
            actions = ", ".join(str(x) for x in (r.get("actions") or [])) or "—"
            r_rows += (
                f"<tr><td><code>{_esc(r.get('file', ''))}</code></td>"
                f"<td>{badge}</td><td>{_esc(actions)}</td>"
                f'<td class="num">{int(r.get("nop_methods") or r.get("nop_method_count") or 0):,}</td></tr>'
            )
        v_block = (
            '<h3>Integrity Verification</h3><table class="data-table">'
            "<thead><tr><th>File</th><th>Status</th><th>Details</th></tr></thead>"
            f"<tbody>{v_rows}</tbody></table>"
            if v_rows
            else ""
        )
        r_block = (
            '<h3>Repair Actions</h3><table class="data-table">'
            '<thead><tr><th>File</th><th>Status</th><th>Actions</th><th class="num">NOP</th></tr></thead>'
            f"<tbody>{r_rows}</tbody></table>"
            if r_rows
            else ""
        )
        verify_html = f'<section class="panel"><h2>Verification &amp; Repair</h2>{v_block}{r_block}</section>'

    # Recommendations section
    rec_items = "".join(f"<li>{_esc(rec)}</li>" for rec in audit.recommendations)
    rec_html = f'<section class="panel"><h2>Actionable Recommendations</h2><ol class="rec-list">{rec_items}</ol></section>'

    sha_pill = (
        f'<span class="meta-pill">SHA-256: <code>{_esc(audit.target_sha256[:16])}…</code></span>'
        if audit.target_sha256
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{_esc(audit.title)}</title>
<style>
:root {{
  --bg: #0b0e14;
  --surface: #121720;
  --surface-2: #18202c;
  --border: #263143;
  --text: #e6edf3;
  --muted: #8b98a9;
  --accent: #38bdf8;
  --ok: #10b981;
  --warn: #f59e0b;
  --fail: #ef4444;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
}}
[data-theme="light"] {{
  --bg: #f6f8fa;
  --surface: #ffffff;
  --surface-2: #f1f5f9;
  --border: #d8dee6;
  --text: #0f172a;
  --muted: #526071;
  --accent: #0284c7;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  line-height: 1.55;
  font-size: 14px;
}}
.container {{ max-width: 1120px; margin: 0 auto; padding: 28px 24px 56px; }}
.topbar {{
  display: flex; justify-content: space-between; align-items: flex-start; gap: 20px;
  padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 24px;
}}
.brand {{ font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--accent); font-weight: 700; }}
h1 {{ margin: 4px 0 8px; font-size: 22px; font-weight: 700; letter-spacing: -0.01em; }}
h2 {{ margin: 0 0 14px; font-size: 15px; font-weight: 600; letter-spacing: 0.01em; }}
h3 {{ margin: 18px 0 10px; font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }}
.meta-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }}
.meta-pill {{
  font-size: 12px; color: var(--muted); background: var(--surface); border: 1px solid var(--border);
  padding: 3px 9px; border-radius: 6px;
}}
.top-actions {{ display: flex; align-items: center; gap: 14px; }}
.btn {{
  background: var(--surface); color: var(--text); border: 1px solid var(--border);
  padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 500;
}}
.btn:hover {{ border-color: var(--accent); }}
.summary-banner {{
  background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--accent);
  border-radius: 8px; padding: 14px 16px; margin-bottom: 20px; color: var(--text);
}}
.kpi-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 22px;
}}
.kpi {{
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px;
}}
.kpi-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }}
.kpi-value {{ font-size: 20px; font-weight: 700; margin-top: 4px; font-variant-numeric: tabular-nums; }}
.kpi-sub {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}
.panel {{
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 18px 20px; margin-bottom: 18px;
}}
.kv-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 14px;
}}
.kv-grid .k {{ display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }}
.kv-grid .v {{ display: block; font-size: 13px; font-weight: 500; margin-top: 2px; word-break: break-word; }}
code {{ font-family: var(--mono); font-size: 12px; background: var(--surface-2); padding: 1px 5px; border-radius: 4px; }}
.tag-row {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }}
.tag {{ border: 1px solid var(--border); padding: 2px 7px; }}
.data-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.data-table th, .data-table td {{
  padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top;
}}
.data-table th {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); font-weight: 600; }}
.data-table .num {{ text-align: right; font-variant-numeric: tabular-nums; font-family: var(--mono); }}
.bar-track {{ width: 140px; height: 7px; background: var(--surface-2); border-radius: 99px; overflow: hidden; }}
.bar-fill {{ height: 100%; background: var(--accent); border-radius: 99px; }}
.badge {{
  display: inline-block; font-size: 10px; font-weight: 700; letter-spacing: 0.06em;
  padding: 2px 7px; border-radius: 4px; font-family: var(--mono);
}}
.sev-critical {{ background: rgba(239, 68, 68, 0.22); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.45); }}
.sev-high {{ background: rgba(249, 115, 22, 0.18); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
.sev-medium {{ background: rgba(245, 158, 11, 0.16); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); }}
.sev-low {{ background: rgba(56, 189, 248, 0.14); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }}
.sev-info {{ background: var(--surface-2); color: var(--muted); border: 1px solid var(--border); }}
.sev-pass {{ background: rgba(16, 185, 129, 0.16); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35); }}
.toolbar {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; margin-bottom: 14px; }}
.pill-group {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.pill {{
  background: var(--surface-2); color: var(--muted); border: 1px solid var(--border);
  padding: 4px 10px; border-radius: 99px; font-size: 12px; cursor: pointer;
}}
.pill.active {{ background: var(--accent); color: #06131f; border-color: var(--accent); font-weight: 600; }}
.search-input {{
  background: var(--surface-2); color: var(--text); border: 1px solid var(--border);
  padding: 6px 10px; border-radius: 6px; font-size: 12px; min-width: 220px;
}}
.finding-card {{
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
  padding: 13px 15px; margin-bottom: 10px;
}}
.finding-head {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 6px; }}
.finding-title {{ font-weight: 600; }}
.rule-id {{ color: var(--muted); }}
.chip {{
  margin-left: auto; font-size: 11px; color: var(--muted);
  border: 1px solid var(--border); padding: 1px 7px; border-radius: 99px;
}}
.finding-desc {{ margin: 4px 0 8px; color: var(--text); }}
.finding-meta {{ font-size: 12px; color: var(--muted); }}
.finding-sub {{ margin-top: 8px; font-size: 12.5px; }}
.finding-sub ul {{ margin: 4px 0 0; padding-left: 18px; }}
.finding-sub p {{ margin: 4px 0 0; color: var(--muted); }}
.donut-wrap {{ display: flex; flex-wrap: wrap; align-items: center; gap: 24px; margin-bottom: 16px; }}
.legend {{ display: flex; flex-direction: column; gap: 6px; }}
.legend-item {{ display: flex; align-items: center; gap: 8px; font-size: 13px; }}
.dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
.muted {{ color: var(--muted); }}
.empty {{ color: var(--muted); font-style: italic; }}
.table-toolbar {{ margin-bottom: 10px; display: flex; justify-content: flex-end; }}
.rec-list {{ margin: 0; padding-left: 20px; }}
.rec-list li {{ margin-bottom: 6px; }}
footer {{ margin-top: 28px; text-align: center; font-size: 12px; color: var(--muted); }}
@media print {{
  body {{ background: #ffffff; color: #0f172a; }}
  .btn, .toolbar, .table-toolbar {{ display: none !important; }}
  .panel, .kpi, .finding-card {{ break-inside: avoid; background: #ffffff; border-color: #cbd5e1; }}
}}
</style>
</head>
<body>
<div class="container">
  <header class="topbar">
    <div>
      <div class="brand">UNPACK · Security &amp; Reverse-Engineering Audit</div>
      <h1>{_esc(audit.title)}</h1>
      <div class="meta-row">
        <span class="meta-pill">Target: <code>{_esc(audit.target)}</code></span>
        {sha_pill}
        <span class="meta-pill">Generated: {_esc(audit.generated_at)}</span>
        <span class="meta-pill">UNPACK v{_esc(audit.tool_version)}</span>
      </div>
    </div>
    <div class="top-actions">
      {_svg_risk_gauge(audit.risk_score, audit.grade)}
      <button class="btn" id="themeToggle" type="button">Toggle Theme</button>
    </div>
  </header>

  <div class="summary-banner">{_esc(audit.executive_summary)}</div>

  <section class="kpi-grid">
    <div class="kpi"><div class="kpi-label">Packer</div><div class="kpi-value">{_esc(packer_label)}</div><div class="kpi-sub">Level: {_esc(protection_label)} ({_esc(confidence_pct)})</div></div>
    <div class="kpi"><div class="kpi-label">Code Coverage</div><div class="kpi-value">{_esc(coverage_str)}</div><div class="kpi-sub">DEX files: {_esc(dex_count_str)}</div></div>
    <div class="kpi"><div class="kpi-label">Methods</div><div class="kpi-value">{_esc(methods_str)}</div><div class="kpi-sub">Risk Score: {audit.risk_score}/100</div></div>
    <div class="kpi"><div class="kpi-label">Findings</div><div class="kpi-value">{len(audit.findings)}</div><div class="kpi-sub">Crit/High: {counts['critical'] + counts['high']} · Med: {counts['medium']}</div></div>
  </section>

  <section class="panel">
    <h2>Findings Explorer ({len(audit.findings)})</h2>
    <div class="toolbar">
      <div class="pill-group" id="sevFilters">
        <button class="pill active" data-sev="all" type="button">All ({len(audit.findings)})</button>
        <button class="pill" data-sev="critical" type="button">Critical ({counts['critical']})</button>
        <button class="pill" data-sev="high" type="button">High ({counts['high']})</button>
        <button class="pill" data-sev="medium" type="button">Medium ({counts['medium']})</button>
        <button class="pill" data-sev="low" type="button">Low ({counts['low']})</button>
        <button class="pill" data-sev="info" type="button">Info ({counts['info']})</button>
      </div>
      <input id="findingSearch" class="search-input" type="search" placeholder="Search findings..." aria-label="Search findings" />
    </div>
    <div id="findingsList">{findings_section_body}</div>
  </section>

  {packer_html}
  {inspect_html}
  {quality_html}
  {verify_html}
  {rec_html}

  <footer>Generated offline by UNPACK v{_esc(audit.tool_version)} · Schema v{_esc(audit.schema_version)}</footer>
</div>
<script>
(function() {{
  var root = document.documentElement;
  var toggle = document.getElementById("themeToggle");
  if (toggle) {{
    toggle.addEventListener("click", function() {{
      root.setAttribute("data-theme", root.getAttribute("data-theme") === "dark" ? "light" : "dark");
    }});
  }}
  var activeSev = "all";
  var searchEl = document.getElementById("findingSearch");
  var cards = Array.prototype.slice.call(document.querySelectorAll(".finding-card"));
  function applyFilters() {{
    var q = (searchEl ? searchEl.value : "").trim().toLowerCase();
    cards.forEach(function(card) {{
      var sevOk = activeSev === "all" || card.getAttribute("data-severity") === activeSev;
      var qOk = !q || (card.getAttribute("data-search") || "").indexOf(q) !== -1;
      card.style.display = (sevOk && qOk) ? "" : "none";
    }});
  }}
  var pills = document.querySelectorAll("#sevFilters .pill");
  pills.forEach(function(btn) {{
    btn.addEventListener("click", function() {{
      pills.forEach(function(b) {{ b.classList.remove("active"); }});
      btn.classList.add("active");
      activeSev = btn.getAttribute("data-sev") || "all";
      applyFilters();
    }});
  }});
  if (searchEl) searchEl.addEventListener("input", applyFilters);
  var dexSearch = document.getElementById("dexSearch");
  var dexTable = document.getElementById("dexTable");
  if (dexSearch && dexTable) {{
    dexSearch.addEventListener("input", function() {{
      var q = dexSearch.value.trim().toLowerCase();
      Array.prototype.slice.call(dexTable.querySelectorAll("tbody tr")).forEach(function(tr) {{
        tr.style.display = !q || tr.textContent.toLowerCase().indexOf(q) !== -1 ? "" : "none";
      }});
    }});
  }}
}})();
</script>
</body>
</html>
"""


class ReportGenerator:
    """Unified multi-format report renderer (HTML, Markdown, SARIF 2.1.0, JSON)."""

    SUPPORTED_FORMATS = ("html", "markdown", "md", "sarif", "json")

    @classmethod
    def render(cls, audit: AuditReport, fmt: str) -> str:
        norm = fmt.strip().lower()
        if norm == "html":
            return render_html(audit)
        if norm in ("markdown", "md"):
            return render_markdown(audit)
        if norm == "sarif":
            return render_sarif_json(audit)
        if norm == "json":
            return render_json(audit)
        raise ValueError(
            f"Unsupported report format {fmt!r}. Supported: {', '.join(cls.SUPPORTED_FORMATS)}"
        )
