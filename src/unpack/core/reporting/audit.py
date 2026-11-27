"""Commercial audit report models, aggregation, and JSON serialization."""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from unpack import __version__
from unpack.i18n import resolve_lang, t

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

# Semantic equivalence between ApkInspector findings (APK-*) and synthesized
# fallback audit rules (UNPACK-APK-*) so findings and risk scores are never
# double-counted when real ApkInspector output is passed into build_audit_report.
_EQUIVALENT_INSPECT_RULES: dict[str, str] = {
    "APK-MANIFEST-001": "UNPACK-APK-001",
    "APK-MANIFEST-002": "UNPACK-APK-002",
    "APK-MANIFEST-003": "UNPACK-APK-003",
    "APK-SIGN-001": "UNPACK-APK-005",
}


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


# ── Normalization & Localization Helpers ─────────────────────────────────────


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


def _build_executive_summary(
    target: str,
    scan_d: dict[str, Any] | None,
    quality_d: dict[str, Any] | None,
    verify_l: list[dict[str, Any]],
    vmp_d: dict[str, Any] | None,
    findings: list[AuditFinding],
    grade: str,
    risk_score: int,
    *,
    lang: str = "en",
) -> str:
    eff = resolve_lang(lang)
    parts: list[str] = [
        t("report.exec.intro", eff, target=target, grade=grade, risk=risk_score)
    ]
    if isinstance(scan_d, dict):
        if scan_d.get("packer_name"):
            ver = f" {scan_d['packer_version']}" if scan_d.get("packer_version") else ""
            parts.append(
                t(
                    "report.exec.packer_hit",
                    eff,
                    packer=scan_d["packer_name"],
                    ver=ver,
                    level=scan_d.get("protection_level", "unknown"),
                    conf=float(scan_d.get("confidence", 0)),
                )
            )
        else:
            parts.append(t("report.exec.packer_none", eff))
    if isinstance(quality_d, dict) and quality_d.get("dex_count", 0) > 0:
        parts.append(
            t(
                "report.exec.quality",
                eff,
                dex_count=quality_d["dex_count"],
                cov=float(quality_d.get("code_coverage", 0)),
                nop=int(quality_d.get("nop_methods", 0)),
            )
        )
    if verify_l:
        passed = sum(1 for v in verify_l if v.get("valid"))
        parts.append(t("report.exec.verify", eff, passed=passed, total=len(verify_l)))
    if isinstance(vmp_d, dict) and vmp_d.get("total_methods", 0) > 0:
        parts.append(t("report.exec.vmp", eff, vmp=int(vmp_d.get("vmp_count", 0))))
    if findings:
        high_plus = sum(1 for f in findings if f.severity in ("critical", "high"))
        parts.append(t("report.exec.findings", eff, total=len(findings), high_plus=high_plus))
    sep = "" if eff == "zh" else " "
    return sep.join(parts)


def _localized_report_title(audit: AuditReport, lang: str) -> str:
    en_default = f"UNPACK Audit Report — {audit.target}"
    if lang == "zh" and audit.title in (en_default, "UNPACK Mobile Security & Unpacking Audit"):
        return t("report.default_title", "zh", target=audit.target)
    return audit.title


def _localized_exec_summary(audit: AuditReport, lang: str) -> str:
    if lang == "zh" and audit.executive_summary.startswith("Automated security & unpacking assessment"):
        return _build_executive_summary(
            audit.target,
            audit.scan,
            audit.quality,
            audit.verify_results,
            audit.vmp,
            audit.findings,
            audit.grade,
            audit.risk_score,
            lang="zh",
        )
    return audit.executive_summary


def _localized_recommendations(audit: AuditReport, lang: str) -> list[str]:
    en_default = t("report.default_rec", "en")
    if lang == "zh":
        return [
            t("report.default_rec", "zh") if r == en_default else r
            for r in audit.recommendations
        ]
    return list(audit.recommendations)


def _sev_label(sev: str, lang: str) -> str:
    key = f"report.sev.{(sev or 'info').lower()}"
    if lang == "zh":
        return t(key, "zh")
    return (sev or "info").upper()


# ── Audit Bundle Builder ─────────────────────────────────────────────────────


def build_audit_report(
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
    lang: str = "en",
) -> AuditReport:
    """Assemble a complete commercial ``AuditReport`` from any subset of stage outputs."""
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
    covered_rules: set[str] = set()
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
        covered_rules.add(rule_id)
        equiv = _EQUIVALENT_INSPECT_RULES.get(rule_id)
        if equiv:
            covered_rules.add(equiv)
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

    # 2. APK inspection findings (import core findings + synthesize missing fallback checks)
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
            if manifest.get("debuggable") is True and "UNPACK-APK-001" not in covered_rules:
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
            if manifest.get("allow_backup") is True and "UNPACK-APK-002" not in covered_rules:
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
            if manifest.get("uses_cleartext_traffic") is True and "UNPACK-APK-003" not in covered_rules:
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
        if isinstance(signing, dict) and signing.get("is_debug_cert") and "UNPACK-APK-005" not in covered_rules:
            certs = signing.get("certificates") or []
            cert_subj = (
                certs[0].get("subject")
                if certs and isinstance(certs[0], dict)
                else None
            )
            add_finding(
                "UNPACK-APK-005",
                "APK signed with Android debug certificate",
                "high",
                "apk_security",
                "Debug signing keys are publicly known and must not be shipped to production.",
                evidence=[str(signing.get("subject") or cert_subj or "CN=Android Debug")],
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
            f"{m.get('class_name') or m.get('class') or ''}->{m.get('method_name') or m.get('method') or ''}"
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
        risk_score = min(100, max(computed_risk, int(round(inspect_d["risk_score"]))))
    else:
        risk_score = computed_risk

    eff_lang = resolve_lang(lang)
    grade = _score_to_grade(risk_score)
    exec_summary = _build_executive_summary(
        target_str, scan_d, quality_d, verify_l, vmp_d, findings, grade, risk_score, lang=eff_lang
    )

    if not recommendations:
        recommendations.append(t("report.default_rec", eff_lang))

    default_title = t("report.default_title", eff_lang, target=target_str)
    return AuditReport(
        target=target_str,
        title=title or default_title,
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


def render_json(audit: AuditReport) -> str:
    """Render an ``AuditReport`` as formatted JSON."""
    return json.dumps(audit.to_dict(), indent=2, ensure_ascii=False)


__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "SEVERITY_ORDER",
    "SEVERITY_WEIGHTS",
    "SARIF_LEVEL_MAP",
    "SARIF_SECURITY_SEVERITY",
    "AuditFinding",
    "AuditReport",
    "build_audit_report",
    "render_json",
    "_fmt_bytes",
    "_localized_exec_summary",
    "_localized_recommendations",
    "_localized_report_title",
    "_sev_label",
]
