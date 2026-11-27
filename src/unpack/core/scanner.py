from __future__ import annotations

import re
import struct
import warnings
import zipfile
from contextlib import ExitStack
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from unpack.core.signatures import PACKER_SIGNATURES, PackerSignature, _PackerSig
from unpack.logging_config import get_logger
from unpack.utils.apk import silence_androguard_logs

logger = get_logger(__name__)


class ProtectionLevel(Enum):
    NONE = "none"
    DEX_ENCRYPTION = "dex_encryption"
    FUNCTION_EXTRACTION = "function_extraction"
    VMP = "vmp"
    DEX2C = "dex2c"
    UNKNOWN = "unknown"


@dataclass
class EvidenceItem:
    """Single explainable piece of packer detection evidence."""

    dimension: str
    indicator: str
    location: str
    weight: float
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "indicator": self.indicator,
            "location": self.location,
            "weight": round(self.weight, 2),
            "detail": self.detail,
        }


@dataclass
class ScanResult:
    packer_name: str | None = None
    packer_version: str | None = None
    confidence: float = 0.0
    protection_level: ProtectionLevel = ProtectionLevel.NONE
    matched_signatures: list[str] = field(default_factory=list)
    details: str = ""

    score_breakdown: list[dict] = field(default_factory=list)
    apk_info: dict[str, Any] = field(default_factory=dict)
    all_so_files: list[str] = field(default_factory=list)
    all_so_by_abi: dict[str, list[str]] = field(default_factory=dict)
    all_dex_info: list[dict] = field(default_factory=list)
    suspicious_assets: list[str] = field(default_factory=list)
    app_class: str | None = None
    all_candidates: list[dict] = field(default_factory=list)

    # Commercial intelligence fields (additive, backward-compatible)
    evidence: list[EvidenceItem] = field(default_factory=list)
    recommended_engine: str = "memory"
    recommended_flags: list[str] = field(default_factory=list)
    strategy_reason: str = ""
    heuristic_anomalies: list[str] = field(default_factory=list)
    risk_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "packer_name": self.packer_name,
            "packer_version": self.packer_version,
            "confidence": round(self.confidence, 3),
            "protection_level": self.protection_level.value,
            "matched_signatures": self.matched_signatures,
            "details": self.details,
        }

    def to_verbose_dict(self) -> dict[str, Any]:
        d = self.to_dict()
        d["score_breakdown"] = self.score_breakdown
        d["apk_info"] = self.apk_info
        d["app_class"] = self.app_class
        d["all_so_files"] = self.all_so_files
        d["all_so_by_abi"] = self.all_so_by_abi
        d["all_dex_info"] = self.all_dex_info
        d["suspicious_assets"] = self.suspicious_assets
        d["all_candidates"] = self.all_candidates
        d["evidence"] = [e.to_dict() for e in self.evidence]
        d["recommended_engine"] = self.recommended_engine
        d["recommended_flags"] = self.recommended_flags
        d["strategy_reason"] = self.strategy_reason
        d["heuristic_anomalies"] = self.heuristic_anomalies
        d["risk_score"] = self.risk_score
        return d

    def to_detailed_dict(self) -> dict[str, Any]:
        """Alias returning full explainable intelligence payload."""
        return self.to_verbose_dict()

    def to_report(self) -> str:
        lines = []
        lines.append("=" * 72)
        lines.append("UNPACK SCAN REPORT")
        lines.append("=" * 72)

        if self.apk_info:
            lines.append(f"\n## APK Info")
            lines.append(f"  Package:    {self.apk_info.get('package', 'unknown')}")
            lines.append(f"  File:       {self.apk_info.get('filename', 'unknown')}")
            lines.append(f"  Size:       {self.apk_info.get('size_mb', 0):.1f} MB")
            lines.append(f"  DEX count:  {self.apk_info.get('dex_count', 0)}")
            lines.append(f"  SO count:   {self.apk_info.get('so_count', 0)}")

        lines.append(f"\n## Detection Result")
        if self.packer_name:
            lines.append(f"  Packer:     {self.packer_name}")
            if self.packer_version:
                lines.append(f"  Version:    {self.packer_version}")
            lines.append(f"  Confidence: {self.confidence:.0%}")
            lines.append(f"  Protection: {self.protection_level.value}")
            lines.append(f"  Signatures: {', '.join(self.matched_signatures)}")
        else:
            lines.append(f"  Result:     No known packer detected")
            lines.append(f"  Note:       {self.details}")

        if self.score_breakdown:
            lines.append(f"\n## Confidence Breakdown")
            lines.append(f"  {'Dimension':<24s} {'Score':>5s} {'Max':>5s}  Status")
            lines.append(f"  {'-'*24} {'-'*5} {'-'*5}  {'-'*8}")
            for b in self.score_breakdown:
                status = "HIT" if b["matched"] else "-"
                lines.append(f"  {b['dimension']:<24s} {b['score']:>5.1f} {b['max']:>5.1f}  {status}")
            total = sum(b["score"] for b in self.score_breakdown)
            total_max = sum(b["max"] for b in self.score_breakdown)
            lines.append(f"  {'TOTAL':<24s} {total:>5.1f} {total_max:>5.1f}  confidence={total/total_max:.0%}")

        if self.app_class:
            lines.append(f"\n## Application Class")
            lines.append(f"  {self.app_class}")

        if self.all_so_files:
            lines.append(f"\n## Native Libraries ({len(self.all_so_files)} SO files)")
            for so in self.all_so_files:
                lines.append(f"  - {so}")

        if self.all_dex_info:
            lines.append(f"\n## DEX Files")
            for d in self.all_dex_info:
                lines.append(f"  - {d['name']}: {d['size_kb']:.0f}KB, {d['classes']} classes")

        if self.suspicious_assets:
            lines.append(f"\n## Suspicious Assets")
            for a in self.suspicious_assets:
                lines.append(f"  - {a}")

        if self.all_candidates:
            lines.append(f"\n## All Packer Candidates")
            for c in self.all_candidates:
                lines.append(f"  - {c['name']}: score={c['score']:.1f}, sigs={c['signatures']}")

        lines.append(f"\n## Analysis Hints")
        if self.packer_name:
            sig = PACKER_SIGNATURES.get(self.packer_name)
            if sig:
                lines.append(f"  Known SO indicators:    {sig.so_files}")
                lines.append(f"  Known app classes:      {sig.app_classes}")
                lines.append(f"  VMP indicators:         {sig.vmp_indicators or 'none'}")
                lines.append(f"  DEX2C indicators:       {sig.dex2c_indicators or 'none'}")
                if sig.version_hints:
                    lines.append(f"  Version hints:")
                    for indicator, ver in sig.version_hints:
                        lines.append(f"    {indicator} → {ver}")

            if self.protection_level == ProtectionLevel.VMP:
                lines.append(f"\n  [!] VMP protection detected — bytecode has been virtualized.")
                lines.append(f"      Automatic unpacking is not possible.")
                lines.append(f"      Manual analysis required: dump VMP interpreter, extract PCode,")
                lines.append(f"      reverse handler dispatch table.")
            elif self.protection_level == ProtectionLevel.DEX2C:
                lines.append(f"\n  [!] DEX2C protection detected — Java methods compiled to native.")
                lines.append(f"      Original DEX code has been destroyed.")
                lines.append(f"      Analyze the corresponding SO file with IDA/Ghidra.")
            elif self.protection_level == ProtectionLevel.FUNCTION_EXTRACTION:
                lines.append(f"\n  [*] Function extraction detected — method bodies are NOP-filled")
                lines.append(f"      at rest and restored at runtime. Use FART-style active invocation")
                lines.append(f"      or wait for runtime decryption then memory dump.")
            elif self.protection_level == ProtectionLevel.DEX_ENCRYPTION:
                lines.append(f"\n  [*] DEX encryption detected — standard memory dump should work.")
                lines.append(f"      Use frida-dexdump style memory scan or eBPF uprobe.")
        else:
            lines.append(f"  App may use custom protection (non-commercial packer),")
            lines.append(f"  or may not be packed at all.")
            if self.all_so_files:
                sec_sos = [s for s in self.all_so_files if any(
                    k in s.lower() for k in ['secure', 'protect', 'shield', 'safe', 'guard', 'crypt', 'hook']
                )]
                if sec_sos:
                    lines.append(f"  Security-related SOs found (possible custom protection):")
                    for s in sec_sos:
                        lines.append(f"    - {s}")

        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Manifest extraction (androguard optional)
# ---------------------------------------------------------------------------

_ALL_APP_CLASS_PATTERNS: list[bytes] = []


def _build_app_class_patterns() -> list[bytes]:
    if _ALL_APP_CLASS_PATTERNS:
        return _ALL_APP_CLASS_PATTERNS
    seen: set[str] = set()
    for sig in PACKER_SIGNATURES.values():
        for cls in sig.app_classes:
            if cls in seen:
                continue
            seen.add(cls)
            escaped = re.escape(cls).encode()
            _ALL_APP_CLASS_PATTERNS.append(escaped)
    return _ALL_APP_CLASS_PATTERNS


def _extract_application_class(apk_zip: zipfile.ZipFile) -> str | None:
    try:
        silence_androguard_logs()
        from androguard.core.apk import APK as AndroAPK
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            a = AndroAPK(apk_zip.filename)
            return a.get_attribute_value("application", "name")
    except Exception as exc:
        logger.debug("Androguard application class extraction failed for %s: %s", apk_zip.filename, exc)
    return _extract_application_class_binary(apk_zip)


def _extract_application_class_binary(apk_zip: zipfile.ZipFile) -> str | None:
    try:
        raw = apk_zip.read("AndroidManifest.xml")
    except KeyError:
        return None
    for pattern in _build_app_class_patterns():
        m = re.search(pattern, raw)
        if m:
            try:
                return m.group(0).decode("utf-8", errors="ignore")
            except Exception as exc:
                logger.debug("Failed to decode matched app class pattern: %s", exc)
    return None


# ---------------------------------------------------------------------------
# DEX header helpers
# ---------------------------------------------------------------------------

_DEX_MAGIC = b"dex\n"


def _count_dex_classes(data: bytes) -> int | None:
    if len(data) < 100 or data[:4] != _DEX_MAGIC:
        return None
    try:
        class_defs_size = struct.unpack_from("<I", data, 96)[0]
        return class_defs_size
    except struct.error:
        return None


# ---------------------------------------------------------------------------
# SO export analysis (builtin ELF + optional LIEF via NativeAnalyzer)
# ---------------------------------------------------------------------------

def _check_so_exports(apk_zip: zipfile.ZipFile, so_entry: str) -> list[str]:
    indicators: list[str] = []
    try:
        data = apk_zip.read(so_entry)
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        logger.debug("Failed to read SO entry %s: %s", so_entry, exc)
        return indicators

    try:
        from unpack.analysis.native import NativeAnalyzer
        info = NativeAnalyzer().analyze_bytes(data, name=so_entry.rsplit("/", 1)[-1], path=so_entry)
        for sym in info.vmp_indicators:
            indicators.append(f"vmp_export:{sym}")
        for sym in info.dex2c_indicators:
            indicators.append(f"dex2c_export:{sym}")
    except Exception as exc:
        logger.debug("Native export analysis failed for %s: %s", so_entry, exc)
    return indicators


# ---------------------------------------------------------------------------
# PackerScanner
# ---------------------------------------------------------------------------

_WEIGHT_SO = 3.0
_WEIGHT_ASSET = 2.0
_WEIGHT_APP_CLASS = 4.0
_WEIGHT_DEX_PREFIX = 2.0
_WEIGHT_CERT = 1.0
_WEIGHT_SMALL_DEX = 1.5


def _recommend_strategy(
    packer_name: str | None,
    protection_level: ProtectionLevel,
) -> tuple[str, list[str], str, int]:
    """Return (recommended_engine, recommended_flags, strategy_reason, risk_score)."""
    if not packer_name or protection_level == ProtectionLevel.NONE:
        return (
            "memory",
            [],
            "No commercial packer detected; static inspection or JADX decompilation can proceed directly.",
            10,
        )
    if protection_level == ProtectionLevel.DEX_ENCRYPTION:
        return (
            "memory",
            ["-e", "memory"],
            "DEX encryption packer — zero-injection /proc/<pid>/mem dump reliably captures decrypted DEX.",
            50,
        )
    if protection_level == ProtectionLevel.FUNCTION_EXTRACTION:
        return (
            "memory",
            ["-e", "memory", "--deep"],
            "Function-extraction packer — dump skeleton via memory/eBPF then recover NOP bodies with --deep or `unpack rescan`.",
            70,
        )
    if protection_level == ProtectionLevel.VMP:
        return (
            "ebpf",
            ["-e", "ebpf", "--deep"],
            "VMP bytecode virtualization detected — automatic unpack recovers non-VMP classes only; analyze dispatcher stubs with `unpack vmp` and native SO.",
            90,
        )
    if protection_level == ProtectionLevel.DEX2C:
        return (
            "ebpf",
            ["-e", "ebpf"],
            "DEX2C native compilation detected — Java methods are compiled to native .so; dump remaining DEX and analyze native ELF with IDA/Ghidra.",
            85,
        )
    return (
        "memory",
        ["-e", "memory"],
        "Unknown protection level — start with zero-injection memory dump.",
        40,
    )


class PackerScanner:
    def scan(self, apk_path: Path, verbose: bool = False, extra_apks: list[Path] | None = None) -> ScanResult:
        if not zipfile.is_zipfile(apk_path):
            return ScanResult(details="Not a valid ZIP/APK file")

        with ExitStack() as stack:
            zf = stack.enter_context(zipfile.ZipFile(apk_path, "r"))
            entries = set(zf.namelist())

            extra_zfs: list[zipfile.ZipFile] = []
            if extra_apks:
                for ep in extra_apks:
                    try:
                        ezf = stack.enter_context(zipfile.ZipFile(ep, "r"))
                        entries.update(ezf.namelist())
                        extra_zfs.append(ezf)
                    except (zipfile.BadZipFile, OSError) as exc:
                        logger.debug("Skipping unreadable split APK %s: %s", ep, exc)
                        continue

            all_zfs = [zf] + extra_zfs

            # Cache manifest Application class extraction ONCE per ZIP instead of
            # repeating AndroAPK parsing inside the 24-vendor loop.
            cached_app_classes: list[str] = []
            for azf in all_zfs:
                cls = _extract_application_class(azf)
                if cls:
                    cached_app_classes.append(cls)

            # Pre-read DEX buffers once for fast prefix scanning
            dex_blobs: list[tuple[str, bytes]] = []
            for azf in all_zfs:
                for e in azf.namelist():
                    if e.endswith(".dex"):
                        try:
                            dex_blobs.append((e, azf.read(e)))
                        except Exception as exc:
                            logger.debug("Failed reading DEX entry %s: %s", e, exc)
                            continue

            # Pre-compute small-DEX heuristic once
            small_dex_info: tuple[int, int] | None = None
            if "classes.dex" in entries:
                info = zf.getinfo("classes.dex")
                if info.file_size < 50 * 1024:
                    try:
                        data = zf.read("classes.dex")
                        nclasses = _count_dex_classes(data)
                        if nclasses is not None and nclasses < 10:
                            small_dex_info = (info.file_size, nclasses)
                    except Exception as exc:
                        logger.debug("Small-DEX heuristic failed on classes.dex: %s", exc)

            # Build basename -> full entry paths map for exact SO matching
            so_by_basename: dict[str, list[str]] = {}
            for entry in sorted(entries):
                if entry.startswith("lib/") and entry.endswith(".so"):
                    base = entry.rsplit("/", 1)[-1]
                    so_by_basename.setdefault(base, []).append(entry)

            scores: dict[str, float] = {}
            all_matches: dict[str, list[str]] = {}
            all_evidence: dict[str, list[EvidenceItem]] = {}
            dim_scores: dict[str, dict[str, float]] = {}

            for packer, sig in PACKER_SIGNATURES.items():
                score = 0.0
                matches: list[str] = []
                ev_items: list[EvidenceItem] = []
                dims: dict[str, float] = {}

                s0 = score
                score, matches = self._check_so(
                    entries, sig, score, matches,
                    so_by_basename=so_by_basename, evidence=ev_items,
                )
                if score > s0:
                    dims["so_files"] = score - s0

                s0 = score
                score, matches = self._check_assets(entries, sig, score, matches, evidence=ev_items)
                if score > s0:
                    dims["assets"] = score - s0

                s0 = score
                for app_cls in cached_app_classes:
                    score, matches = self._check_app_class_cached(
                        app_cls, sig, score, matches, evidence=ev_items,
                    )
                    if score > s0:
                        break
                if score > s0:
                    dims["app_class"] = score - s0

                has_other_signal = score > 0
                needs_dex_only = not sig.so_files and not sig.asset_files and not sig.app_classes
                if has_other_signal or needs_dex_only:
                    s0 = score
                    score, matches = self._check_dex_classes_cached(
                        dex_blobs, sig, score, matches, evidence=ev_items,
                    )
                    if score > s0:
                        dims["dex_classes"] = score - s0

                s0 = score
                score, matches = self._check_cert(entries, sig, score, matches, evidence=ev_items)
                if score > s0:
                    dims["cert"] = score - s0

                # Small-DEX heuristic only boosts a packer candidate that already
                # matched at least one vendor-specific indicator — prevents tiny
                # unprotected APKs from false-positiving on the first dict entry.
                if score > 0 and small_dex_info is not None:
                    fsize, nclasses = small_dex_info
                    score += _WEIGHT_SMALL_DEX
                    dims["small_dex"] = _WEIGHT_SMALL_DEX
                    matches.append(f"small_dex:size={fsize},classes={nclasses}")
                    ev_items.append(
                        EvidenceItem(
                            dimension="Small DEX heuristic",
                            indicator=f"classes.dex ({fsize}B, {nclasses} classes)",
                            location="classes.dex",
                            weight=_WEIGHT_SMALL_DEX,
                            detail="Stub-sized primary DEX consistent with packed application",
                        )
                    )

                if score > 0:
                    scores[packer] = score
                    all_matches[packer] = matches
                    all_evidence[packer] = ev_items
                    dim_scores[packer] = dims

            max_possible = (
                _WEIGHT_SO + _WEIGHT_ASSET + _WEIGHT_APP_CLASS
                + _WEIGHT_DEX_PREFIX + _WEIGHT_CERT + _WEIGHT_SMALL_DEX
            )

            anomalies: list[str] = []
            if small_dex_info is not None and not scores:
                anomalies.append(
                    f"Tiny primary classes.dex ({small_dex_info[0]} bytes, {small_dex_info[1]} classes) — possible custom packer"
                )

            if not scores:
                rec_eng, rec_flags, rec_reason, rscore = _recommend_strategy(None, ProtectionLevel.NONE)
                result = ScanResult(
                    protection_level=ProtectionLevel.NONE,
                    details="No known packer signatures found",
                    recommended_engine=rec_eng,
                    recommended_flags=rec_flags,
                    strategy_reason=rec_reason,
                    heuristic_anomalies=anomalies,
                    risk_score=rscore if not anomalies else 30,
                )
            else:
                # Deterministic tie-breaker: highest score, then most evidence items, then name
                best = max(
                    scores,
                    key=lambda k: (scores[k], len(all_evidence.get(k, [])), -list(PACKER_SIGNATURES).index(k)),
                )
                best_score = scores[best]
                confidence = min(best_score / max_possible, 1.0)
                protection = self._determine_protection_level(zf, entries, best)
                version = self._detect_version(entries, best)
                version_str = f" {version}" if version else ""

                breakdown = []
                dims = dim_scores.get(best, {})
                dim_labels = {
                    "so_files": ("SO files", _WEIGHT_SO),
                    "assets": ("Assets", _WEIGHT_ASSET),
                    "app_class": ("Application class", _WEIGHT_APP_CLASS),
                    "dex_classes": ("DEX class prefixes", _WEIGHT_DEX_PREFIX),
                    "cert": ("Certificate keywords", _WEIGHT_CERT),
                    "small_dex": ("Small DEX heuristic", _WEIGHT_SMALL_DEX),
                }
                for dim_key, (label, max_w) in dim_labels.items():
                    got = dims.get(dim_key, 0.0)
                    breakdown.append({
                        "dimension": label,
                        "score": got,
                        "max": max_w,
                        "matched": got > 0,
                    })

                rec_eng, rec_flags, rec_reason, rscore = _recommend_strategy(best, protection)
                result = ScanResult(
                    packer_name=best,
                    packer_version=version,
                    confidence=confidence,
                    protection_level=protection,
                    matched_signatures=all_matches[best],
                    score_breakdown=breakdown,
                    evidence=all_evidence.get(best, []),
                    recommended_engine=rec_eng,
                    recommended_flags=rec_flags,
                    strategy_reason=rec_reason,
                    heuristic_anomalies=anomalies,
                    risk_score=rscore,
                    details=(
                        f"Detected {best}{version_str} "
                        f"(score {best_score:.1f}/{max_possible:.1f})"
                    ),
                )

            if verbose:
                self._populate_verbose(
                    result, zf, apk_path, entries, scores, all_matches,
                    cached_app_class=cached_app_classes[0] if cached_app_classes else None,
                )

            return result

    def _populate_verbose(
        self, result: ScanResult, zf: zipfile.ZipFile,
        apk_path: Path, entries: set[str],
        scores: dict[str, float], all_matches: dict[str, list[str]],
        cached_app_class: str | None = None,
    ):
        result.apk_info = {
            "filename": apk_path.name,
            "size_mb": apk_path.stat().st_size / 1024 / 1024,
            "dex_count": sum(1 for e in entries if e.endswith(".dex")),
            "so_count": sum(1 for e in entries if e.endswith(".so")),
        }

        from unpack.utils.apk import get_package_name
        result.apk_info["package"] = get_package_name(apk_path) or "unknown"

        # Group native libs by ABI, and include all ABIs in all_so_files
        so_by_abi: dict[str, list[str]] = {}
        all_sos = sorted(e for e in entries if e.startswith("lib/") and e.endswith(".so"))
        for e in all_sos:
            parts = e.split("/")
            abi = parts[1] if len(parts) >= 3 else "unknown"
            so_by_abi.setdefault(abi, []).append(e)
        result.all_so_by_abi = so_by_abi
        # Prefer arm64-v8a if present for concise list, otherwise show all ABIs
        if "arm64-v8a" in so_by_abi:
            result.all_so_files = so_by_abi["arm64-v8a"]
        else:
            result.all_so_files = all_sos

        result.all_dex_info = []
        for e in sorted(entries):
            if not e.endswith(".dex"):
                continue
            info = zf.getinfo(e)
            data = zf.read(e)
            classes = 0
            if len(data) >= 100 and data[:4] == _DEX_MAGIC:
                classes = struct.unpack_from("<I", data, 96)[0]
            result.all_dex_info.append({
                "name": e, "size_kb": info.file_size / 1024, "classes": classes,
            })

        sus_keywords = {"shell", "jiagu", "protect", "sec", "shield", "guard",
                        "stub", "encrypt", "reinforce", "mogosec", "ijiami"}
        result.suspicious_assets = sorted(
            e for e in entries if e.startswith("assets/")
            and any(k in e.lower() for k in sus_keywords)
        )

        result.app_class = cached_app_class if cached_app_class is not None else _extract_application_class(zf)

        result.all_candidates = sorted(
            [{"name": name, "score": score, "signatures": all_matches[name]}
             for name, score in scores.items()],
            key=lambda x: x["score"], reverse=True,
        )

    def _check_so(
        self,
        entries: set[str],
        sig: _PackerSig,
        score: float,
        matches: list[str],
        so_by_basename: dict[str, list[str]] | None = None,
        evidence: list[EvidenceItem] | None = None,
    ) -> tuple[float, list[str]]:
        hit_any = False
        if so_by_basename is not None:
            for so_name in sig.so_files:
                paths = so_by_basename.get(so_name)
                if paths:
                    first = paths[0]
                    matches.append(f"so:{first}")
                    if evidence is not None:
                        evidence.append(
                            EvidenceItem(
                                dimension="SO files",
                                indicator=so_name,
                                location=first,
                                weight=_WEIGHT_SO if not hit_any else 0.0,
                                detail=f"Matched across {len(paths)} ABI(s)",
                            )
                        )
                    if not hit_any:
                        score += _WEIGHT_SO
                        hit_any = True
            return score, matches

        for so_name in sig.so_files:
            for entry in entries:
                if entry.startswith("lib/") and entry.rsplit("/", 1)[-1] == so_name:
                    score += _WEIGHT_SO
                    matches.append(f"so:{entry}")
                    return score, matches
        return score, matches

    def _check_assets(
        self,
        entries: set[str],
        sig: _PackerSig,
        score: float,
        matches: list[str],
        evidence: list[EvidenceItem] | None = None,
    ) -> tuple[float, list[str]]:
        hit_any = False
        for asset_name in sig.asset_files:
            candidate = f"assets/{asset_name}"
            if candidate in entries:
                matches.append(f"asset:{candidate}")
                if evidence is not None:
                    evidence.append(
                        EvidenceItem(
                            dimension="Assets",
                            indicator=asset_name,
                            location=candidate,
                            weight=_WEIGHT_ASSET if not hit_any else 0.0,
                            detail="Packer payload/configuration asset present",
                        )
                    )
                if not hit_any:
                    score += _WEIGHT_ASSET
                    hit_any = True
        return score, matches

    def _check_app_class_cached(
        self,
        app_class: str,
        sig: _PackerSig,
        score: float,
        matches: list[str],
        evidence: list[EvidenceItem] | None = None,
    ) -> tuple[float, list[str]]:
        if not sig.app_classes or not app_class:
            return score, matches
        for known in sig.app_classes:
            if known in app_class:
                score += _WEIGHT_APP_CLASS
                matches.append(f"app_class:{app_class}")
                if evidence is not None:
                    evidence.append(
                        EvidenceItem(
                            dimension="Application class",
                            indicator=known,
                            location="AndroidManifest.xml",
                            weight=_WEIGHT_APP_CLASS,
                            detail=f"android:name={app_class}",
                        )
                    )
                return score, matches
        return score, matches

    def _check_app_class(
        self, zf: zipfile.ZipFile, sig: _PackerSig, score: float, matches: list[str],
    ) -> tuple[float, list[str]]:
        if not sig.app_classes:
            return score, matches
        app_class = _extract_application_class(zf)
        if app_class:
            return self._check_app_class_cached(app_class, sig, score, matches)
        return score, matches

    def _check_dex_classes_cached(
        self,
        dex_blobs: list[tuple[str, bytes]],
        sig: _PackerSig,
        score: float,
        matches: list[str],
        evidence: list[EvidenceItem] | None = None,
    ) -> tuple[float, list[str]]:
        if not sig.dex_class_prefixes:
            return score, matches
        hit_any = False
        for entry, data in dex_blobs:
            for prefix in sig.dex_class_prefixes:
                if prefix.encode("utf-8") in data:
                    tag = f"dex_class:{prefix}"
                    if tag not in matches:
                        matches.append(tag)
                        if evidence is not None:
                            evidence.append(
                                EvidenceItem(
                                    dimension="DEX class prefixes",
                                    indicator=prefix,
                                    location=entry,
                                    weight=_WEIGHT_DEX_PREFIX if not hit_any else 0.0,
                                    detail=f"Stub class prefix found in {entry}",
                                )
                            )
                    if not hit_any:
                        score += _WEIGHT_DEX_PREFIX
                        hit_any = True
        return score, matches

    def _check_dex_classes(
        self, zf: zipfile.ZipFile, entries: set[str], sig: _PackerSig,
        score: float, matches: list[str],
    ) -> tuple[float, list[str]]:
        if not sig.dex_class_prefixes:
            return score, matches
        for entry in entries:
            if not entry.endswith(".dex"):
                continue
            try:
                data = zf.read(entry)
            except Exception as exc:
                logger.debug("Failed reading DEX entry %s: %s", entry, exc)
                continue
            for prefix in sig.dex_class_prefixes:
                if prefix.encode("utf-8") in data:
                    score += _WEIGHT_DEX_PREFIX
                    matches.append(f"dex_class:{prefix}")
                    return score, matches
        return score, matches

    def _check_cert(
        self,
        entries: set[str],
        sig: _PackerSig,
        score: float,
        matches: list[str],
        evidence: list[EvidenceItem] | None = None,
    ) -> tuple[float, list[str]]:
        if not sig.cert_keywords:
            return score, matches
        meta_entries = [e for e in entries if e.startswith("META-INF/")]
        meta_lower = " ".join(meta_entries).lower()
        for kw in sig.cert_keywords:
            if kw.lower() in meta_lower:
                score += _WEIGHT_CERT
                matches.append(f"cert_keyword:{kw}")
                if evidence is not None:
                    evidence.append(
                        EvidenceItem(
                            dimension="Certificate keywords",
                            indicator=kw,
                            location="META-INF/",
                            weight=_WEIGHT_CERT,
                            detail="Keyword matched in META-INF signing metadata",
                        )
                    )
                return score, matches
        return score, matches

    def _check_small_dex(
        self, zf: zipfile.ZipFile, entries: set[str],
        score: float, matches: list[str], packer: str,
    ) -> tuple[float, list[str]]:
        if "classes.dex" not in entries:
            return score, matches
        info = zf.getinfo("classes.dex")
        if info.file_size < 50 * 1024:
            try:
                data = zf.read("classes.dex")
                nclasses = _count_dex_classes(data)
                if nclasses is not None and nclasses < 10:
                    score += _WEIGHT_SMALL_DEX
                    matches.append(f"small_dex:size={info.file_size},classes={nclasses}")
            except Exception as exc:
                logger.debug("Small-DEX check failed on classes.dex: %s", exc)
        return score, matches

    def _determine_protection_level(
        self, zf: zipfile.ZipFile, entries: set[str], packer: str,
    ) -> ProtectionLevel:
        sig = PACKER_SIGNATURES.get(packer)
        if sig is None:
            return ProtectionLevel.UNKNOWN

        for dex2c_so in sig.dex2c_indicators:
            for entry in entries:
                if dex2c_so in entry:
                    return ProtectionLevel.DEX2C

        for vmp_so in sig.vmp_indicators:
            for entry in entries:
                if vmp_so in entry:
                    return ProtectionLevel.VMP

        for entry in entries:
            if not entry.startswith("lib/") or not entry.endswith(".so"):
                continue
            indicators = _check_so_exports(zf, entry)
            for ind in indicators:
                if ind.startswith("dex2c_export:"):
                    return ProtectionLevel.DEX2C
                if ind.startswith("vmp_export:"):
                    return ProtectionLevel.VMP

        for entry in entries:
            if not entry.startswith("lib/") or not entry.endswith(".so"):
                continue
            basename = entry.rsplit("/", 1)[-1]
            if sig.so_files and basename in sig.so_files:
                return ProtectionLevel.FUNCTION_EXTRACTION

        return ProtectionLevel.DEX_ENCRYPTION

    def _detect_version(self, entries: set[str], packer: str) -> str | None:
        sig = PACKER_SIGNATURES.get(packer)
        if sig is None or not sig.version_hints:
            return None

        all_entry_str = " ".join(entries)
        for indicator, version_label in sig.version_hints:
            if indicator in all_entry_str:
                return version_label
        return None
