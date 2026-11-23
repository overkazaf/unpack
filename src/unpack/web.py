"""UNPACK Studio — Commercial-grade Flask Web Workbench & REST/SSE API.

Provides:
- Hardened Studio API under ``/api/v1/*`` (samples vault, sandboxed local
  library, deep APK/DEX inspection & disassembly, scan intelligence, repair
  with before/after diff, VMP/xref analysis, repack & FART export, commercial
  HTML/Markdown/JSON/SARIF reporting, environment doctor, and real-time SSE
  async job streaming).
- Backward-compatible legacy endpoints under ``/api/*`` (hardened against path
  traversal, unsynchronized shared state, and unvalidated inputs).
- Zero-argument ``create_app()`` contract preserved for ``unpack web``.
"""

from __future__ import annotations

import atexit
import hashlib
import html
import inspect
import io
import json
import os
import queue
import shutil
import struct
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

os.environ.setdefault("LOGURU_LEVEL", "ERROR")

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_file,
    stream_with_context,
)
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

import unpack as unpack_pkg

APP_VERSION = getattr(unpack_pkg, "__version__", "0.1.0")
MAX_JOBS_RETAINED = 100
MAX_DEX_CACHE = 8
ALLOWED_UPLOAD_EXTS = {".apk", ".dex"}


# ---------------------------------------------------------------------------
# Security & parsing helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_filename(raw: str | None, default: str = "upload.bin") -> str:
    """Return a traversal-safe single filename component."""
    if not raw or "\x00" in raw:
        return default
    base = Path(raw.replace("\\", "/")).name
    cleaned = secure_filename(base)
    if not cleaned or cleaned in {".", ".."}:
        return default
    return cleaned


def _parse_int(
    value: Any,
    default: int,
    *,
    min_val: int | None = None,
    max_val: int | None = None,
    name: str = "parameter",
) -> int:
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid integer for '{name}': {value!r}") from exc
    if min_val is not None and parsed < min_val:
        raise ValueError(f"'{name}' must be >= {min_val}, got {parsed}")
    if max_val is not None and parsed > max_val:
        raise ValueError(f"'{name}' must be <= {max_val}, got {parsed}")
    return parsed


def _parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return default


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _dir_fingerprint(dir_path: Path) -> tuple[str, int, int]:
    """Compute a deterministic hash, total byte size, and dex count for a DEX dir."""
    h = hashlib.sha256()
    total_size = 0
    dex_files = sorted(p for p in dir_path.glob("*.dex") if p.is_file())
    for p in dex_files:
        st = p.stat()
        total_size += st.st_size
        h.update(f"{p.name}:{st.st_size}:{int(st.st_mtime)}".encode())
    return h.hexdigest(), total_size, len(dex_files)


def _discover_default_local_roots() -> list[Path]:
    """Discover safe local sample directories (env override + test_apks/e2e_test)."""
    roots: list[Path] = []
    seen: set[Path] = set()

    def _add(p: Path) -> None:
        try:
            rp = p.resolve()
        except OSError:
            return
        if rp.exists() and rp.is_dir() and rp not in seen:
            seen.add(rp)
            roots.append(rp)

    env_roots = os.environ.get("UNPACK_LOCAL_ROOTS", "")
    if env_roots:
        for part in env_roots.split(os.pathsep):
            if part.strip():
                _add(Path(part.strip()))

    candidates_base = [Path.cwd(), Path(__file__).resolve().parents[2]]
    for base in candidates_base:
        for sub in ("test_apks", "e2e_test"):
            _add(base / sub)

    return roots


def _resolve_allowed_local_path(raw_path: str, allowed_roots: list[Path]) -> Path | None:
    """Resolve raw_path and ensure it lies strictly inside an allowlisted root."""
    if not raw_path or "\x00" in raw_path:
        return None
    try:
        candidate = Path(raw_path).resolve()
    except OSError:
        return None
    if not candidate.exists():
        return None
    for root in allowed_roots:
        try:
            resolved_root = root.resolve()
            if candidate.is_relative_to(resolved_root):
                return candidate
        except OSError:
            continue
    return None


def _is_valid_apk_zip(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = set(zf.namelist())
            return "AndroidManifest.xml" in names or any(n.endswith(".dex") for n in names)
    except (zipfile.BadZipFile, OSError):
        return False


def _is_valid_dex_header(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            magic = f.read(8)
        return len(magic) >= 4 and (magic[:4] == b"dex\n" or magic[:4] == b"cdex")
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Defensive Core Adapters (works before & after core-pro / cli-ux merge)
# ---------------------------------------------------------------------------


def _scan_apk_rich(apk_path: Path) -> dict[str, Any]:
    from unpack.core.scanner import PackerScanner

    scanner = PackerScanner()
    result = scanner.scan(apk_path, verbose=True)
    if hasattr(result, "to_detailed_dict"):
        data = result.to_detailed_dict()
    else:
        data = result.to_verbose_dict()

    # Ensure commercial-grade fields exist even on pre-merge scanner
    if "evidence" not in data:
        evidence = []
        for b in data.get("score_breakdown", []):
            if b.get("matched"):
                evidence.append(
                    {
                        "dimension": b.get("dimension", ""),
                        "score": b.get("score", 0),
                        "max_score": b.get("max", 0),
                        "detail": f"Matched {b.get('dimension', '')} indicators",
                    }
                )
        data["evidence"] = evidence

    if "recommended_engine" not in data:
        lvl = data.get("protection_level", "none")
        if lvl == "vmp":
            rec_engine = "manual"
            rec_reason = "VMP virtualization detected; inspect VMP stubs and native interpreter."
            rec_flags = ["--deep"]
        elif lvl == "dex2c":
            rec_engine = "manual"
            rec_reason = "DEX2C native compilation detected; analyze native SO with IDA/Ghidra."
            rec_flags = []
        elif lvl == "function_extraction":
            rec_engine = "frida"
            rec_reason = "Function extraction detected; use Frida + Active Invoke (--deep)."
            rec_flags = ["--deep", "--anti-detect"]
        elif lvl == "dex_encryption":
            rec_engine = "memory"
            rec_reason = "DEX encryption detected; memory or Frida dump should recover DEX."
            rec_flags = ["--anti-detect"]
        else:
            rec_engine = "none"
            rec_reason = "No known commercial packer detected; static DEX inspection is ready."
            rec_flags = []
        data["recommended_engine"] = rec_engine
        data["recommended_flags"] = rec_flags
        data["strategy_reason"] = rec_reason

    if "risk_score" not in data:
        lvl_weight = {
            "none": 10,
            "unknown": 30,
            "dex_encryption": 55,
            "function_extraction": 75,
            "dex2c": 85,
            "vmp": 92,
        }
        base = lvl_weight.get(data.get("protection_level", "none"), 20)
        conf = float(data.get("confidence", 0.0))
        data["risk_score"] = int(min(100, round(base * (0.5 + 0.5 * conf)))) if data.get("packer_name") else 10

    return data


def _inspect_apk_rich(apk_path: Path) -> dict[str, Any]:
    """Run core-pro's ApkInspector if merged, else pure-Python + androguard fallback."""
    try:
        from unpack.core.inspector import ApkInspector

        res = ApkInspector().inspect(apk_path, deep_elf=True, include_dex_metrics=True)
        return res.to_dict()
    except ImportError:
        pass

    sha256 = _file_sha256(apk_path)
    size_bytes = apk_path.stat().st_size
    manifest: dict[str, Any] = {
        "package": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "application_class": None,
        "debuggable": False,
        "allow_backup": None,
        "uses_cleartext_traffic": None,
    }
    signing: dict[str, Any] = {
        "signed": False,
        "v1": False,
        "v2": False,
        "v3": False,
        "certificates": [],
    }
    permissions: list[dict[str, Any]] = []
    components: dict[str, list[dict[str, Any]]] = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    native_libs: list[dict[str, Any]] = []
    dex_files: list[dict[str, Any]] = []
    suspicious_assets: list[str] = []
    assets_count = 0
    findings: list[dict[str, Any]] = []
    warnings: list[str] = []

    dangerous_perms = {
        "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
        "RECORD_AUDIO", "CAMERA", "READ_PHONE_STATE", "CALL_PHONE", "READ_CALL_LOG",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES",
        "SYSTEM_ALERT_WINDOW", "QUERY_ALL_PACKAGES",
    }

    try:
        from loguru import logger as _lg

        _lg.disable("androguard")
    except ImportError:
        pass

    try:
        from androguard.core.apk import APK

        a = APK(str(apk_path))
        manifest["package"] = a.get_package()
        manifest["version_name"] = a.get_androidversion_name()
        manifest["version_code"] = a.get_androidversion_code()
        manifest["min_sdk"] = a.get_min_sdk_version()
        manifest["target_sdk"] = a.get_target_sdk_version()
        try:
            manifest["application_class"] = a.get_attribute_value("application", "name")
            dbg = a.get_attribute_value("application", "debuggable")
            manifest["debuggable"] = str(dbg).lower() == "true"
            bkp = a.get_attribute_value("application", "allowBackup")
            manifest["allow_backup"] = None if bkp is None else str(bkp).lower() == "true"
            clr = a.get_attribute_value("application", "usesCleartextTraffic")
            manifest["uses_cleartext_traffic"] = None if clr is None else str(clr).lower() == "true"
        except Exception:
            pass

        try:
            signing["v1"] = bool(a.is_signed_v1())
            signing["v2"] = bool(a.is_signed_v2())
            signing["v3"] = bool(a.is_signed_v3())
            signing["signed"] = signing["v1"] or signing["v2"] or signing["v3"]
            for cert in a.get_certificates() or []:
                try:
                    signing["certificates"].append(
                        {
                            "subject": str(cert.subject.human_friendly),
                            "issuer": str(cert.issuer.human_friendly),
                            "sha256": cert.sha256.hex() if hasattr(cert, "sha256") else "",
                        }
                    )
                except Exception:
                    pass
        except Exception:
            pass

        for perm in sorted(set(a.get_permissions() or [])):
            short = perm.rsplit(".", 1)[-1]
            is_danger = short in dangerous_perms
            permissions.append(
                {
                    "name": perm,
                    "short_name": short,
                    "level": "dangerous" if is_danger else "normal",
                }
            )

        for kind, getter in (
            ("activities", a.get_activities),
            ("services", a.get_services),
            ("receivers", a.get_receivers),
            ("providers", a.get_providers),
        ):
            try:
                for name in getter() or []:
                    components[kind].append({"name": name, "exported": False})
            except Exception:
                pass
    except Exception as exc:
        warnings.append(f"Manifest parse fallback: {exc}")
        from unpack.utils.apk import get_package_name

        manifest["package"] = get_package_name(apk_path)

    # Zip-level inspection (DEX, native libs, assets)
    sec_kw = ("jiagu", "shell", "sec", "protect", "shield", "guard", "crypt", "vmp", "bangcle", "ijm", "dex", "stub", "hook", "frida")
    with zipfile.ZipFile(apk_path, "r") as zf:
        for info in zf.infolist():
            name = info.filename
            if name.endswith(".dex") and "/" not in name:
                raw = zf.read(name)
                class_count = 0
                method_count = 0
                string_count = 0
                magic_str = ""
                if len(raw) >= 0x70 and raw[:4] in (b"dex\n", b"cdex"):
                    magic_str = raw[:7].decode("ascii", errors="replace").replace("\n", " ")
                    string_count = struct.unpack_from("<I", raw, 56)[0]
                    method_count = struct.unpack_from("<I", raw, 88)[0]
                    class_count = struct.unpack_from("<I", raw, 96)[0]
                dex_files.append(
                    {
                        "name": name,
                        "size_bytes": info.file_size,
                        "magic": magic_str,
                        "classes": class_count,
                        "methods": method_count,
                        "strings": string_count,
                    }
                )
            elif name.startswith("lib/") and name.endswith(".so"):
                parts = name.split("/")
                abi = parts[1] if len(parts) >= 3 else "unknown"
                so_name = parts[-1]
                low = so_name.lower()
                indicators = [k for k in sec_kw if k in low]
                elf_meta = _quick_elf_header(zf.read(name)[:64])
                native_libs.append(
                    {
                        "path": name,
                        "name": so_name,
                        "abi": abi,
                        "size_bytes": info.file_size,
                        "arch": elf_meta.get("arch", abi),
                        "bits": elf_meta.get("bits", 0),
                        "pie": elf_meta.get("pie", False),
                        "security_indicators": indicators,
                    }
                )
            elif name.startswith("assets/") and not name.endswith("/"):
                assets_count += 1
                low = name.lower()
                if any(k in low for k in (".dex", ".so", ".dat", ".bin", "jiagu", "shell", "encrypt", "ijm", "vmp", "sec")):
                    suspicious_assets.append(name)

    if manifest.get("debuggable"):
        findings.append(
            {
                "id": "APK-DEBUGGABLE",
                "severity": "high",
                "title": "Application is debuggable",
                "detail": "android:debuggable is true in AndroidManifest.xml.",
                "category": "manifest",
            }
        )
    if manifest.get("allow_backup"):
        findings.append(
            {
                "id": "APK-BACKUP",
                "severity": "medium",
                "title": "ADB backup enabled",
                "detail": "android:allowBackup is true; app data may be extracted via backup.",
                "category": "manifest",
            }
        )
    if manifest.get("uses_cleartext_traffic"):
        findings.append(
            {
                "id": "APK-CLEARTEXT",
                "severity": "medium",
                "title": "Cleartext HTTP traffic allowed",
                "detail": "android:usesCleartextTraffic is true.",
                "category": "manifest",
            }
        )
    danger_count = sum(1 for p in permissions if p["level"] == "dangerous")
    if danger_count >= 5:
        findings.append(
            {
                "id": "APK-PERMS",
                "severity": "medium",
                "title": f"{danger_count} dangerous permissions requested",
                "detail": "Review permission scope for least-privilege compliance.",
                "category": "permissions",
            }
        )
    sec_sos = [s for s in native_libs if s["security_indicators"]]
    if sec_sos:
        findings.append(
            {
                "id": "APK-SEC-SO",
                "severity": "info",
                "title": f"{len(sec_sos)} security/hardening native library indicator(s)",
                "detail": ", ".join(sorted({s["name"] for s in sec_sos})[:8]),
                "category": "native",
            }
        )

    risk_score = min(
        100,
        (25 if manifest.get("debuggable") else 0)
        + (12 if manifest.get("allow_backup") else 0)
        + (12 if manifest.get("uses_cleartext_traffic") else 0)
        + min(25, danger_count * 3)
        + min(20, len(sec_sos) * 5),
    )
    risk_grade = (
        "A" if risk_score < 20 else "B" if risk_score < 40 else "C" if risk_score < 60 else "D" if risk_score < 80 else "F"
    )

    return {
        "file": apk_path.name,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "manifest": manifest,
        "signing": signing,
        "permissions": permissions,
        "components": components,
        "native_libs": native_libs,
        "dex_files": dex_files,
        "assets_count": assets_count,
        "suspicious_assets": suspicious_assets[:100],
        "findings": findings,
        "risk_score": risk_score,
        "risk_grade": risk_grade,
        "warnings": warnings,
    }


def _quick_elf_header(head: bytes) -> dict[str, Any]:
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return {}
    ei_class = head[4]
    bits = 64 if ei_class == 2 else 32 if ei_class == 1 else 0
    endian = "<" if head[5] == 1 else ">"
    e_type, e_machine = struct.unpack_from(f"{endian}HH", head, 16)
    arch_map = {3: "x86", 40: "arm", 62: "x86_64", 183: "arm64"}
    return {
        "bits": bits,
        "arch": arch_map.get(e_machine, f"machine_{e_machine}"),
        "pie": e_type == 3,
    }


def _run_doctor_rich(check_devices: bool = True) -> dict[str, Any]:
    try:
        from unpack.core.doctor import run_doctor

        return run_doctor(check_devices=check_devices).to_dict()
    except ImportError:
        pass

    checks: list[dict[str, Any]] = []
    engines: list[dict[str, Any]] = []
    devices: list[dict[str, Any]] = []

    checks.append(
        {
            "name": "Python Runtime",
            "category": "runtime",
            "status": "pass",
            "detail": f"Python {sys.version.split()[0]}",
            "hint": "",
        }
    )

    import importlib.metadata

    for pkg_name, import_name, install_hint in (
        ("flask", "flask", "pip install -e '.[web]'"),
        ("androguard", "androguard", "pip install -e '.[analysis]'"),
        ("lief", "lief", "pip install lief"),
        ("frida", "frida", "pip install -e '.[frida]'"),
    ):
        try:
            __import__(import_name)
            try:
                ver = importlib.metadata.version(pkg_name)
            except importlib.metadata.PackageNotFoundError:
                ver = "installed"
            checks.append(
                {
                    "name": pkg_name,
                    "category": "python",
                    "status": "pass",
                    "detail": str(ver),
                    "hint": "",
                }
            )
        except Exception:
            checks.append(
                {
                    "name": pkg_name,
                    "category": "python",
                    "status": "warn",
                    "detail": "Not installed",
                    "hint": install_hint,
                }
            )

    for tool, hint in (
        ("adb", "Install Android Platform Tools"),
        ("jadx", "brew install jadx"),
        ("apktool", "brew install apktool"),
        ("apksigner", "Install Android SDK build-tools"),
        ("zipalign", "Install Android SDK build-tools"),
    ):
        found = shutil.which(tool)
        checks.append(
            {
                "name": tool,
                "category": "tools",
                "status": "pass" if found else "warn",
                "detail": found or "Not found on PATH",
                "hint": "" if found else hint,
            }
        )

    # Engines status
    for eng_name, mod_path, cls_name, fallback_reason in (
        ("frida", "unpack.engines.frida_engine", "FridaEngine", "frida not installed or no device"),
        ("memory", "unpack.engines.memory_engine", "MemoryEngine", "No rooted ADB device"),
        ("ebpf", "unpack.engines.ebpf_engine", "EbpfEngine", "No eBPF-capable device"),
    ):
        try:
            mod = __import__(mod_path, fromlist=[cls_name])
            eng = getattr(mod, cls_name)()
            avail = bool(eng.is_available()) if check_devices else False
            reason = "" if avail else (getattr(eng, "unavailable_reason", None) or fallback_reason)
            if not check_devices and not avail:
                reason = "Device check skipped"
            engines.append({"name": eng_name, "available": avail, "reason": reason})
        except Exception as exc:
            engines.append({"name": eng_name, "available": False, "reason": str(exc)})

    if check_devices and shutil.which("adb"):
        try:
            import subprocess

            proc = subprocess.run(
                ["adb", "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=2.5,
                check=False,
            )
            for line in proc.stdout.splitlines()[1:]:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    devices.append(
                        {
                            "serial": parts[0],
                            "state": parts[1],
                            "info": " ".join(parts[2:]),
                        }
                    )
        except Exception:
            pass

    overall = "pass"
    if any(c["status"] == "fail" for c in checks):
        overall = "fail"
    elif any(c["status"] == "warn" for c in checks):
        overall = "warn"

    return {
        "overall_status": overall,
        "python_version": sys.version.split()[0],
        "unpack_version": APP_VERSION,
        "checks": checks,
        "devices": devices,
        "engines": engines,
    }


def _verify_dex_rich(dex_path: Path) -> dict[str, Any]:
    from unpack.repair.verifier import DexVerifier

    vr = DexVerifier().verify(dex_path)
    if hasattr(vr, "to_dict"):
        d = vr.to_dict()
        d.setdefault("file", dex_path.name)
        return d

    cov = float(vr.stats.get("code_coverage", 0.0))
    issue_penalty = min(60, len(vr.issues) * 15)
    health = max(0.0, round((100.0 - issue_penalty) * (0.4 + 0.6 * cov), 1)) if vr.stats.get("methods_with_code") else (100.0 if vr.valid else max(0.0, 100.0 - issue_penalty))
    return {
        "file": dex_path.name,
        "valid": vr.valid,
        "issues": list(vr.issues),
        "stats": dict(vr.stats),
        "health_score": health,
    }


def _repair_dex_with_diff(dex_path: Path, out_dir: Path) -> tuple[dict[str, Any], Path | None]:
    """Copy DEX to out_dir and run repair_with_diff (or fallback before/after verify)."""
    from unpack.repair.dex_repair import DexRepairPipeline

    work_copy = out_dir / dex_path.name
    shutil.copy2(dex_path, work_copy)
    pipeline = DexRepairPipeline()

    if hasattr(pipeline, "repair_with_diff"):
        diff = pipeline.repair_with_diff(work_copy, in_place=True)
        d = diff.to_dict()
        d.setdefault("file", dex_path.name)
        out_path = Path(diff.repair.output_path) if getattr(diff.repair, "output_path", None) else work_copy
        return d, out_path

    before = _verify_dex_rich(work_copy)
    rr = pipeline.repair(work_copy, in_place=True)
    after = _verify_dex_rich(work_copy)
    before_set = set(before.get("issues", []))
    after_set = set(after.get("issues", []))
    resolved = sorted(before_set - after_set)
    remaining = sorted(after_set)
    health_delta = round(float(after.get("health_score", 0)) - float(before.get("health_score", 0)), 1)

    return (
        {
            "file": dex_path.name,
            "before": before,
            "after": after,
            "repair": {
                "success": rr.success,
                "actions": list(rr.actions),
                "nop_method_count": rr.nop_method_count,
            },
            "resolved_issues": resolved,
            "remaining_issues": remaining,
            "health_delta": health_delta,
        },
        rr.output_path or work_copy,
    )


def _analyze_vmp_dex_bytes(dex_bytes: bytes, dex_name: str) -> dict[str, Any]:
    from unpack.analysis.vmp import VmpDetector

    det = VmpDetector()
    rep = det.analyze_dex(dex_bytes)
    if hasattr(rep, "to_detailed_dict"):
        d = rep.to_detailed_dict()
        d["dex"] = dex_name
        return d

    d = rep.to_dict()
    total = max(1, d["total_methods"])
    vmp_ratio = round(d["vmp_count"] / total, 4)
    # Cluster dispatchers from call_graph
    dispatchers: dict[str, int] = {}
    class_counts: dict[str, int] = {}
    for m in d.get("vmp_methods", []):
        cls = m.get("class", "unknown")
        class_counts[cls] = class_counts.get(cls, 0) + 1
    for edge in d.get("call_graph", []):
        tgt = edge.get("target") or edge.get("callee") or "unknown"
        dispatchers[tgt] = dispatchers.get(tgt, 0) + 1

    risk_score = min(100, int(round(vmp_ratio * 250 + (20 if d["vmp_count"] > 0 else 0))))
    verdict = "heavy_vmp" if vmp_ratio >= 0.15 else "partial_vmp" if d["vmp_count"] > 0 else "clean"

    d["dex"] = dex_name
    d["vmp_ratio"] = vmp_ratio
    d["risk_score"] = risk_score
    d["verdict"] = verdict
    d["dispatchers"] = [
        {"target": k, "call_count": v}
        for k, v in sorted(dispatchers.items(), key=lambda x: -x[1])[:30]
    ]
    d["class_density"] = [
        {"class": k, "vmp_methods": v}
        for k, v in sorted(class_counts.items(), key=lambda x: -x[1])[:30]
    ]
    return d


def _analyze_xref_dex_bytes(dex_bytes: bytes, limit: int = 100) -> dict[str, Any]:
    from unpack.analysis.xref import XrefBuilder

    builder = XrefBuilder()
    rep = builder.build(dex_bytes)
    if hasattr(rep, "summary"):
        return rep.summary(limit=limit)

    import re

    url_re = re.compile(r"https?://[^\s'\"<>]{4,120}")
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    urls: list[str] = []
    ips: list[str] = []
    top_strings: list[dict[str, Any]] = []
    for s, refs in sorted(rep.string_refs.items(), key=lambda x: -len(x[1])):
        if len(urls) < 40 and url_re.search(s):
            urls.append(s[:140])
        elif len(ips) < 30 and ip_re.search(s):
            ips.append(s[:80])
        if len(top_strings) < limit:
            top_strings.append({"value": s[:180], "ref_count": len(refs), "sample_callers": refs[:3]})

    top_callees = [
        {"target": k, "call_count": len(v), "sample_callers": v[:3]}
        for k, v in sorted(rep.method_calls.items(), key=lambda x: -len(x[1]))[:limit]
    ]

    sensitive_kw = (
        "Runtime;->exec", "DexClassLoader", "InMemoryDexClassLoader",
        "Cipher;->getInstance", "MessageDigest", "Signature",
        "getDeviceId", "getSubscriberId", "System;->loadLibrary",
    )
    sensitive_apis = [
        {"target": k, "call_count": len(v), "sample_callers": v[:3]}
        for k, v in rep.method_calls.items()
        if any(kw in k for kw in sensitive_kw)
    ][:limit]

    return {
        "counts": {
            "strings": len(rep.string_refs),
            "method_targets": len(rep.method_calls),
            "field_targets": len(rep.field_refs),
            "reflection_calls": len(rep.reflection_calls),
        },
        "reflection_calls": rep.reflection_calls[:limit],
        "sensitive_apis": sensitive_apis,
        "iocs": {"urls": urls, "ips": ips},
        "top_strings": top_strings,
        "top_callees": top_callees,
    }


def _normalize_lang(raw: Any) -> str:
    s = str(raw or "en").strip().lower()
    return "zh" if s.startswith("zh") else "en"


def _render_commercial_report(
    *,
    sample: dict[str, Any],
    fmt: str,
    title: str | None = None,
    lang: str = "en",
) -> tuple[str, str, str]:
    """Render report via cli-ux's core.reporter if merged, else rich built-in generator.

    Supports bilingual output (``zh`` / ``en``) and defensively checks whether
    ``ReportGenerator.render`` accepts ``lang`` so pre-merge and post-merge
    worktrees both work seamlessly.

    Returns ``(content_str, mimetype, filename_ext)``.
    """
    fmt = fmt.lower().strip()
    if fmt == "md":
        fmt = "markdown"
    if fmt not in {"html", "markdown", "json", "sarif"}:
        raise ValueError(f"Unsupported report format: {fmt!r}")

    lang = _normalize_lang(lang)
    is_zh = lang == "zh"
    default_title = (
        f"UNPACK 安全审计报告 — {sample['name']}"
        if is_zh
        else f"UNPACK Security Audit — {sample['name']}"
    )
    report_title = title or default_title

    mime_map = {
        "html": ("text/html; charset=utf-8", "html"),
        "markdown": ("text/markdown; charset=utf-8", "md"),
        "json": ("application/json; charset=utf-8", "json"),
        "sarif": ("application/sarif+json; charset=utf-8", "sarif.json"),
    }

    # Try cli-ux commercial reporter contract first
    try:
        from unpack.core.reporter import (
            ReportGenerator,
            Reporter,
        )

        if hasattr(Reporter, "build_audit_report"):
            render_sig = inspect.signature(ReportGenerator.render)
            supports_lang = "lang" in render_sig.parameters
            if supports_lang or not is_zh or fmt in {"json", "sarif"}:
                build_sig = inspect.signature(Reporter.build_audit_report)
                build_kwargs: dict[str, Any] = {
                    "target": sample["name"],
                    "scan": sample.get("scan_result"),
                    "inspect": sample.get("inspect_result"),
                    "quality": sample.get("quality_report"),
                    "verify_results": sample.get("verify_results"),
                    "repair_results": sample.get("repair_diffs"),
                    "vmp": sample.get("vmp_result"),
                    "xref": sample.get("xref_result"),
                    "title": report_title,
                }
                if "lang" in build_sig.parameters:
                    build_kwargs["lang"] = lang
                audit = Reporter().build_audit_report(**build_kwargs)
                if supports_lang:
                    content = ReportGenerator.render(audit, fmt, lang=lang)
                else:
                    content = ReportGenerator.render(audit, fmt)
                mime, ext = mime_map[fmt]
                return content, mime, ext
    except Exception:
        pass

    # Built-in commercial fallback (complete, self-contained bilingual HTML / Markdown / JSON / SARIF 2.1.0)
    scan = sample.get("scan_result") or {}
    insp = sample.get("inspect_result") or {}
    vmp = sample.get("vmp_result") or {}
    verify = sample.get("verify_results") or []
    repairs = sample.get("repair_diffs") or []
    findings = list(insp.get("findings") or [])

    if scan.get("packer_name"):
        sev = "high" if scan.get("protection_level") in {"vmp", "dex2c"} else "medium"
        findings.insert(
            0,
            {
                "id": "PACKER-DETECTED",
                "severity": sev,
                "title": (
                    f"检测到商用加固壳：{scan['packer_name']} ({scan.get('protection_level', 'unknown')})"
                    if is_zh
                    else f"Packer detected: {scan['packer_name']} ({scan.get('protection_level', 'unknown')})"
                ),
                "detail": scan.get("strategy_reason")
                or scan.get("details")
                or ("命中商用加固特征指纹。" if is_zh else "Matched commercial packer signatures."),
                "category": "packer",
            },
        )
    if vmp.get("vmp_count", 0) > 0:
        findings.append(
            {
                "id": "VMP-STUBS",
                "severity": "high",
                "title": (
                    f"检测到 {vmp['vmp_count']} 个 VMP 虚拟机调度桩方法"
                    if is_zh
                    else f"{vmp['vmp_count']} VMP dispatcher stub method(s) detected"
                ),
                "detail": (
                    f"VMP 占比 {round(vmp.get('vmp_ratio', 0) * 100, 2)}%（共分析 {vmp.get('total_methods', 0)} 个方法）。"
                    if is_zh
                    else f"VMP ratio: {round(vmp.get('vmp_ratio', 0) * 100, 2)}% across {vmp.get('total_methods', 0)} methods."
                ),
                "category": "vmp",
            }
        )

    risk_score = max(int(insp.get("risk_score", 0)), int(scan.get("risk_score", 0)), int(vmp.get("risk_score", 0)))
    risk_grade = (
        "A" if risk_score < 20 else "B" if risk_score < 40 else "C" if risk_score < 60 else "D" if risk_score < 80 else "F"
    )

    bundle = {
        "tool": "UNPACK Studio",
        "version": APP_VERSION,
        "lang": lang,
        "generated_at": _utc_now_iso(),
        "title": report_title,
        "sample": {
            "id": sample["id"],
            "name": sample["name"],
            "kind": sample["kind"],
            "sha256": sample["sha256"],
            "size_bytes": sample["size_bytes"],
        },
        "risk_score": risk_score,
        "risk_grade": risk_grade,
        "findings": findings,
        "scan": scan,
        "inspect": insp,
        "vmp": vmp,
        "verify": verify,
        "repair": repairs,
    }

    if fmt == "json":
        return json.dumps(bundle, indent=2, ensure_ascii=False), "application/json; charset=utf-8", "json"

    if fmt == "sarif":
        level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
        rules = []
        results = []
        seen_rules: set[str] = set()
        for f in findings:
            rid = f.get("id", "UNPACK-001")
            if rid not in seen_rules:
                seen_rules.add(rid)
                rules.append(
                    {
                        "id": rid,
                        "name": rid,
                        "shortDescription": {"text": f.get("title", rid)},
                    }
                )
            results.append(
                {
                    "ruleId": rid,
                    "level": level_map.get(str(f.get("severity", "info")).lower(), "note"),
                    "message": {"text": f"{f.get('title', '')}: {f.get('detail', '')}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": sample["name"]},
                            }
                        }
                    ],
                }
            )
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "UNPACK Studio",
                            "version": APP_VERSION,
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False), "application/sarif+json; charset=utf-8", "sarif.json"

    if fmt == "markdown":
        size_mb = round(sample["size_bytes"] / (1024 * 1024), 2)
        if is_zh:
            lines = [
                f"# {report_title}",
                "",
                f"- **生成时间**：`{bundle['generated_at']}`",
                f"- **目标样本**：`{sample['name']}` ({sample['kind'].upper()}, {size_mb} MB)",
                f"- **SHA-256**：`{sample['sha256']}`",
                f"- **综合风险评级**：**{risk_grade}** 级（风险分 {risk_score}/100）",
                "",
                "## 核心安全发现",
                "",
            ]
            if findings:
                lines.append("| 编号 | 严重级别 | 发现项 | 详细说明 |")
                lines.append("|---|---|---|---|")
                for f in findings:
                    lines.append(
                        f"| `{f.get('id', '')}` | **{str(f.get('severity', 'info')).upper()}** | "
                        f"{f.get('title', '')} | {f.get('detail', f.get('description', ''))} |"
                    )
            else:
                lines.append("未记录到高风险安全问题。")
            if scan:
                lines.extend(
                    [
                        "",
                        "## 加固壳与保护等级情报",
                        "",
                        f"- **识别加固方案**：{scan.get('packer_name') or '未检测到商用加固'} {scan.get('packer_version') or ''}",
                        f"- **保护强度等级**：`{scan.get('protection_level', 'none')}`",
                        f"- **置信度**：{round(float(scan.get('confidence', 0)) * 100)}%",
                        f"- **推荐策略**：{scan.get('strategy_reason', '--')}",
                    ]
                )
            if vmp:
                lines.extend(
                    [
                        "",
                        "## VMP 虚拟化保护分析",
                        "",
                        f"- **分析方法总数**：{vmp.get('total_methods', 0)}",
                        f"- **VMP 调度桩方法**：{vmp.get('vmp_count', 0)} ({round(vmp.get('vmp_ratio', 0) * 100, 2)}%)",
                        f"- **NOP 抽取方法**：{vmp.get('nop_count', 0)}",
                    ]
                )
            if repairs:
                resolved_sum = sum(len(d.get("resolved_issues", [])) for d in repairs)
                lines.extend(
                    [
                        "",
                        "## DEX 修复与校验摘要",
                        "",
                        f"- **修复 DEX 数量**：{len(repairs)}",
                        f"- **已修复结构异常**：{resolved_sum} 项",
                    ]
                )
            return "\n".join(lines) + "\n", "text/markdown; charset=utf-8", "md"

        lines = [
            f"# {report_title}",
            "",
            f"- **Generated**: `{bundle['generated_at']}`",
            f"- **Sample**: `{sample['name']}` ({sample['kind'].upper()}, {size_mb} MB)",
            f"- **SHA-256**: `{sample['sha256']}`",
            f"- **Risk Assessment**: Grade **{risk_grade}** ({risk_score}/100)",
            "",
            "## Executive Findings",
            "",
        ]
        if findings:
            lines.append("| ID | Severity | Finding | Detail |")
            lines.append("|---|---|---|---|")
            for f in findings:
                lines.append(
                    f"| `{f.get('id', '')}` | **{str(f.get('severity', 'info')).upper()}** | "
                    f"{f.get('title', '')} | {f.get('detail', f.get('description', ''))} |"
                )
        else:
            lines.append("No high-risk findings recorded.")
        if scan:
            lines.extend(
                [
                    "",
                    "## Packer Intelligence",
                    "",
                    f"- **Packer**: {scan.get('packer_name') or 'None detected'} {scan.get('packer_version') or ''}",
                    f"- **Protection Level**: `{scan.get('protection_level', 'none')}`",
                    f"- **Confidence**: {round(float(scan.get('confidence', 0)) * 100)}%",
                    f"- **Strategy**: {scan.get('strategy_reason', '--')}",
                ]
            )
        if vmp:
            lines.extend(
                [
                    "",
                    "## VMP Analysis",
                    "",
                    f"- **Total Methods**: {vmp.get('total_methods', 0)}",
                    f"- **VMP Stubs**: {vmp.get('vmp_count', 0)} ({round(vmp.get('vmp_ratio', 0) * 100, 2)}%)",
                    f"- **NOP Methods**: {vmp.get('nop_count', 0)}",
                ]
            )
        return "\n".join(lines) + "\n", "text/markdown; charset=utf-8", "md"

    # Self-contained commercial HTML report (bilingual)
    esc = html.escape
    no_findings_text = "未记录到安全发现项。" if is_zh else "No findings recorded."
    finding_rows = "".join(
        f"<tr><td class='mono'>{esc(str(f.get('id', '')))}</td>"
        f"<td><span class='sev sev-{esc(str(f.get('severity', 'info')).lower())}'>{esc(str(f.get('severity', 'info')).upper())}</span></td>"
        f"<td><strong>{esc(str(f.get('title', '')))}</strong></td>"
        f"<td>{esc(str(f.get('detail', f.get('description', ''))))}</td></tr>"
        for f in findings
    ) or f"<tr><td colspan='4' style='color:#64748b'>{no_findings_text}</td></tr>"

    manifest = insp.get("manifest") or {}
    pkg_name = manifest.get("package") or manifest.get("package_name") or sample["name"]
    lbl_brand = f"UNPACK STUDIO v{APP_VERSION} — {'安全审计报告' if is_zh else 'SECURITY AUDIT REPORT'}"
    lbl_gen = "生成时间" if is_zh else "Generated"
    lbl_risk = f"风险分 {risk_score}/100" if is_zh else f"Risk {risk_score}/100"
    lbl_packer = "识别加固壳" if is_zh else "Packer"
    lbl_prot = "保护等级" if is_zh else "Protection"
    lbl_pkg = "应用包名 / 目标" if is_zh else "Package"
    lbl_find = "安全发现数" if is_zh else "Findings"
    lbl_sec_find = "安全发现与证据链" if is_zh else "Findings &amp; Evidence"
    th_id = "编号" if is_zh else "ID"
    th_sev = "级别" if is_zh else "Severity"
    th_title = "发现项" if is_zh else "Title"
    th_detail = "说明" if is_zh else "Detail"
    none_txt = "未检测到" if is_zh else "None"

    packer_sec = ""
    if scan:
        packer_sec = f"""
  <div class="card">
    <h2>{'加固壳情报与脱壳策略' if is_zh else 'Packer Intelligence &amp; Strategy'}</h2>
    <div class="meta-grid">
      <div><strong>{'加固厂商' if is_zh else 'Vendor'}:</strong> {esc(str(scan.get('packer_name') or none_txt))} {esc(str(scan.get('packer_version') or ''))}</div>
      <div><strong>{'置信度' if is_zh else 'Confidence'}:</strong> {round(float(scan.get('confidence', 0)) * 100)}%</div>
      <div><strong>{'推荐引擎' if is_zh else 'Recommended Engine'}:</strong> <span class="mono">{esc(str(scan.get('recommended_engine') or 'auto'))}</span></div>
      <div><strong>{'策略说明' if is_zh else 'Strategy'}:</strong> {esc(str(scan.get('strategy_reason') or '--'))}</div>
    </div>
  </div>"""

    html_doc = f"""<!DOCTYPE html>
<html lang="{'zh-CN' if is_zh else 'en'}">
<head>
<meta charset="UTF-8">
<title>{esc(report_title)}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei','Segoe UI',system-ui,sans-serif;background:#0a0d12;color:#e6edf3;margin:0;padding:32px;line-height:1.6}}
  .wrap{{max-width:1040px;margin:0 auto}}
  .hdr{{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid #1f2836;padding-bottom:20px;margin-bottom:24px}}
  .brand{{font-family:ui-monospace,Menlo,monospace;font-size:12px;letter-spacing:.12em;color:#38bdf8;text-transform:uppercase}}
  h1{{margin:6px 0 4px;font-size:24px;font-weight:600}}
  .meta{{color:#9aa6b8;font-size:13px}}
  .grade{{font-family:ui-monospace,Menlo,monospace;font-size:28px;font-weight:700;padding:10px 18px;border:1px solid #2c394d;border-radius:8px;background:#11161f;text-align:center}}
  .grade small{{display:block;font-size:11px;color:#9aa6b8;font-weight:400}}
  .grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}}
  .meta-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;font-size:13px;color:#cbd5e1}}
  .kpi{{background:#11161f;border:1px solid #1f2836;border-radius:8px;padding:14px}}
  .kpi .lbl{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#9aa6b8}}
  .kpi .val{{font-family:ui-monospace,Menlo,monospace;font-size:18px;font-weight:600;margin-top:4px}}
  .card{{background:#11161f;border:1px solid #1f2836;border-radius:8px;padding:18px;margin-bottom:20px}}
  h2{{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#9aa6b8;margin:0 0 12px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #1f2836}}
  th{{color:#9aa6b8;font-weight:600;font-size:12px}}
  .mono{{font-family:ui-monospace,Menlo,monospace}}
  .sev{{font-family:ui-monospace,Menlo,monospace;font-size:11px;padding:2px 7px;border-radius:4px;font-weight:600}}
  .sev-critical,.sev-high{{background:rgba(244,63,94,.16);color:#fb7185}}
  .sev-medium{{background:rgba(245,158,11,.16);color:#fbbf24}}
  .sev-low,.sev-info{{background:rgba(56,189,248,.16);color:#38bdf8}}
  @media print{{body{{background:#fff;color:#0f172a}}.card,.kpi,.grade{{background:#fff;border-color:#cbd5e1}}}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div>
      <div class="brand">{esc(lbl_brand)}</div>
      <h1>{esc(report_title)}</h1>
      <div class="meta">SHA-256: <span class="mono">{esc(sample['sha256'])}</span> &middot; {esc(lbl_gen)} {esc(bundle['generated_at'])}</div>
    </div>
    <div class="grade">{esc(risk_grade)}<small>{esc(lbl_risk)}</small></div>
  </div>
  <div class="grid">
    <div class="kpi"><div class="lbl">{esc(lbl_packer)}</div><div class="val">{esc(str(scan.get('packer_name') or none_txt))}</div></div>
    <div class="kpi"><div class="lbl">{esc(lbl_prot)}</div><div class="val">{esc(str(scan.get('protection_level') or 'none'))}</div></div>
    <div class="kpi"><div class="lbl">{esc(lbl_pkg)}</div><div class="val" style="font-size:14px;word-break:break-all">{esc(str(pkg_name))}</div></div>
    <div class="kpi"><div class="lbl">{esc(lbl_find)}</div><div class="val">{len(findings)}</div></div>
  </div>
  {packer_sec}
  <div class="card">
    <h2>{lbl_sec_find}</h2>
    <table><thead><tr><th>{th_id}</th><th>{th_sev}</th><th>{th_title}</th><th>{th_detail}</th></tr></thead><tbody>{finding_rows}</tbody></table>
  </div>
</div>
</body>
</html>"""
    return html_doc, "text/html; charset=utf-8", "html"


# ---------------------------------------------------------------------------
# DEX Browser Helper (uses core-pro DexInspector if available, else DexFile)
# ---------------------------------------------------------------------------


class _DexBrowserSession:
    """Unified DEX inspection facade wrapping DexInspector or DexFile fallback."""

    def __init__(self, dex_bytes: bytes, name: str):
        self.name = name
        self._native_inspector = None
        self._dex = None
        self._vmp_map: dict[tuple[str, str], str] = {}
        self._class_index: list[dict[str, Any]] = []
        self._class_map: dict[str, Any] = {}

        try:
            from unpack.analysis.dex_inspector import DexInspector

            self._native_inspector = DexInspector.from_bytes(dex_bytes, name=name)
            return
        except ImportError:
            pass

        from unpack.analysis.vmp import MethodClassification, VmpDetector
        from unpack.repair.dex_parser import DexFile

        self._dex = DexFile.parse(dex_bytes)
        vmp_det = VmpDetector()

        for cdef in self._dex.class_defs:
            cls_name = self._dex.get_type_name(cdef.class_idx) or f"Lclass_{cdef.class_idx};"
            super_name = self._dex.get_type_name(cdef.superclass_idx) or ""
            methods = []
            if cdef.class_data:
                methods = list(cdef.class_data.direct_methods) + list(cdef.class_data.virtual_methods)

            nop_cnt = 0
            vmp_cnt = 0
            empty_cnt = 0
            ok_cnt = 0
            for m in methods:
                m_name = self._dex.get_method_name(m.method_idx) or f"method_{m.method_idx}"
                ci = m.code_item
                if ci is None or ci.insns_size == 0:
                    empty_cnt += 1
                    status = "empty"
                else:
                    target_cls = None
                    t_idx = vmp_det._invoke_target(ci.insns, ci.insns_size)
                    if t_idx is not None:
                        target_cls, _ = self._dex.get_method_full(t_idx)
                    c = vmp_det.classify_insns(ci.insns, ci.insns_size, method_name=m_name, invoke_target_class=target_cls)
                    if c == MethodClassification.VMP_STUB:
                        vmp_cnt += 1
                        status = "vmp_stub"
                    elif c == MethodClassification.NOP:
                        nop_cnt += 1
                        status = "nop"
                    else:
                        ok_cnt += 1
                        status = "ok"
                self._vmp_map[(cls_name, f"{m_name}#{m.method_idx}")] = status

            health = "vmp" if vmp_cnt > 0 else "nop" if nop_cnt > 0 else "ok"
            pkg = cls_name.strip("L;").rsplit("/", 1)[0].replace("/", ".") if "/" in cls_name else "(default)"
            entry = {
                "name": cls_name,
                "package": pkg,
                "superclass": super_name,
                "method_count": len(methods),
                "ok_methods": ok_cnt,
                "nop_methods": nop_cnt,
                "vmp_methods": vmp_cnt,
                "empty_methods": empty_cnt,
                "health": health,
            }
            self._class_index.append(entry)
            self._class_map[cls_name] = cdef

    def summary(self) -> dict[str, Any]:
        if self._native_inspector is not None:
            return self._native_inspector.summary().to_dict()
        h = self._dex.header
        return {
            "name": self.name,
            "magic": h.magic[:7].decode("ascii", errors="replace").replace("\n", " "),
            "file_size": h.file_size,
            "class_count": h.class_defs_size,
            "method_count": h.method_ids_size,
            "string_count": h.string_ids_size,
            "field_count": h.field_ids_size,
            "type_count": h.type_ids_size,
        }

    def list_classes(
        self, query: str = "", package: str = "", health: str = "", offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        if self._native_inspector is not None:
            health_map = {"ok": "normal", "vmp": "vmp_stub", "nop": "nop", "empty": "empty"}
            mapped_health = health_map.get(health.strip().lower(), health.strip().lower())
            page = self._native_inspector.list_classes(
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
            page["packages"] = [p.to_dict() for p in self._native_inspector.package_tree()[:80]]
            return page

        q = query.strip().lower()
        pkg_f = package.strip().lower()
        h_f = health.strip().lower()
        filtered = []
        pkg_counts: dict[str, int] = {}
        for item in self._class_index:
            pkg_counts[item["package"]] = pkg_counts.get(item["package"], 0) + 1
            if q and q not in item["name"].lower():
                continue
            if pkg_f and not item["package"].lower().startswith(pkg_f):
                continue
            if h_f and item["health"] != h_f:
                continue
            filtered.append(item)

        packages = [
            {"package": k, "class_count": v}
            for k, v in sorted(pkg_counts.items(), key=lambda x: (-x[1], x[0]))[:80]
        ]
        return {
            "total": len(filtered),
            "offset": offset,
            "limit": limit,
            "classes": filtered[offset : offset + limit],
            "packages": packages,
        }

    def inspect_class(self, class_name: str) -> dict[str, Any] | None:
        if self._native_inspector is not None:
            res = self._native_inspector.inspect_class(class_name)
            if res is None:
                return None
            d = res.to_dict()
            desc = d.get("descriptor") or d.get("name", class_name)
            d["name"] = desc
            d["descriptor"] = desc
            norm_methods = []
            for m in d.get("methods", []):
                raw_h = m.get("health", "normal")
                ui_h = "ok" if raw_h == "normal" else raw_h
                norm_methods.append(
                    {
                        **m,
                        "kind": m.get("kind") or ("direct" if m.get("is_direct") else "virtual"),
                        "health": ui_h,
                    }
                )
            d["methods"] = norm_methods
            d["fields"] = [
                {**f, "kind": f.get("kind") or ("static" if f.get("is_static") else "instance")}
                for f in d.get("fields", [])
            ]
            return d

        cdef = self._class_map.get(class_name)
        if cdef is None:
            return None

        methods_out = []
        if cdef.class_data:
            for kind, mlist in (
                ("direct", cdef.class_data.direct_methods),
                ("virtual", cdef.class_data.virtual_methods),
            ):
                for m in mlist:
                    m_name = self._dex.get_method_name(m.method_idx) or f"method_{m.method_idx}"
                    ci = m.code_item
                    status = self._vmp_map.get((class_name, f"{m_name}#{m.method_idx}"), "ok")
                    methods_out.append(
                        {
                            "name": m_name,
                            "method_idx": m.method_idx,
                            "kind": kind,
                            "access_flags": m.access_flags,
                            "code_off": m.code_off,
                            "registers_size": ci.registers_size if ci else 0,
                            "ins_size": ci.ins_size if ci else 0,
                            "outs_size": ci.outs_size if ci else 0,
                            "insns_size": ci.insns_size if ci else 0,
                            "health": status,
                        }
                    )

        fields_out = []
        if cdef.class_data:
            for kind, flist in (
                ("static", cdef.class_data.static_fields),
                ("instance", cdef.class_data.instance_fields),
            ):
                for f in flist:
                    _, fname = self._dex.get_field_full(f.field_idx)
                    fields_out.append(
                        {
                            "name": fname or f"field_{f.field_idx}",
                            "field_idx": f.field_idx,
                            "kind": kind,
                            "access_flags": f.access_flags,
                        }
                    )

        return {
            "name": class_name,
            "superclass": self._dex.get_type_name(cdef.superclass_idx) or "",
            "access_flags": cdef.access_flags,
            "methods": methods_out,
            "fields": fields_out,
        }

    def disassemble_method(
        self,
        class_name: str,
        method_name: str,
        method_idx: int | None = None,
        max_insns: int = 500,
    ) -> dict[str, Any] | None:
        if self._native_inspector is not None:
            res = self._native_inspector.disassemble_method(
                class_name, method_name, method_idx=method_idx, max_insns=max_insns
            )
            if res is None:
                return None
            d = res.to_dict()
            if "code_off" not in d:
                cls_info = self._native_inspector.inspect_class(class_name)
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

        cdef = self._class_map.get(class_name)
        if cdef is None or not cdef.class_data:
            return None

        target = None
        for m in list(cdef.class_data.direct_methods) + list(cdef.class_data.virtual_methods):
            m_name = self._dex.get_method_name(m.method_idx) or ""
            if method_idx is not None and m.method_idx == method_idx:
                target = m
                break
            if method_idx is None and m_name == method_name:
                target = m
                break

        if target is None:
            return None

        ci = target.code_item
        if ci is None:
            return {
                "class_name": class_name,
                "method_name": self._dex.get_method_name(target.method_idx) or method_name,
                "method_idx": target.method_idx,
                "code_off": target.code_off,
                "registers_size": 0,
                "insns_size": 0,
                "instructions": [],
                "truncated": False,
                "note": "Abstract or native method (no Dalvik code_item).",
            }

        from unpack.analysis.disasm import DalvikDecoder

        decoder = DalvikDecoder()
        raw_insns = decoder.decode(ci.insns, ci.insns_size)
        truncated = len(raw_insns) > max_insns
        insns_out = []
        for insn in raw_insns[:max_insns]:
            operand = ""
            ref_kind = ""
            if insn.string_idx is not None:
                sval = self._dex.get_string(insn.string_idx)
                operand = json.dumps(sval if sval is not None else f"string#{insn.string_idx}")
                ref_kind = "string"
            elif insn.type_idx is not None:
                operand = self._dex.get_type_name(insn.type_idx) or f"type#{insn.type_idx}"
                ref_kind = "type"
            elif insn.method_idx is not None:
                tc, tn = self._dex.get_method_full(insn.method_idx)
                operand = f"{tc or '?'}->{tn or '?'}"
                ref_kind = "method"
            elif insn.field_idx is not None:
                fc, fn = self._dex.get_field_full(insn.field_idx)
                operand = f"{fc or '?'}->{fn or '?'}"
                ref_kind = "field"

            raw_slice = ci.insns[insn.offset : insn.offset + insn.size * 2]
            insns_out.append(
                {
                    "offset": f"0x{insn.offset:04x}",
                    "offset_int": insn.offset,
                    "hex": raw_slice.hex(" "),
                    "mnemonic": insn.mnemonic,
                    "operand": operand,
                    "ref_kind": ref_kind,
                }
            )

        return {
            "class_name": class_name,
            "method_name": self._dex.get_method_name(target.method_idx) or method_name,
            "method_idx": target.method_idx,
            "code_off": target.code_off,
            "registers_size": ci.registers_size,
            "insns_size": ci.insns_size,
            "instructions": insns_out,
            "truncated": truncated,
        }

    def search_strings(self, query: str = "", limit: int = 100) -> list[dict[str, Any]]:
        if self._native_inspector is not None:
            out = []
            for hit in self._native_inspector.search_strings(query=query, limit=limit):
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
        q = query.strip().lower()
        hits = []
        for idx in range(self._dex.header.string_ids_size):
            val = self._dex.get_string(idx)
            if val is None:
                continue
            if q and q not in val.lower():
                continue
            hits.append({"index": idx, "value": val[:240], "length": len(val)})
            if len(hits) >= limit:
                break
        return hits


# ---------------------------------------------------------------------------
# Thread-Safe Job Manager with SSE pub/sub
# ---------------------------------------------------------------------------


class JobManager:
    """Thread-safe async job tracker with real-time SSE event streaming."""

    def __init__(
        self,
        max_jobs: int = MAX_JOBS_RETAINED,
        on_finish: Callable[[dict[str, Any]], None] | None = None,
    ):
        self._lock = threading.RLock()
        self._jobs: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._cancel_events: dict[str, threading.Event] = {}
        self._subscribers: dict[str, list[queue.Queue]] = {}
        self._max_jobs = max_jobs
        self._on_finish = on_finish

    def create_job(
        self,
        *,
        job_type: str,
        apk: str,
        apk_hash: str = "",
        sample_id: str = "",
        phase: str = "queued",
        extra: dict[str, Any] | None = None,
    ) -> str:
        job_id = str(uuid.uuid4())[:8]
        now = _utc_now_iso()
        job: dict[str, Any] = {
            "id": job_id,
            "type": job_type,
            "status": "running",
            "phase": phase,
            "progress": 0,
            "apk": apk,
            "apk_hash": apk_hash,
            "sample_id": sample_id or apk_hash,
            "mode": (extra or {}).get("mode", "legacy"),
            "stages": list((extra or {}).get("stages", [])),
            "phases": {},
            "result": None,
            "error": None,
            "logs": [],
            "artifacts": [],
            "created_at": now,
            "finished_at": None,
            "duration_ms": 0,
        }
        if extra:
            for k, v in extra.items():
                if k not in {"stages"}:
                    job[k] = v

        with self._lock:
            self._jobs[job_id] = job
            self._cancel_events[job_id] = threading.Event()
            self._subscribers[job_id] = []
            self._evict_locked()
        return job_id

    def _evict_locked(self) -> None:
        while len(self._jobs) > self._max_jobs:
            evict_id = None
            for jid, job in self._jobs.items():
                if job["status"] in {"done", "failed", "cancelled"}:
                    evict_id = jid
                    break
            if evict_id is None:
                break
            self._jobs.pop(evict_id, None)
            self._cancel_events.pop(evict_id, None)
            self._subscribers.pop(evict_id, None)

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return json.loads(json.dumps(job)) if job is not None else None

    def list_all(self) -> list[dict[str, Any]]:
        with self._lock:
            items = []
            for job in reversed(self._jobs.values()):
                items.append(
                    {
                        "id": job["id"],
                        "type": job["type"],
                        "status": job["status"],
                        "phase": job["phase"],
                        "progress": job["progress"],
                        "apk": job["apk"],
                        "sample_id": job["sample_id"],
                        "created_at": job["created_at"],
                        "finished_at": job["finished_at"],
                        "duration_ms": job["duration_ms"],
                        "error": job["error"],
                        "artifact_count": len(job.get("artifacts", [])),
                    }
                )
            return items

    def is_cancelled(self, job_id: str) -> bool:
        with self._lock:
            ev = self._cancel_events.get(job_id)
            return ev.is_set() if ev else False

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            ev = self._cancel_events.get(job_id)
            if ev:
                ev.set()
            if job["status"] == "running":
                job["status"] = "cancelled"
                job["phase"] = "cancelled"
                job["finished_at"] = _utc_now_iso()
                self._append_log_locked(job_id, "warn", "cancelled", "Cancellation requested by user.")
                self._broadcast_locked(job_id, "cancelled", {"status": "cancelled", "phase": "cancelled"})
            return True

    def log(self, job_id: str, message: str, *, level: str = "info", phase: str | None = None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            entry = self._append_log_locked(job_id, level, phase or job["phase"], message)
            self._broadcast_locked(job_id, "log", entry)

    def _append_log_locked(self, job_id: str, level: str, phase: str, message: str) -> dict[str, Any]:
        entry = {"ts": _utc_now_iso(), "level": level, "phase": phase, "message": message}
        logs = self._jobs[job_id]["logs"]
        logs.append(entry)
        if len(logs) > 500:
            del logs[:100]
        return entry

    def set_phase(self, job_id: str, phase: str, progress: int | None = None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["phase"] = phase
            if progress is not None:
                job["progress"] = progress
            self._broadcast_locked(job_id, "phase", {"phase": phase, "progress": job["progress"]})

    def set_phase_data(self, job_id: str, key: str, data: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["phases"][key] = data
            self._broadcast_locked(job_id, "phase_data", {"key": key, "data": data})

    def add_artifact(self, job_id: str, artifact: dict[str, Any]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["artifacts"].append(artifact)
            self._broadcast_locked(job_id, "artifact", artifact)

    def update_stage(
        self,
        job_id: str,
        stage_id: str,
        *,
        status: str,
        duration_ms: int | None = None,
        summary: str | None = None,
        metrics: dict[str, Any] | None = None,
        artifacts: list[dict[str, Any]] | None = None,
        next_hint: str | None = None,
        log_message: str | None = None,
        log_level: str = "info",
    ) -> None:
        """Update per-stage structured telemetry and emit an SSE ``stage`` event."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            stage_obj = None
            for st in job.setdefault("stages", []):
                if st.get("id") == stage_id or st.get("stage_id") == stage_id:
                    stage_obj = st
                    break
            if stage_obj is None:
                stage_obj = {
                    "id": stage_id,
                    "stage_id": stage_id,
                    "status": status,
                    "duration_ms": 0,
                    "summary": "",
                    "metrics": {},
                    "artifacts": [],
                    "next_hint": "",
                    "logs": [],
                }
                job["stages"].append(stage_obj)

            stage_obj["stage_id"] = stage_id
            stage_obj["status"] = status
            if duration_ms is not None:
                stage_obj["duration_ms"] = int(duration_ms)
            if summary is not None:
                stage_obj["summary"] = summary
            if metrics is not None:
                stage_obj["metrics"] = dict(metrics)
            if artifacts is not None:
                stage_obj["artifacts"] = list(artifacts)
            if next_hint is not None:
                stage_obj["next_hint"] = next_hint
            if log_message:
                entry = self._append_log_locked(job_id, log_level, stage_id, log_message)
                stage_obj.setdefault("logs", []).append(entry)
                self._broadcast_locked(job_id, "log", entry)

            payload = {
                "stage_id": stage_id,
                "status": stage_obj["status"],
                "duration_ms": stage_obj.get("duration_ms", 0),
                "summary": stage_obj.get("summary", ""),
                "metrics": stage_obj.get("metrics", {}),
                "artifacts": stage_obj.get("artifacts", []),
                "next_hint": stage_obj.get("next_hint", ""),
                "logs": stage_obj.get("logs", [])[-50:],
            }
            self._broadcast_locked(job_id, "stage", payload)

    def finish(
        self,
        job_id: str,
        *,
        status: str = "done",
        result: Any = None,
        error: str | None = None,
        duration_ms: int = 0,
    ) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            if job["status"] == "cancelled":
                return
            job["status"] = status
            if status == "done":
                job["phase"] = "done"
                job["progress"] = 100
            if result is not None:
                job["result"] = result
            if error is not None:
                job["error"] = error
            job["finished_at"] = _utc_now_iso()
            job["duration_ms"] = duration_ms
            snapshot = json.loads(json.dumps(job))
        if self._on_finish is not None:
            try:
                self._on_finish(snapshot)
            except Exception:
                pass
        with self._lock:
            self._broadcast_locked(
                job_id,
                status,
                {"status": status, "phase": snapshot["phase"], "progress": snapshot["progress"], "error": error},
            )

    def _broadcast_locked(self, job_id: str, event: str, payload: Any) -> None:
        for q in list(self._subscribers.get(job_id, [])):
            try:
                q.put_nowait((event, payload))
            except queue.Full:
                pass

    def subscribe(self, job_id: str) -> tuple[dict[str, Any] | None, queue.Queue]:
        q: queue.Queue = queue.Queue(maxsize=256)
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None, q
            snapshot = json.loads(json.dumps(job))
            self._subscribers.setdefault(job_id, []).append(q)
            return snapshot, q

    def unsubscribe(self, job_id: str, q: queue.Queue) -> None:
        with self._lock:
            subs = self._subscribers.get(job_id)
            if subs and q in subs:
                subs.remove(q)


# ---------------------------------------------------------------------------
# Flask App Factory
# ---------------------------------------------------------------------------


def create_app(
    local_roots: list[Path | str] | None = None,
    max_content_length: int = 512 * 1024 * 1024,
    workspace_dir: Path | str | None = None,
) -> Flask:
    """Create and configure the UNPACK Studio Flask application."""
    from unpack.core.ai_engine import (
        AIAnalyzer,
        AIConfig,
        AIConfigStore,
        is_masked_api_key,
        list_provider_presets,
        test_connection as ai_test_connection,
    )
    from unpack.core.errors import UnpackError
    from unpack.core.workspace_store import DEFAULT_WORKSPACE_ID, WorkspaceStore

    pkg_dir = Path(__file__).parent
    app = Flask(
        __name__,
        template_folder=str(pkg_dir / "templates"),
        static_folder=str(pkg_dir / "static"),
        static_url_path="/static",
    )
    app.config["MAX_CONTENT_LENGTH"] = max_content_length
    app.config["JSON_SORT_KEYS"] = False

    allowed_local_roots: list[Path] = (
        [Path(r).resolve() for r in local_roots if Path(r).exists()]
        if local_roots is not None
        else _discover_default_local_roots()
    )

    workspace_root = Path(tempfile.mkdtemp(prefix="unpack_studio_"))
    uploads_dir = workspace_root / "uploads"
    artifacts_dir = workspace_root / "artifacts"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Persistent WorkspaceStore + AIConfigStore (isolated via workspace_dir or UNPACK_HOME)
    if workspace_dir is not None:
        ws_base = Path(workspace_dir).expanduser()
        ws_store = WorkspaceStore(base_dir=ws_base / "studio")
        ai_config_store = AIConfigStore(base_dir=ws_base)
    else:
        ws_store = WorkspaceStore()
        ai_config_store = AIConfigStore()
    ws_store.ensure_default_workspace()

    def _cleanup_workspace() -> None:
        try:
            ws_store.close()
        except Exception:
            pass
        shutil.rmtree(workspace_root, ignore_errors=True)

    atexit.register(_cleanup_workspace)
    app.config["UNPACK_CLEANUP"] = _cleanup_workspace
    app.config["UNPACK_WORKSPACE"] = workspace_root
    app.config["UNPACK_WS_STORE"] = ws_store
    app.config["UNPACK_AI_STORE"] = ai_config_store

    lock = threading.RLock()
    ws_state: dict[str, str] = {"active_workspace_id": DEFAULT_WORKSPACE_ID}
    # Per-sample single-flight inspect locks (prevents duplicate deep ELF scans)
    inspect_locks: dict[str, threading.Lock] = {}
    # sample_id (16-char sha256 prefix or persisted sample_id) -> sample dict
    samples: OrderedDict[str, dict[str, Any]] = OrderedDict()
    # artifact token -> {path, name, kind, size_bytes, mimetype}
    artifacts: dict[str, dict[str, Any]] = {}
    # LRU cache for parsed _DexBrowserSession: (sample_id, dex_name) -> _DexBrowserSession
    dex_sessions: OrderedDict[tuple[str, str], _DexBrowserSession] = OrderedDict()
    # Short-TTL cache for doctor probes so Pipeline preset/option switches are instantaneous
    doctor_cache: dict[str, Any] = {"ts": 0.0, "data": None}

    def _active_ws_id() -> str:
        with lock:
            return ws_state["active_workspace_id"]

    def _persist_sample(record: dict[str, Any], ws_id: str | None = None) -> None:
        """Persist sample snapshot and analysis results into WorkspaceStore."""
        target_ws = ws_id or record.get("workspace_id") or _active_ws_id()
        try:
            path_obj = record.get("path")
            src_path = str(path_obj) if path_obj else str(record.get("source_path") or "")
            saved = ws_store.save_sample(
                target_ws,
                {
                    "sample_id": record["id"],
                    "filename": record["name"],
                    "sha256": record.get("sha256", ""),
                    "kind": record.get("kind", "apk"),
                    "size_bytes": int(record.get("size_bytes") or 0),
                    "source_path": src_path,
                    "scan_result": record.get("scan_result"),
                    "inspect_result": record.get("inspect_result"),
                    "vmp_result": record.get("vmp_result"),
                    "xref_result": record.get("xref_result"),
                    "repair_result": record.get("repair_diffs"),
                    "notes": record.get("notes", ""),
                    "bookmarks": record.get("bookmarks", []),
                    "ai_analyses": record.get("ai_analyses", []),
                },
            )
            with lock:
                record["workspace_id"] = saved["workspace_id"]
                record["updated_at"] = saved["updated_at"]
        except Exception:
            pass

    def _persist_job_run(job_snap: dict[str, Any]) -> None:
        ws_id = job_snap.get("workspace_id") or _active_ws_id()
        try:
            stages = job_snap.get("stages") or []
            done_cnt = sum(1 for st in stages if st.get("status") == "done")
            summary = f"{job_snap.get('mode', 'pipeline')} · {done_cnt}/{len(stages)} stages" if stages else f"{job_snap.get('phase', '')}"
            ws_store.save_pipeline_run(
                ws_id,
                {
                    "id": job_snap["id"],
                    "sample_id": job_snap.get("sample_id") or job_snap.get("apk_hash"),
                    "name": f"{job_snap.get('mode', 'pipeline')}:{job_snap.get('apk', '')}",
                    "stage": job_snap.get("phase", ""),
                    "status": job_snap.get("status", "done"),
                    "started_at": job_snap.get("created_at", ""),
                    "finished_at": job_snap.get("finished_at") or _utc_now_iso(),
                    "duration_ms": int(job_snap.get("duration_ms") or 0),
                    "summary": summary,
                    "error": job_snap.get("error") or "",
                    "stages": stages,
                    "payload": {
                        "apk": job_snap.get("apk"),
                        "mode": job_snap.get("mode"),
                        "phases": job_snap.get("phases", {}),
                    },
                },
            )
            sid = job_snap.get("sample_id") or job_snap.get("apk_hash")
            if sid:
                rec = _get_sample_or_404(str(sid))
                if rec is not None:
                    _persist_sample(rec, ws_id=ws_id)
        except Exception:
            pass

    job_mgr = JobManager(on_finish=_persist_job_run)

    def _restore_workspace_samples(ws_id: str) -> list[dict[str, Any]]:
        """Load persisted samples for ``ws_id`` into the active in-memory vault."""
        persisted = ws_store.list_samples(workspace_id=ws_id)
        with lock:
            ws_state["active_workspace_id"] = ws_id
            samples.clear()
            dex_sessions.clear()
            for item in reversed(persisted):
                sid = str(item["sample_id"])
                raw_src = str(item.get("source_path") or "").strip()
                p_obj: Path | None = None
                file_ok = False
                if raw_src:
                    cand = Path(raw_src)
                    if cand.exists():
                        p_obj = cand
                        file_ok = True
                kind = str(item.get("kind") or "apk")
                dex_cnt = 0
                if file_ok and p_obj is not None:
                    if kind == "dex":
                        dex_cnt = 1
                    elif kind == "dex_dir":
                        dex_cnt = len([p for p in p_obj.glob("*.dex") if p.is_file()])
                    elif kind == "apk":
                        dex_cnt = _count_apk_dex(p_obj)
                elif item.get("inspect_result") and isinstance(item["inspect_result"], dict):
                    dex_cnt = len(item["inspect_result"].get("dex_files") or [])

                work_dir = uploads_dir / f"restored_{sid}"
                work_dir.mkdir(parents=True, exist_ok=True)
                repair_diffs = item.get("repair_result")
                verify_res = None
                if isinstance(repair_diffs, list):
                    verify_res = [d["after"] for d in repair_diffs if isinstance(d, dict) and d.get("after")] or None
                ai_list = ws_store.list_ai_analyses(workspace_id=ws_id, sample_id=sid, limit=50)
                if not ai_list and item.get("ai_analyses"):
                    ai_list = list(item["ai_analyses"])

                samples[sid] = {
                    "id": sid,
                    "workspace_id": ws_id,
                    "name": item["filename"],
                    "kind": kind,
                    "source": "local" if file_ok else "saved",
                    "path": p_obj,
                    "source_path": raw_src,
                    "file_available": file_ok,
                    "work_dir": work_dir,
                    "display_path": (
                        _relative_display_path(p_obj, allowed_local_roots)
                        if (file_ok and p_obj is not None)
                        else f"saved://{item['filename']}"
                    ),
                    "size_bytes": int(item.get("size_bytes") or 0),
                    "sha256": item.get("sha256") or "",
                    "created_at": item.get("created_at") or _utc_now_iso(),
                    "updated_at": item.get("updated_at") or _utc_now_iso(),
                    "dex_count": dex_cnt,
                    "scan_result": item.get("scan_result"),
                    "inspect_result": item.get("inspect_result"),
                    "vmp_result": item.get("vmp_result"),
                    "xref_result": item.get("xref_result"),
                    "verify_results": verify_res,
                    "repair_diffs": repair_diffs if isinstance(repair_diffs, list) else None,
                    "quality_report": None,
                    "last_job_id": None,
                    "artifacts": [],
                    "notes": item.get("notes") or "",
                    "bookmarks": list(item.get("bookmarks") or []),
                    "ai_analyses": ai_list,
                }
            return [_public_sample(s) for s in reversed(samples.values())]

    def _get_doctor_cached(*, check_devices: bool = True, force_refresh: bool = False) -> dict[str, Any]:
        if not check_devices:
            return _run_doctor_rich(check_devices=False)
        now = time.monotonic()
        with lock:
            if not force_refresh and doctor_cache["data"] is not None and (now - doctor_cache["ts"]) < 15.0:
                return doctor_cache["data"]
        fresh = _run_doctor_rich(check_devices=True)
        with lock:
            doctor_cache["data"] = fresh
            doctor_cache["ts"] = time.monotonic()
        return fresh

    # ── Internal Store Helpers ──

    def _register_artifact(path: Path, name: str, kind: str, mimetype: str = "application/octet-stream") -> dict[str, Any]:
        token = uuid.uuid4().hex[:16]
        size = path.stat().st_size if path.exists() else 0
        meta = {
            "token": token,
            "path": path,
            "name": _safe_filename(name, "artifact.bin"),
            "kind": kind,
            "size_bytes": size,
            "mimetype": mimetype,
            "created_at": _utc_now_iso(),
        }
        with lock:
            artifacts[token] = meta
        return {
            "token": token,
            "name": meta["name"],
            "kind": kind,
            "size_bytes": size,
            "download_url": f"/api/v1/artifacts/{token}/download",
        }

    def _sample_file_exists(s: dict[str, Any]) -> bool:
        p = s.get("path")
        return bool(p is not None and Path(p).exists())

    def _public_sample(s: dict[str, Any], include_details: bool = False) -> dict[str, Any]:
        file_ok = _sample_file_exists(s)
        ai_list = s.get("ai_analyses") or []
        out: dict[str, Any] = {
            "id": s["id"],
            "workspace_id": s.get("workspace_id") or _active_ws_id(),
            "name": s["name"],
            "kind": s["kind"],
            "source": s["source"],
            "file_available": file_ok,
            "display_path": s["display_path"],
            "size_bytes": s["size_bytes"],
            "size_mb": round(s["size_bytes"] / (1024 * 1024), 2),
            "sha256": s["sha256"],
            "created_at": s["created_at"],
            "updated_at": s.get("updated_at") or s["created_at"],
            "dex_count": s.get("dex_count", 0),
            "packer": (s.get("scan_result") or {}).get("packer_name"),
            "protection_level": (s.get("scan_result") or {}).get("protection_level"),
            "risk_score": (s.get("inspect_result") or {}).get("risk_score")
            or (s.get("scan_result") or {}).get("risk_score"),
            "last_job_id": s.get("last_job_id"),
            "has_scan": s.get("scan_result") is not None,
            "has_inspect": s.get("inspect_result") is not None,
            "has_vmp": s.get("vmp_result") is not None,
            "has_xref": s.get("xref_result") is not None,
            "has_repair": bool(s.get("repair_diffs")),
            "notes": s.get("notes") or "",
            "bookmarks_count": len(s.get("bookmarks") or []),
            "ai_analyses_count": len(ai_list),
        }
        if include_details:
            out["scan_result"] = s.get("scan_result")
            out["inspect_result"] = s.get("inspect_result")
            out["vmp_result"] = s.get("vmp_result")
            out["xref_result"] = s.get("xref_result")
            out["verify_results"] = s.get("verify_results")
            out["repair_diffs"] = s.get("repair_diffs")
            out["artifacts"] = s.get("artifacts", [])
            out["bookmarks"] = list(s.get("bookmarks") or [])
            out["ai_analyses"] = list(ai_list)
        return out

    def _save_uploaded_file(file_storage) -> dict[str, Any]:
        raw_name = file_storage.filename or ""
        safe_name = _safe_filename(raw_name, "")
        ext = Path(safe_name).suffix.lower()
        if not safe_name or ext not in ALLOWED_UPLOAD_EXTS:
            raise ValueError("Only .apk and .dex files are supported")

        tmp_dir = uploads_dir / uuid.uuid4().hex[:10]
        tmp_dir.mkdir(parents=True, exist_ok=True)
        dest = tmp_dir / safe_name
        file_storage.save(str(dest))

        if ext == ".apk" and not _is_valid_apk_zip(dest):
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise ValueError(f"'{safe_name}' is not a valid APK archive")
        if ext == ".dex" and not _is_valid_dex_header(dest):
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise ValueError(f"'{safe_name}' does not have a valid DEX/CDEX header")

        sha = _file_sha256(dest)
        sid = sha[:16]
        with lock:
            if sid in samples:
                existing = samples[sid]
                if not _sample_file_exists(existing):
                    existing["path"] = dest
                    existing["source"] = "upload"
                    existing["work_dir"] = tmp_dir
                    existing["file_available"] = True
                    existing["display_path"] = f"upload://{safe_name}"
                else:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                return existing

            dex_count = 1 if ext == ".dex" else _count_apk_dex(dest)
            record = {
                "id": sid,
                "workspace_id": _active_ws_id(),
                "name": safe_name,
                "kind": "apk" if ext == ".apk" else "dex",
                "source": "upload",
                "path": dest,
                "source_path": str(dest),
                "file_available": True,
                "work_dir": tmp_dir,
                "display_path": f"upload://{safe_name}",
                "size_bytes": dest.stat().st_size,
                "sha256": sha,
                "created_at": _utc_now_iso(),
                "updated_at": _utc_now_iso(),
                "dex_count": dex_count,
                "scan_result": None,
                "inspect_result": None,
                "vmp_result": None,
                "xref_result": None,
                "verify_results": None,
                "repair_diffs": None,
                "quality_report": None,
                "last_job_id": None,
                "artifacts": [],
                "notes": "",
                "bookmarks": [],
                "ai_analyses": [],
            }
            samples[sid] = record
        _persist_sample(record)
        return record

    def _import_local_sample(resolved: Path) -> dict[str, Any]:
        if resolved.is_dir():
            sha, total_size, dex_count = _dir_fingerprint(resolved)
            if dex_count == 0:
                raise ValueError(f"Directory '{resolved.name}' contains no .dex files")
            kind = "dex_dir"
            name = resolved.name
        else:
            ext = resolved.suffix.lower()
            if ext not in ALLOWED_UPLOAD_EXTS:
                raise ValueError("Local sample must be an .apk, .dex, or DEX directory")
            sha = _file_sha256(resolved)
            total_size = resolved.stat().st_size
            kind = "apk" if ext == ".apk" else "dex"
            dex_count = 1 if kind == "dex" else _count_apk_dex(resolved)
            name = resolved.name

        sid = sha[:16]
        with lock:
            if sid in samples:
                existing = samples[sid]
                if not _sample_file_exists(existing):
                    existing["path"] = resolved
                    existing["source_path"] = str(resolved)
                    existing["source"] = "local"
                    existing["file_available"] = True
                    existing["display_path"] = _relative_display_path(resolved, allowed_local_roots)
                return existing

            work_dir = uploads_dir / f"local_{sid}"
            work_dir.mkdir(parents=True, exist_ok=True)
            rel_display = _relative_display_path(resolved, allowed_local_roots)
            record = {
                "id": sid,
                "workspace_id": _active_ws_id(),
                "name": name,
                "kind": kind,
                "source": "local",
                "path": resolved,
                "source_path": str(resolved),
                "file_available": True,
                "work_dir": work_dir,
                "display_path": rel_display,
                "size_bytes": total_size,
                "sha256": sha,
                "created_at": _utc_now_iso(),
                "updated_at": _utc_now_iso(),
                "dex_count": dex_count,
                "scan_result": None,
                "inspect_result": None,
                "vmp_result": None,
                "xref_result": None,
                "verify_results": None,
                "repair_diffs": None,
                "quality_report": None,
                "last_job_id": None,
                "artifacts": [],
                "notes": "",
                "bookmarks": [],
                "ai_analyses": [],
            }
            samples[sid] = record
        _persist_sample(record)
        return record

    def _count_apk_dex(apk_path: Path) -> int:
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                return sum(1 for n in zf.namelist() if n.endswith(".dex") and "/" not in n)
        except Exception:
            return 0

    def _relative_display_path(p: Path, roots: list[Path]) -> str:
        for r in roots:
            try:
                rel = p.resolve().relative_to(r.resolve())
                return f"{r.name}/{rel.as_posix()}" if str(rel) != "." else r.name
            except ValueError:
                continue
        return p.name

    def _get_sample_or_404(sample_id: str) -> dict[str, Any] | None:
        with lock:
            return samples.get(sample_id)

    def _list_sample_dex_entries(sample: dict[str, Any]) -> list[dict[str, Any]]:
        path: Path | None = sample.get("path")
        if path is None or not path.exists():
            insp = sample.get("inspect_result") or {}
            return list(insp.get("dex_files") or [])
        kind = sample["kind"]
        entries: list[dict[str, Any]] = []

        if kind == "dex":
            raw = path.read_bytes()
            entries.append(_dex_quick_meta(path.name, raw))
        elif kind == "dex_dir":
            for p in sorted(path.glob("*.dex")):
                if p.is_file():
                    entries.append(_dex_quick_meta(p.name, p.read_bytes()[:0x70], full_size=p.stat().st_size))
        elif kind == "apk":
            with zipfile.ZipFile(path, "r") as zf:
                dex_names = sorted(n for n in zf.namelist() if n.endswith(".dex") and "/" not in n)
                for name in dex_names:
                    info = zf.getinfo(name)
                    with zf.open(name) as fp:
                        head = fp.read(0x70)
                    entries.append(_dex_quick_meta(name, head, full_size=info.file_size))
        return entries

    def _dex_quick_meta(name: str, head: bytes, full_size: int | None = None) -> dict[str, Any]:
        sz = full_size if full_size is not None else len(head)
        magic = ""
        classes = methods = strings = 0
        valid_magic = False
        if len(head) >= 0x70 and head[:4] in (b"dex\n", b"cdex"):
            valid_magic = True
            magic = head[:7].decode("ascii", errors="replace").replace("\n", " ")
            strings = struct.unpack_from("<I", head, 56)[0]
            methods = struct.unpack_from("<I", head, 88)[0]
            classes = struct.unpack_from("<I", head, 96)[0]
        return {
            "name": name,
            "size_bytes": sz,
            "size_kb": round(sz / 1024, 1),
            "magic": magic,
            "valid_magic": valid_magic,
            "classes": classes,
            "methods": methods,
            "strings": strings,
        }

    def _read_sample_dex_bytes(sample: dict[str, Any], dex_name: str) -> bytes | None:
        safe = _safe_filename(dex_name, "")
        if not safe or safe != dex_name:
            return None
        path: Path | None = sample.get("path")
        if path is None or not path.exists():
            return None
        kind = sample["kind"]
        if kind == "dex":
            return path.read_bytes() if path.name == safe else None
        if kind == "dex_dir":
            target = (path / safe).resolve()
            if target.is_relative_to(path.resolve()) and target.is_file():
                return target.read_bytes()
            return None
        if kind == "apk":
            with zipfile.ZipFile(path, "r") as zf:
                if safe in zf.namelist():
                    return zf.read(safe)
        return None

    def _get_dex_browser(sample: dict[str, Any], dex_name: str) -> _DexBrowserSession | None:
        key = (sample["id"], dex_name)
        with lock:
            if key in dex_sessions:
                dex_sessions.move_to_end(key)
                return dex_sessions[key]

        raw = _read_sample_dex_bytes(sample, dex_name)
        if raw is None:
            return None
        session = _DexBrowserSession(raw, dex_name)
        with lock:
            dex_sessions[key] = session
            while len(dex_sessions) > MAX_DEX_CACHE:
                dex_sessions.popitem(last=False)
        return session

    def _extract_sample_dex_files(sample: dict[str, Any], target_dir: Path, dex_names: list[str] | None = None) -> list[Path]:
        """Materialize selected or all DEX files of a sample into target_dir."""
        target_dir.mkdir(parents=True, exist_ok=True)
        path: Path | None = sample.get("path")
        if path is None or not path.exists():
            return []
        kind = sample["kind"]
        out: list[Path] = []
        wanted = set(dex_names) if dex_names else None

        if kind == "dex":
            if wanted is None or path.name in wanted:
                dst = target_dir / path.name
                shutil.copy2(path, dst)
                out.append(dst)
        elif kind == "dex_dir":
            for p in sorted(path.glob("*.dex")):
                if p.is_file() and (wanted is None or p.name in wanted):
                    dst = target_dir / p.name
                    shutil.copy2(p, dst)
                    out.append(dst)
        elif kind == "apk":
            with zipfile.ZipFile(path, "r") as zf:
                for name in sorted(zf.namelist()):
                    if name.endswith(".dex") and "/" not in name:
                        if wanted is None or name in wanted:
                            dst = target_dir / _safe_filename(name, "classes.dex")
                            dst.write_bytes(zf.read(name))
                            out.append(dst)
        return out

    # Auto-restore saved samples for the default workspace on startup
    _restore_workspace_samples(DEFAULT_WORKSPACE_ID)

    # ── Structured Error Handlers ──

    @app.errorhandler(400)
    def handle_400(e):
        return jsonify(error=str(getattr(e, "description", e)), code="BAD_REQUEST"), 400

    @app.errorhandler(403)
    def handle_403(e):
        return jsonify(error=str(getattr(e, "description", e)), code="FORBIDDEN"), 403

    @app.errorhandler(404)
    def handle_404(e):
        if request.path.startswith("/api/"):
            return jsonify(error="Not found", code="NOT_FOUND"), 404
        return render_template("index.html", version=APP_VERSION), 404

    @app.errorhandler(413)
    def handle_413(e):
        mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return jsonify(error=f"Upload exceeds maximum limit ({mb} MB)", code="PAYLOAD_TOO_LARGE"), 413

    @app.errorhandler(500)
    def handle_500(e):
        return jsonify(error=str(getattr(e, "description", e)), code="INTERNAL_ERROR"), 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        if isinstance(e, HTTPException):
            if request.path.startswith("/api/"):
                return jsonify(error=e.description, code=f"HTTP_{e.code}"), e.code
            return e
        if request.path.startswith("/api/"):
            code = getattr(e, "code", "INTERNAL_ERROR")
            if hasattr(code, "value"):
                code = code.value
            return jsonify(error=str(e), code=str(code)), 500
        return render_template("index.html", version=APP_VERSION), 500

    # ── UI Entrypoint ──

    @app.route("/")
    def index():
        return render_template("index.html", version=APP_VERSION)

    @app.route("/favicon.ico")
    def favicon():
        return Response(status=204)

    # =======================================================================
    # Studio v1 API
    # =======================================================================

    @app.get("/api/v1/health")
    def api_v1_health():
        with lock:
            s_cnt = len(samples)
        return jsonify(
            status="ok",
            app="UNPACK Studio",
            version=APP_VERSION,
            sample_count=s_cnt,
            local_roots=[r.name for r in allowed_local_roots],
        )

    @app.get("/api/v1/doctor")
    def api_v1_doctor():
        check_devices = _parse_bool(request.args.get("check_devices"), default=True)
        return jsonify(_get_doctor_cached(check_devices=check_devices, force_refresh=check_devices))

    @app.get("/api/v1/local-library")
    def api_v1_local_library():
        items: list[dict[str, Any]] = []
        for root in allowed_local_roots:
            if not root.exists():
                continue
            try:
                children = sorted(root.iterdir(), key=lambda p: p.name.lower())
            except OSError:
                continue
            for child in children:
                if child.name.startswith("."):
                    continue
                if child.is_file() and child.suffix.lower() in ALLOWED_UPLOAD_EXTS:
                    sz = child.stat().st_size
                    items.append(
                        {
                            "name": child.name,
                            "kind": "apk" if child.suffix.lower() == ".apk" else "dex",
                            "root": root.name,
                            "path": str(child.resolve()),
                            "display_path": f"{root.name}/{child.name}",
                            "size_bytes": sz,
                            "size_mb": round(sz / (1024 * 1024), 2),
                        }
                    )
                elif child.is_dir():
                    dex_files = [p for p in child.glob("*.dex") if p.is_file()]
                    if dex_files:
                        total_sz = sum(p.stat().st_size for p in dex_files)
                        items.append(
                            {
                                "name": child.name,
                                "kind": "dex_dir",
                                "root": root.name,
                                "path": str(child.resolve()),
                                "display_path": f"{root.name}/{child.name}",
                                "dex_count": len(dex_files),
                                "size_bytes": total_sz,
                                "size_mb": round(total_sz / (1024 * 1024), 2),
                            }
                        )
        return jsonify(roots=[r.name for r in allowed_local_roots], items=items)

    @app.get("/api/v1/samples")
    def api_v1_samples():
        with lock:
            items = [_public_sample(s) for s in reversed(samples.values())]
        return jsonify(items=items)

    @app.post("/api/v1/samples/upload")
    def api_v1_samples_upload():
        files = request.files.getlist("files") or request.files.getlist("file")
        files = [f for f in files if f and f.filename]
        if not files:
            return jsonify(error="No .apk or .dex files provided", code="NO_FILE"), 400

        auto_scan = _parse_bool(request.form.get("auto_scan"), default=True)
        uploaded = []
        errors = []
        for f in files:
            try:
                rec = _save_uploaded_file(f)
                if auto_scan and rec["kind"] == "apk" and rec["scan_result"] is None:
                    try:
                        scan_dict = _scan_apk_rich(rec["path"])
                        with lock:
                            rec["scan_result"] = scan_dict
                        _persist_sample(rec)
                    except Exception:
                        pass
                uploaded.append(_public_sample(rec, include_details=True))
            except ValueError as exc:
                errors.append({"file": f.filename, "error": str(exc)})

        if not uploaded and errors:
            return jsonify(error=errors[0]["error"], errors=errors, code="INVALID_FILE"), 400
        return jsonify(items=uploaded, errors=errors), 201

    @app.post("/api/v1/samples/import-local")
    def api_v1_samples_import_local():
        body = request.get_json(silent=True) or {}
        raw_path = body.get("path", "")
        auto_scan = _parse_bool(body.get("auto_scan"), default=True)

        resolved = _resolve_allowed_local_path(raw_path, allowed_local_roots)
        if resolved is None:
            return jsonify(error="Path is outside allowlisted local library roots or does not exist", code="FORBIDDEN_PATH"), 403

        try:
            rec = _import_local_sample(resolved)
        except ValueError as exc:
            return jsonify(error=str(exc), code="INVALID_SAMPLE"), 400

        if auto_scan and rec["kind"] == "apk" and rec["scan_result"] is None:
            try:
                scan_dict = _scan_apk_rich(rec["path"])
                with lock:
                    rec["scan_result"] = scan_dict
                _persist_sample(rec)
            except Exception:
                pass

        return jsonify(sample=_public_sample(rec, include_details=True))

    @app.get("/api/v1/samples/<sample_id>")
    def api_v1_sample_detail(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        return jsonify(sample=_public_sample(sample, include_details=True))

    @app.delete("/api/v1/samples/<sample_id>")
    def api_v1_sample_delete(sample_id: str):
        with lock:
            sample = samples.pop(sample_id, None)
            if sample is None:
                return jsonify(error="Sample not found", code="NOT_FOUND"), 404
            for k in [k for k in dex_sessions if k[0] == sample_id]:
                dex_sessions.pop(k, None)
        try:
            ws_store.delete_sample(sample_id)
        except Exception:
            pass
        if sample["source"] == "upload" and sample.get("work_dir"):
            shutil.rmtree(sample["work_dir"], ignore_errors=True)
        return jsonify(deleted=True, id=sample_id)

    @app.patch("/api/v1/samples/<sample_id>/notes")
    def api_v1_sample_notes(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        body = request.get_json(silent=True) or {}
        notes = body.get("notes")
        bookmarks = body.get("bookmarks")
        if bookmarks is not None and not isinstance(bookmarks, list):
            return jsonify(error="'bookmarks' must be a list", code="BAD_REQUEST"), 400
        with lock:
            if notes is not None:
                sample["notes"] = str(notes)
            if bookmarks is not None:
                sample["bookmarks"] = list(bookmarks)
        _persist_sample(sample)
        ws_store.update_sample_notes(
            sample_id,
            notes=sample["notes"] if notes is not None else None,
            bookmarks=sample["bookmarks"] if bookmarks is not None else None,
        )
        return jsonify(sample=_public_sample(sample, include_details=True))

    # ── Scan & Inspect ──

    @app.post("/api/v1/samples/<sample_id>/scan")
    def api_v1_sample_scan(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        if sample["kind"] != "apk":
            return jsonify(error="Packer scanning requires an APK sample", code="UNSUPPORTED_KIND"), 400
        if not _sample_file_exists(sample):
            if sample.get("scan_result"):
                return jsonify(scan=sample["scan_result"], sample=_public_sample(sample))
            return jsonify(error="Original APK file is no longer on disk (saved snapshot only)", code="FILE_UNAVAILABLE"), 400

        scan_dict = _scan_apk_rich(sample["path"])
        with lock:
            sample["scan_result"] = scan_dict
        _persist_sample(sample)
        return jsonify(scan=scan_dict, sample=_public_sample(sample))

    def _ensure_apk_inspect(sample: dict[str, Any], force: bool = False) -> dict[str, Any]:
        sid = sample["id"]
        with lock:
            slock = inspect_locks.setdefault(sid, threading.Lock())
        with slock:
            if sample["inspect_result"] is None or force:
                if not _sample_file_exists(sample):
                    return sample.get("inspect_result") or {
                        "file": sample["name"],
                        "sha256": sample["sha256"],
                        "size_bytes": sample["size_bytes"],
                        "manifest": {},
                        "signing": {},
                        "permissions": [],
                        "components": {"activities": [], "services": [], "receivers": [], "providers": []},
                        "native_libs": [],
                        "dex_files": [],
                        "findings": [],
                        "risk_score": 0,
                        "risk_grade": "A",
                        "warnings": ["Original APK file not on disk; showing saved snapshot."],
                    }
                insp = _inspect_apk_rich(sample["path"])
                with lock:
                    sample["inspect_result"] = insp
                _persist_sample(sample)
            return sample["inspect_result"]

    @app.get("/api/v1/samples/<sample_id>/inspect")
    def api_v1_sample_inspect(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404

        force = _parse_bool(request.args.get("refresh"), default=False)
        if sample["kind"] == "apk":
            return jsonify(inspect=_ensure_apk_inspect(sample, force=force))

        # DEX / DEX dir inspect overview
        dex_list = _list_sample_dex_entries(sample)
        overview = {
            "file": sample["name"],
            "sha256": sample["sha256"],
            "size_bytes": sample["size_bytes"],
            "kind": sample["kind"],
            "dex_files": dex_list,
            "manifest": None,
            "signing": None,
            "permissions": [],
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
            "native_libs": [],
            "findings": [],
            "risk_score": 0,
            "risk_grade": "A",
            "warnings": [],
        }
        return jsonify(inspect=overview)

    # ── DEX Browser & Disassembly Preview ──

    @app.get("/api/v1/samples/<sample_id>/dex")
    def api_v1_sample_dex_list(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        return jsonify(dex_files=_list_sample_dex_entries(sample))

    @app.get("/api/v1/samples/<sample_id>/dex/<dex_name>/classes")
    def api_v1_sample_dex_classes(sample_id: str, dex_name: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        try:
            offset = _parse_int(request.args.get("offset"), 0, min_val=0, name="offset")
            limit = _parse_int(request.args.get("limit"), 100, min_val=1, max_val=500, name="limit")
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400

        browser = _get_dex_browser(sample, dex_name)
        if browser is None:
            return jsonify(error=f"DEX '{dex_name}' not found", code="NOT_FOUND"), 404

        q = request.args.get("q", "")
        pkg = request.args.get("package", "")
        health = request.args.get("health", "")
        data = browser.list_classes(query=q, package=pkg, health=health, offset=offset, limit=limit)
        data["summary"] = browser.summary()
        return jsonify(data)

    @app.get("/api/v1/samples/<sample_id>/dex/<dex_name>/class")
    def api_v1_sample_dex_class_detail(sample_id: str, dex_name: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        class_name = request.args.get("name", "")
        if not class_name:
            return jsonify(error="Missing 'name' query parameter", code="BAD_REQUEST"), 400
        browser = _get_dex_browser(sample, dex_name)
        if browser is None:
            return jsonify(error=f"DEX '{dex_name}' not found", code="NOT_FOUND"), 404
        detail = browser.inspect_class(class_name)
        if detail is None:
            return jsonify(error=f"Class '{class_name}' not found", code="NOT_FOUND"), 404
        return jsonify(detail)

    @app.get("/api/v1/samples/<sample_id>/dex/<dex_name>/disasm")
    def api_v1_sample_dex_disasm(sample_id: str, dex_name: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        class_name = request.args.get("class", "")
        method_name = request.args.get("method", "")
        if not class_name or not method_name:
            return jsonify(error="Both 'class' and 'method' query parameters are required", code="BAD_REQUEST"), 400
        try:
            method_idx = (
                _parse_int(request.args.get("method_idx"), 0, min_val=0, name="method_idx")
                if request.args.get("method_idx") not in (None, "")
                else None
            )
            max_insns = _parse_int(request.args.get("max_insns"), 500, min_val=1, max_val=2000, name="max_insns")
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400

        browser = _get_dex_browser(sample, dex_name)
        if browser is None:
            return jsonify(error=f"DEX '{dex_name}' not found", code="NOT_FOUND"), 404
        disasm = browser.disassemble_method(class_name, method_name, method_idx=method_idx, max_insns=max_insns)
        if disasm is None:
            return jsonify(error="Method not found", code="NOT_FOUND"), 404
        return jsonify(disasm)

    @app.get("/api/v1/samples/<sample_id>/dex/<dex_name>/strings")
    def api_v1_sample_dex_strings(sample_id: str, dex_name: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        try:
            limit = _parse_int(request.args.get("limit"), 100, min_val=1, max_val=500, name="limit")
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400
        browser = _get_dex_browser(sample, dex_name)
        if browser is None:
            return jsonify(error=f"DEX '{dex_name}' not found", code="NOT_FOUND"), 404
        q = request.args.get("q", "")
        return jsonify(strings=browser.search_strings(query=q, limit=limit))

    # ── VMP & Xref Analysis ──

    @app.post("/api/v1/samples/<sample_id>/vmp")
    def api_v1_sample_vmp(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404

        body = request.get_json(silent=True) or {}
        selected_dex = body.get("dex_name")
        dex_entries = _list_sample_dex_entries(sample)
        if not dex_entries:
            return jsonify(error="No DEX files found in sample", code="NO_DEX"), 400

        target_names = [selected_dex] if selected_dex else [d["name"] for d in dex_entries[:12]]
        total_methods = normal_count = nop_count = vmp_count = 0
        all_vmp_methods: list[dict[str, Any]] = []
        all_call_graph: list[dict[str, Any]] = []
        dispatcher_counts: dict[str, int] = {}
        class_counts: dict[str, int] = {}
        per_dex: list[dict[str, Any]] = []

        for dname in target_names:
            raw = _read_sample_dex_bytes(sample, dname)
            if raw is None:
                continue
            rep = _analyze_vmp_dex_bytes(raw, dname)
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
                    all_vmp_methods.append({**m, "class": cls, "class_name": cls, "method": meth, "method_name": meth, "dex": dname})
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

        merged = {
            "dex_analyzed": len(per_dex),
            "total_dex": len(dex_entries),
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
        with lock:
            sample["vmp_result"] = merged
        _persist_sample(sample)
        return jsonify(vmp=merged)

    @app.post("/api/v1/samples/<sample_id>/xref")
    def api_v1_sample_xref(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404

        body = request.get_json(silent=True) or {}
        dex_name = body.get("dex_name")
        try:
            limit = _parse_int(body.get("limit"), 100, min_val=10, max_val=500, name="limit")
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400

        dex_entries = _list_sample_dex_entries(sample)
        if not dex_entries:
            return jsonify(error="No DEX files found in sample", code="NO_DEX"), 400

        target = dex_name or dex_entries[0]["name"]
        raw = _read_sample_dex_bytes(sample, target)
        if raw is None:
            return jsonify(error=f"DEX '{target}' not found", code="NOT_FOUND"), 404

        summary = _analyze_xref_dex_bytes(raw, limit=limit)
        summary["dex_name"] = target
        with lock:
            sample["xref_result"] = summary
        _persist_sample(sample)
        return jsonify(xref=summary)

    # ── Repair & Verify Lab ──

    @app.post("/api/v1/samples/<sample_id>/verify")
    def api_v1_sample_verify(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404

        body = request.get_json(silent=True) or {}
        dex_names = body.get("dex_names")
        with tempfile.TemporaryDirectory(prefix="unpack_verify_") as td:
            extracted = _extract_sample_dex_files(sample, Path(td), dex_names=dex_names)
            if not extracted:
                return jsonify(error="No DEX files available to verify", code="NO_DEX"), 400
            results = [_verify_dex_rich(p) for p in extracted]

        valid_count = sum(1 for r in results if r.get("valid"))
        avg_health = round(sum(float(r.get("health_score", 0)) for r in results) / len(results), 1)
        summary = {
            "total": len(results),
            "valid_count": valid_count,
            "invalid_count": len(results) - valid_count,
            "avg_health": avg_health,
            "results": results,
        }
        with lock:
            sample["verify_results"] = results
        return jsonify(summary)

    @app.post("/api/v1/samples/<sample_id>/repair")
    def api_v1_sample_repair(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404

        body = request.get_json(silent=True) or {}
        dex_names = body.get("dex_names")

        run_dir = artifacts_dir / f"repair_{sample_id}_{uuid.uuid4().hex[:6]}"
        src_dir = run_dir / "src"
        out_dir = run_dir / "repaired"
        out_dir.mkdir(parents=True, exist_ok=True)

        extracted = _extract_sample_dex_files(sample, src_dir, dex_names=dex_names)
        if not extracted:
            return jsonify(error="No DEX files available to repair", code="NO_DEX"), 400

        diffs = []
        repaired_files: list[Path] = []
        for p in extracted:
            diff, out_p = _repair_dex_with_diff(p, out_dir)
            diffs.append(diff)
            if out_p and out_p.exists():
                repaired_files.append(out_p)

        # Bundle repaired DEX files as downloadable zip
        zip_path = run_dir / f"{Path(sample['name']).stem}_repaired_dex.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rf in repaired_files:
                zf.write(rf, arcname=rf.name)

        art = _register_artifact(zip_path, zip_path.name, "repaired_dex_bundle", "application/zip")
        with lock:
            sample["repair_diffs"] = diffs
            sample["repaired_dir"] = out_dir
            sample["artifacts"] = [art, *sample.get("artifacts", [])][:20]
        _persist_sample(sample)

        resolved_total = sum(len(d.get("resolved_issues", [])) for d in diffs)
        return jsonify(
            total=len(diffs),
            resolved_issues_total=resolved_total,
            diffs=diffs,
            artifact=art,
        )

    # ── Repack & FART Export ──

    @app.post("/api/v1/samples/<sample_id>/repack")
    def api_v1_sample_repack(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        if sample["kind"] != "apk":
            return jsonify(error="Base sample for repacking must be an APK", code="UNSUPPORTED_KIND"), 400

        body = request.get_json(silent=True) or {}
        dex_sample_id = body.get("dex_sample_id")
        strip_sigs = _parse_bool(body.get("strip_signatures"), default=True)

        dex_dir: Path | None = None
        if dex_sample_id:
            dex_sample = _get_sample_or_404(dex_sample_id)
            if dex_sample is None:
                return jsonify(error="Selected DEX source sample not found", code="NOT_FOUND"), 404
            if dex_sample["kind"] == "dex_dir":
                dex_dir = dex_sample["path"]
            else:
                tmp_dex = artifacts_dir / f"repack_dex_{uuid.uuid4().hex[:6]}"
                _extract_sample_dex_files(dex_sample, tmp_dex)
                dex_dir = tmp_dex
        elif sample.get("repaired_dir") and Path(sample["repaired_dir"]).exists():
            dex_dir = Path(sample["repaired_dir"])
        else:
            # Extract original DEXs if user simply wants to strip signatures / repack
            tmp_dex = artifacts_dir / f"repack_dex_{uuid.uuid4().hex[:6]}"
            _extract_sample_dex_files(sample, tmp_dex)
            dex_dir = tmp_dex

        out_dir = artifacts_dir / f"repack_{sample_id}_{uuid.uuid4().hex[:6]}"
        from unpack.repack.repacker import Repacker

        repacker = Repacker()
        try:
            rr = repacker.repack(sample["path"], dex_dir, out_dir, strip_signatures=strip_sigs)
        except TypeError:
            rr = repacker.repack(sample["path"], dex_dir, out_dir)

        if not rr.success or not rr.output_path:
            return jsonify(error=rr.error or "Repack failed", code="REPACK_FAILED"), 400

        art = _register_artifact(
            rr.output_path,
            rr.output_path.name,
            "repacked_apk",
            "application/vnd.android.package-archive",
        )
        with lock:
            sample["artifacts"] = [art, *sample.get("artifacts", [])][:20]

        res_dict = (
            rr.to_dict()
            if hasattr(rr, "to_dict")
            else {
                "success": rr.success,
                "output": rr.output_path.name,
                "dex_count": rr.dex_count,
                "resources_preserved": rr.resources_preserved,
            }
        )
        return jsonify(repack=res_dict, artifact=art)

    @app.post("/api/v1/samples/<sample_id>/export/fart")
    def api_v1_sample_export_fart(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404

        body = request.get_json(silent=True) or {}
        dex_names = body.get("dex_names")
        run_dir = artifacts_dir / f"fart_{sample_id}_{uuid.uuid4().hex[:6]}"
        src_dir = run_dir / "dex"
        out_dir = run_dir / "fart"
        extracted = _extract_sample_dex_files(sample, src_dir, dex_names=dex_names)
        if not extracted:
            return jsonify(error="No DEX files available for FART export", code="NO_DEX"), 400

        from unpack.export.fart import FartExporter

        exporter = FartExporter()
        exported = []
        total_methods = 0
        for p in extracted:
            res = exporter.export(p, out_dir)
            total_methods += res.method_count
            exported.append(
                {
                    "dex": p.name,
                    "method_count": res.method_count,
                    "bin_file": res.bin_path.name,
                    "txt_file": res.txt_path.name,
                }
            )

        zip_path = run_dir / f"{Path(sample['name']).stem}_fart_export.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(out_dir.iterdir()):
                if f.is_file():
                    zf.write(f, arcname=f.name)

        art = _register_artifact(zip_path, zip_path.name, "fart_export", "application/zip")
        with lock:
            sample["artifacts"] = [art, *sample.get("artifacts", [])][:20]

        return jsonify(total_methods=total_methods, files=exported, artifact=art)

    # ── Commercial Report Export ──

    @app.get("/api/v1/reports/<sample_id>")
    @app.get("/api/v1/samples/<sample_id>/reports")
    def api_v1_report(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404

        fmt = request.args.get("format", "html")
        download = _parse_bool(request.args.get("download"), default=False)
        title = request.args.get("title") or None
        lang = _normalize_lang(request.args.get("lang", "en"))

        # Ensure baseline scan & inspect data exist for APK samples
        if sample["kind"] == "apk":
            if sample["scan_result"] is None:
                try:
                    sc = _scan_apk_rich(sample["path"])
                    with lock:
                        sample["scan_result"] = sc
                except Exception:
                    pass
            if sample["inspect_result"] is None:
                try:
                    _ensure_apk_inspect(sample, force=False)
                except Exception:
                    pass

        try:
            content, mime, ext = _render_commercial_report(sample=sample, fmt=fmt, title=title, lang=lang)
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400

        resp = Response(content, mimetype=mime)
        if download:
            dl_name = _safe_filename(f"{Path(sample['name']).stem}_audit_{lang}.{ext}", f"audit.{ext}")
            resp.headers["Content-Disposition"] = f'attachment; filename="{dl_name}"'
        return resp

    # ── Deep Interactive Pipeline Planner & Orchestrator ──

    PIPELINE_MODES = ("offline_audit", "repair_repack", "device_standard", "device_deep")

    def _packer_plain_explanation(scan: dict[str, Any] | None, is_zh: bool) -> str:
        if not scan or not scan.get("packer_name"):
            return (
                "未检测到商用加固壳：APK 内的 DEX 可直接离线提取、反汇编、校验修复并导出审计报告，无需连接 Root 手机。"
                if is_zh
                else "No commercial packer detected: embedded DEX files can be extracted, disassembled, repaired, and audited 100% offline without an Android device."
            )
        pname = scan.get("packer_name", "Unknown")
        lvl = str(scan.get("protection_level") or "unknown").lower()
        if lvl == "vmp":
            return (
                f"检测到 {pname}（VMP 虚拟机保护）：核心业务方法被替换为指向原生解释器的调度桩（Stub）。离线管线可立即识别所有 VMP 桩方法、聚类调度器、分析原生 SO 防护并提取 IOC；若需还原外层/内存 DEX，可连接 Root 真机并启用 Frida 深度模式。"
                if is_zh
                else f"Detected {pname} (VMP Virtualization): protected methods are replaced with stubs dispatching to a native VM interpreter. Offline Audit immediately maps VMP stubs, clusters dispatchers, inspects native SO hardening, and extracts IOCs; connect a rooted device with Frida Deep Mode to recover outer/runtime DEX layers."
            )
        if lvl == "dex2c":
            return (
                f"检测到 {pname}（DEX2C 原生化编译）：Java 字节码已编译为原生 C/C++ SO 函数。离线管线可完整审计 Manifest、权限、ELF 安全特性与 JNI 交叉引用，辅助 IDA/Ghidra 逆向。"
                if is_zh
                else f"Detected {pname} (DEX2C Native Compilation): Dalvik bytecode is compiled into native ELF libraries. Offline Audit surfaces manifest posture, ELF hardening, and JNI cross-references to guide native reverse engineering."
            )
        if lvl == "function_extraction":
            return (
                f"检测到 {pname}（函数抽取保护）：DEX 中的部分方法体被清空或填充为 NOP，在运行时按需还原。离线管线可立即定位所有 NOP 抽取方法并评估覆盖率；若需还原完整方法体，需连接 Root 真机执行「真机深度主动调用」模式。"
                if is_zh
                else f"Detected {pname} (Function Extraction): method bodies are zeroed/NOP-filled at rest and restored on demand at runtime. Offline Audit pinpoints NOP-extracted methods immediately; connect a rooted device and run Live Device Deep Mode to recover code items."
            )
        if lvl == "dex_encryption":
            return (
                f"检测到 {pname}（整体 DEX 加密）：原始 DEX 被加密存储于 assets 或壳代码中，加载时在内存解密。离线管线可先完成壳特征、签名、原生库与静态审计；连接 Root 真机后使用「真机标准动态脱壳」即可从内存完整 Dump。"
                if is_zh
                else f"Detected {pname} (Whole-DEX Encryption): original DEX payloads are encrypted on disk and decrypted in memory at startup. Run Offline Audit for immediate static intelligence, or connect a rooted device for Live Standard Dump."
            )
        return (
            f"检测到 {pname}（保护等级：{lvl}）：建议先执行离线深度审计，再按需选择真机动态脱壳。"
            if is_zh
            else f"Detected {pname} (level: {lvl}): start with Offline Deep Audit and escalate to Live Device unpacking if runtime payloads are missing."
        )

    def _build_pipeline_plan(
        *,
        sample: dict[str, Any],
        mode: str | None = None,
        engine: str = "",
        deep: bool = False,
        timeout_s: int = 15,
        anti_detect: bool = True,
        repack: bool | None = None,
        generate_report: bool = True,
        lang: str = "en",
        check_devices: bool = True,
        refresh_doctor: bool = False,
    ) -> dict[str, Any]:
        is_zh = _normalize_lang(lang) == "zh"

        # Auto-scan APK if not scanned yet so recommendations are informed
        if sample["kind"] == "apk" and sample.get("scan_result") is None:
            try:
                sc = _scan_apk_rich(sample["path"])
                with lock:
                    sample["scan_result"] = sc
            except Exception:
                pass

        scan = sample.get("scan_result") or {}
        doc = _get_doctor_cached(check_devices=check_devices, force_refresh=refresh_doctor)
        devices = doc.get("devices") or []
        online_devices = [d for d in devices if str(d.get("state", "")).lower() == "device"]
        engines_list = doc.get("engines") or []
        avail_engines = [e["name"] for e in engines_list if e.get("available")]

        prot = str(scan.get("protection_level") or "none").lower()
        is_apk = sample["kind"] == "apk"

        # Determine optimal recommended preset
        if not is_apk:
            rec_mode = "repair_repack"
            rec_reason = (
                "当前样本为 DEX / 脱壳目录，推荐「DEX 修复校验与重打包」离线管线：直接修复头校验、生成修复前后对比并完成 VMP/IOC 审计。"
                if is_zh
                else "Current target is a DEX file/directory. Recommended: Repair & Verify offline pipeline to fix headers/checksums, verify diffs, and run VMP/IOC analysis."
            )
        elif not online_devices:
            rec_mode = "offline_audit"
            if scan.get("packer_name"):
                rec_reason = (
                    f"检测到 {scan['packer_name']}（{prot}），但当前未连接在线 ADB 设备。推荐立即运行「离线深度审计管线」：无需手机即可完成壳情报、DEX 修复对比、VMP 桩映射、IOC 抽取与双语审计报告。"
                    if is_zh
                    else f"Detected {scan['packer_name']} ({prot}) with 0 online ADB devices. Recommended: Offline Deep Audit to immediately run packer intel, DEX repair diff, VMP mapping, IOC extraction, and audit reporting without a device."
                )
            else:
                rec_reason = (
                    "未检测到商用加固壳且无需真机环境，推荐「离线深度审计管线」：一键完成 APK 深度剖析、DEX 校验修复、VMP/IOC 分析与报告生成。"
                    if is_zh
                    else "No commercial packer detected and no device needed. Recommended: Offline Deep Audit for complete APK inspection, DEX verification/repair, VMP/IOC analysis, and audit reporting."
                )
        else:
            if prot in {"vmp", "function_extraction"}:
                rec_mode = "device_deep"
                rec_reason = (
                    f"检测到在线 ADB 设备且样本具备 {prot.upper()} 高强度保护，推荐「真机深度主动调用脱壳」以最大化恢复被抽取的函数体。"
                    if is_zh
                    else f"Online ADB device detected and target uses {prot.upper()} protection. Recommended: Live Device Deep Active Invoke to maximize method body recovery."
                )
            elif prot == "dex_encryption":
                rec_mode = "device_standard"
                rec_reason = (
                    "检测到整体 DEX 加密且已连接在线 ADB 设备，推荐「真机标准动态脱壳」从内存恢复完整 DEX。"
                    if is_zh
                    else "Whole-DEX encryption detected with an online ADB device connected. Recommended: Live Standard Dump to recover decrypted DEX payloads from memory."
                )
            else:
                rec_mode = "offline_audit"
                rec_reason = (
                    "未检测到必须真机脱壳的加密壳，推荐先运行「离线深度审计管线」快速产出全量静态情报与报告。"
                    if is_zh
                    else "No runtime encryption shell requires live dumping. Recommended: Offline Deep Audit for fast, deterministic static intelligence and reporting."
                )

        selected_mode = mode if mode in PIPELINE_MODES else rec_mode
        is_device_mode = selected_mode in {"device_standard", "device_deep"}
        effective_repack = (selected_mode == "repair_repack") if repack is None else bool(repack)
        effective_deep = True if selected_mode == "device_deep" else bool(deep)

        # Build Preflight Checks
        checks: list[dict[str, Any]] = []
        checks.append(
            {
                "id": "sample_ready",
                "category": "sample",
                "status": "pass",
                "title": "样本已装载并校验通过" if is_zh else "Target sample mounted & verified",
                "detail": f"{sample['name']} ({sample['kind'].upper()}, {sample.get('dex_count', 0)} DEX)",
                "fix_hint": "",
            }
        )

        if is_device_mode and not is_apk:
            checks.append(
                {
                    "id": "apk_required",
                    "category": "sample",
                    "status": "block",
                    "title": "真机动态脱壳需要 APK 样本" if is_zh else "Live device unpacking requires an APK sample",
                    "detail": (
                        f"当前样本类型为 {sample['kind'].upper()}，无法安装到 Android 设备运行。"
                        if is_zh
                        else f"Current sample is {sample['kind'].upper()} and cannot be installed on Android."
                    ),
                    "fix_hint": (
                        "请切换至「离线深度审计」或「DEX 修复校验」模式，或选择一个 .apk 样本。"
                        if is_zh
                        else "Switch to Offline Audit / Repair & Verify mode, or select an .apk sample."
                    ),
                    "fallback_mode": "repair_repack",
                }
            )

        if is_device_mode:
            if online_devices:
                checks.append(
                    {
                        "id": "adb_device",
                        "category": "device",
                        "status": "pass",
                        "title": "在线 ADB 设备已就绪" if is_zh else "Online ADB device connected",
                        "detail": ", ".join(d["serial"] for d in online_devices[:3]),
                        "fix_hint": "",
                    }
                )
            else:
                checks.append(
                    {
                        "id": "adb_device",
                        "category": "device",
                        "status": "block",
                        "title": "未检测到在线 Android 设备（0 台 ADB 设备）" if is_zh else "No online Android device detected (0 ADB devices)",
                        "detail": (
                            "真机动态脱壳需要通过 USB/无线连接已 Root 的 Android 设备或模拟器，并开启 USB 调试。"
                            if is_zh
                            else "Live dynamic unpacking requires a rooted Android device/emulator connected via ADB with USB debugging enabled."
                        ),
                        "fix_hint": (
                            "运行 `adb devices` 确认设备状态为 device，并确保 `adb root` 可用；或点击下方按钮一键切换至无需设备的「离线深度审计管线」。"
                            if is_zh
                            else "Run `adb devices` to confirm an online rooted device, or click below to switch to the zero-device Offline Deep Audit pipeline."
                        ),
                        "fallback_mode": "offline_audit",
                    }
                )

            req_engine = engine or ("frida" if selected_mode == "device_deep" else "")
            if req_engine and req_engine not in avail_engines:
                checks.append(
                    {
                        "id": "engine_ready",
                        "category": "engine",
                        "status": "block",
                        "title": (
                            f"指定脱壳引擎 `{req_engine}` 当前不可用"
                            if is_zh
                            else f"Selected dump engine `{req_engine}` is unavailable"
                        ),
                        "detail": (
                            f"当前可用引擎：{', '.join(avail_engines) if avail_engines else '无'}。"
                            if is_zh
                            else f"Available engines: {', '.join(avail_engines) if avail_engines else 'none'}."
                        ),
                        "fix_hint": (
                            "在真机启动 frida-server 或检查 root/eBPF 环境，或改用「离线深度审计管线」立即分析静态与已提取 DEX。"
                            if is_zh
                            else "Start frida-server / verify root on device, or switch to Offline Deep Audit for immediate static & DEX analysis."
                        ),
                        "fallback_mode": "offline_audit",
                    }
                )
            elif not avail_engines:
                checks.append(
                    {
                        "id": "engine_ready",
                        "category": "engine",
                        "status": "block",
                        "title": "暂无可用的动态脱壳引擎" if is_zh else "No dynamic dump engines currently ready",
                        "detail": (
                            "Frida / Memory / eBPF 引擎均依赖已连接的 Root 设备。"
                            if is_zh
                            else "Frida, Memory, and eBPF engines all require a connected rooted Android device."
                        ),
                        "fix_hint": (
                            "先在「环境诊断 Doctor」检查 ADB/Frida 状态，或一键切换为「离线深度审计管线」。"
                            if is_zh
                            else "Check Environment Doctor for ADB/Frida setup, or switch to Offline Deep Audit."
                        ),
                        "fallback_mode": "offline_audit",
                    }
                )
            else:
                checks.append(
                    {
                        "id": "engine_ready",
                        "category": "engine",
                        "status": "pass",
                        "title": "动态脱壳引擎就绪" if is_zh else "Dynamic dump engine ready",
                        "detail": ", ".join(avail_engines),
                        "fix_hint": "",
                    }
                )
        else:
            checks.append(
                {
                    "id": "zero_device",
                    "category": "environment",
                    "status": "pass",
                    "title": "零设备离线引擎就绪" if is_zh else "Zero-device offline engine ready",
                    "detail": (
                        "本模式 100% 在本地沙箱执行，不依赖 ADB/Root/Frida 手机。"
                        if is_zh
                        else "Runs 100% locally in an isolated sandbox — no ADB, root, or Android device required."
                    ),
                    "fix_hint": "",
                }
            )
            if sample.get("dex_count", 0) == 0:
                checks.append(
                    {
                        "id": "dex_inventory",
                        "category": "sample",
                        "status": "warn",
                        "title": "样本根目录下未发现明文 DEX 文件" if is_zh else "No top-level DEX files found in sample",
                        "detail": (
                            "APK 可能高度加密或仅包含原生库，DEX 修复/VMP 阶段将自动跳过，静态扫描与 APK 剖析仍会正常执行。"
                            if is_zh
                            else "Archive has no top-level classes*.dex; DEX repair/VMP stages will gracefully skip while scan & APK inspect still complete."
                        ),
                        "fix_hint": "",
                    }
                )
            else:
                checks.append(
                    {
                        "id": "dex_inventory",
                        "category": "sample",
                        "status": "pass",
                        "title": (
                            f"已发现 {sample.get('dex_count', 0)} 个可分析 DEX 文件"
                            if is_zh
                            else f"{sample.get('dex_count', 0)} DEX file(s) ready for inspection & repair"
                        ),
                        "detail": (
                            "可执行非破坏性头修复、校验对比、VMP 检测与 IOC 交叉引用。"
                            if is_zh
                            else "Ready for non-destructive repair, verification diff, VMP stub detection, and IOC xref."
                        ),
                        "fix_hint": "",
                    }
                )

        if effective_repack and not is_apk:
            checks.append(
                {
                    "id": "repack_warn",
                    "category": "options",
                    "status": "warn",
                    "title": "非 APK 样本将跳过重打包" if is_zh else "Repack skipped for non-APK sample",
                    "detail": (
                        "已开启自动重打包，但当前样本为纯 DEX，将仅输出修复后的 DEX ZIP 压缩包。"
                        if is_zh
                        else "Auto Repack is enabled, but sample is raw DEX — a repaired DEX ZIP bundle will be produced instead."
                    ),
                    "fix_hint": "",
                }
            )

        blocking_count = sum(1 for c in checks if c["status"] == "block")
        warning_count = sum(1 for c in checks if c["status"] == "warn")

        # Build Stages Blueprint
        if not is_device_mode:
            has_dex = sample.get("dex_count", 0) > 0
            will_repack = bool(effective_repack and is_apk and has_dex)
            stages = [
                {
                    "id": "intake",
                    "order": 1,
                    "title_key": "stage.intake.title",
                    "title": "样本入库与指纹校验" if is_zh else "Intake & Integrity Fingerprint",
                    "what_it_does": (
                        "计算样本 SHA-256 指纹、校验 ZIP/DEX 结构头，并建立沙箱工作目录以保证所有处理完全非破坏性。"
                        if is_zh
                        else "Computes SHA-256 fingerprint, validates APK/DEX structure, and prepares an isolated sandbox workspace so original files are never modified."
                    ),
                    "why_it_matters": (
                        "确保审计证据可溯源、避免重复计算，并防止修复或重打包操作污染原始样本。"
                        if is_zh
                        else "Guarantees reproducible evidence provenance and protects original artifacts from accidental mutation."
                    ),
                    "inputs": [sample["name"]],
                    "outputs": ["SHA-256 指纹" if is_zh else "SHA-256 Digest", "沙箱工作目录" if is_zh else "Sandbox Workspace"],
                    "will_run": True,
                    "skip_reason": "",
                    "estimated_hint": "< 0.2s",
                    "preflight_status": "pass",
                    "troubleshooting": [
                        "若样本损坏或非合法 ZIP/DEX 头，请先在「样本库」确认文件完整性。"
                        if is_zh
                        else "If intake fails, verify the file is a valid .apk archive or DEX/CDEX payload."
                    ],
                },
                {
                    "id": "scan_inspect",
                    "order": 2,
                    "title_key": "stage.scan_inspect.title",
                    "title": "加固壳识别与 APK 深度剖析" if is_zh else "Deep Packer Scan & APK Intel",
                    "what_it_does": (
                        "匹配 24 种商用加固特征（SO、Application 类、资源、资产文件），同时解析 AndroidManifest、签名方案、危险权限与原生 ELF 缓解措施。"
                        if is_zh
                        else "Evaluates 24 commercial packer signature families (native SOs, Application class, assets) and parses AndroidManifest, signing schemes, dangerous permissions, and ELF mitigations."
                    ),
                    "why_it_matters": (
                        "识别加固类型（整体加密 / 函数抽取 / DEX2C / VMP）决定后续分析深度，同时提前暴露 debuggable、明文流量等高危配置。"
                        if is_zh
                        else "Knowing the protection tier (encryption, function extraction, DEX2C, VMP) guides reverse-engineering strategy while surfacing high-risk manifest issues."
                    ),
                    "inputs": ["APK 归档 / Manifest / lib/*.so" if is_zh else "APK Archive / Manifest / lib/*.so"],
                    "outputs": ["加固判定与证据矩阵" if is_zh else "Packer Verdict & Evidence", "APK 安全风险评级" if is_zh else "APK Risk Findings"],
                    "will_run": is_apk,
                    "skip_reason": ("" if is_apk else ("纯 DEX 样本不含 AndroidManifest，跳过 APK 扫描" if is_zh else "Raw DEX sample has no AndroidManifest; APK scan skipped")),
                    "estimated_hint": "0.5 - 3s",
                    "preflight_status": "pass" if is_apk else "skip",
                    "troubleshooting": [
                        "大型 APK 包含较多原生 SO 时，ELF 剖析可能需要数秒，属正常现象。"
                        if is_zh
                        else "Large APKs with many native .so libraries may take a few seconds during deep ELF inspection."
                    ],
                },
                {
                    "id": "extract_dex",
                    "order": 3,
                    "title_key": "stage.extract_dex.title",
                    "title": "DEX 提取与结构清点" if is_zh else "DEX Extraction & Inventory",
                    "what_it_does": (
                        "将样本中所有内嵌或本地 DEX 拷贝至隔离目录，逐一解析 DEX 魔数、类数、方法数与字符串池规模。"
                        if is_zh
                        else "Materializes all embedded or local classes*.dex files into the job sandbox and reads header metadata (magic, classes, methods, strings)."
                    ),
                    "why_it_matters": (
                        "将 DEX 与容器解耦，为下一步自动修复、校验对比和字节码分析提供干净的输入集。"
                        if is_zh
                        else "Decouples DEX binaries from the APK container to feed deterministic repair, verification, and static analysis."
                    ),
                    "inputs": [sample["name"]],
                    "outputs": ["隔离的 classes*.dex 集合" if is_zh else "Isolated classes*.dex Set"],
                    "will_run": has_dex,
                    "skip_reason": ("" if has_dex else ("样本内未包含可提取的 DEX 文件" if is_zh else "No top-level DEX files present in sample")),
                    "estimated_hint": "< 0.5s",
                    "preflight_status": "pass" if has_dex else "warn",
                    "troubleshooting": [
                        "如果加固壳把真实 DEX 加密藏在 assets 中，静态提取仅能得到壳 DEX，需要连接真机做动态 Dump。"
                        if is_zh
                        else "If a packer encrypts real DEX files inside assets/, static extraction only sees the stub DEX; use Live Device Dump to recover runtime payloads."
                    ],
                },
                {
                    "id": "repair_verify",
                    "order": 4,
                    "title_key": "stage.repair_verify.title",
                    "title": "DEX 自动修复与前后校验对比" if is_zh else "DEX Repair & Before/After Verify Diff",
                    "what_it_does": (
                        "先运行 DexVerifier 记录修复前健康分与错误列表，再执行头魔数修复、file_size 修正、SHA-1/Adler32 重算与 CDEX 处理，最后二次校验并打包可下载的修复 ZIP。"
                        if is_zh
                        else "Runs DexVerifier before repair, fixes corrupted headers/file_size/SHA-1/Adler32/CDEX, re-verifies health deltas, and packages a downloadable repaired DEX ZIP."
                    ),
                    "why_it_matters": (
                        "脱壳或抽取得到的 DEX 常出现校验和错乱、头被抹零等问题，导致 JADX/Ghidra 无法打开；修复前后 Diff 让你直观确认每个问题是否解决。"
                        if is_zh
                        else "Dumped or extracted DEX files often have broken checksums or zeroed headers that crash JADX; before/after diffs prove every structural issue is resolved."
                    ),
                    "inputs": ["提取出的 DEX 文件集" if is_zh else "Extracted DEX Set"],
                    "outputs": ["修复前后健康分对比" if is_zh else "Before/After Health Diff", "repaired_dex.zip 产物" if is_zh else "repaired_dex.zip Artifact"],
                    "will_run": has_dex,
                    "skip_reason": ("" if has_dex else ("无可用 DEX 文件" if is_zh else "No DEX files available")),
                    "estimated_hint": "0.3 - 2s",
                    "preflight_status": "pass" if has_dex else "skip",
                    "troubleshooting": [
                        "若修复后仍有 NOP 方法告警，说明原始方法体被壳函数抽取，需真机「深度主动调用」补全。"
                        if is_zh
                        else "Remaining NOP-method warnings after repair indicate function extraction; use Live Deep Active Invoke on a device to restore them."
                    ],
                },
                {
                    "id": "vmp_xref",
                    "order": 5,
                    "title_key": "stage.vmp_xref.title",
                    "title": "VMP 桩检测、原生库与 IOC 交叉引用" if is_zh else "VMP Stub, Native & Xref/IOC Analysis",
                    "what_it_does": (
                        "扫描每个方法的指令体以分类 Normal / NOP / VMP 调度桩，同时构建反射调用、敏感 API、URL/IP 威胁指标（IOC）索引。"
                        if is_zh
                        else "Classifies every Dalvik method body (Normal / NOP / VMP Stub), clusters VM dispatchers, and indexes reflection sinks, sensitive APIs, and URL/IP IOCs."
                    ),
                    "why_it_matters": (
                        "一键量化虚拟化保护比例，快速定位外联域名、动态加载点与需要重点逆向的原生分发函数。"
                        if is_zh
                        else "Quantifies virtualization coverage at a glance and immediately exposes C2/API URLs, DexClassLoader sinks, and top VM dispatchers."
                    ),
                    "inputs": ["修复后的 DEX 字节码" if is_zh else "Repaired DEX Bytecode"],
                    "outputs": ["VMP 桩与调度器清单" if is_zh else "VMP Stub & Dispatcher Map", "反射与 URL/IP IOC 列表" if is_zh else "Reflection & IOC Index"],
                    "will_run": has_dex,
                    "skip_reason": ("" if has_dex else ("无可用 DEX 文件" if is_zh else "No DEX files available")),
                    "estimated_hint": "0.5 - 4s",
                    "preflight_status": "pass" if has_dex else "skip",
                    "troubleshooting": [
                        "多 DEX 大型应用默认优先分析前 6 个主要 DEX 以确保响应流畅；可在「VMP 与原生分析」按单 DEX 深入查看。"
                        if is_zh
                        else "For huge multi-DEX apps, pipeline analyzes the primary DEX set for fast turnaround; drill into individual DEX files inside VMP & Native Studio."
                    ],
                },
                {
                    "id": "repack_report",
                    "order": 6,
                    "title_key": "stage.repack_report.title",
                    "title": "APK 重打包与商用审计报告导出" if is_zh else "Repack APK & Commercial Audit Report",
                    "what_it_does": (
                        "按选项将修复后的 DEX 回填生成未加固 APK（自动剥离失效 META-INF 签名），并生成自包含的中文/英文商用 HTML 审计报告供分享归档。"
                        if is_zh
                        else "Optionally rebuilds an unpacked APK with repaired DEXs (stripping stale META-INF signatures) and generates a self-contained bilingual HTML security audit report."
                    ),
                    "why_it_matters": (
                        "直接产出可交付给研发/安全团队的独立审计报告与可重签名测试的 APK 产物，闭环整个逆向审计工作流。"
                        if is_zh
                        else "Delivers stakeholder-ready standalone audit reports and re-signable APK artifacts to close the reverse-engineering loop."
                    ),
                    "inputs": ["全阶段扫描/修复/VMP 结果" if is_zh else "All Stage Telemetry & Repaired DEXs"],
                    "outputs": (
                        (["重打包 APK 产物" if is_zh else "Repacked APK Artifact"] if will_repack else [])
                        + (["商用 HTML 审计报告" if is_zh else "Commercial HTML Report"] if generate_report else [])
                    )
                    or (["管线结果摘要" if is_zh else "Pipeline Summary"]),
                    "will_run": bool(will_repack or generate_report),
                    "skip_reason": (
                        ""
                        if (will_repack or generate_report)
                        else ("未勾选「自动重打包」且未勾选「生成审计报告」" if is_zh else "Both Auto Repack and Generate Report are disabled")
                    ),
                    "estimated_hint": "0.5 - 3s",
                    "preflight_status": "pass" if (will_repack or generate_report) else "skip",
                    "troubleshooting": [
                        "重打包后的 APK 已移除原签名，安装到真机前需使用 apksigner 或 uber-apk-signer 重新签名。"
                        if is_zh
                        else "Repacked APKs have stale signatures stripped; re-sign with apksigner before installing on a device."
                    ],
                },
            ]
        else:
            dev_status = "pass" if (online_devices and avail_engines and is_apk) else "block"
            stages = [
                {
                    "id": "intake",
                    "order": 1,
                    "title_key": "stage.intake.title",
                    "title": "样本入库与环境预检" if is_zh else "Intake & Device Pre-Flight",
                    "what_it_does": (
                        "校验目标 APK 完整性并确认 ADB 在线设备、Root 权限及脱壳引擎状态。"
                        if is_zh
                        else "Validates target APK integrity and confirms online ADB device, root access, and selected dump engine readiness."
                    ),
                    "why_it_matters": (
                        "提前拦截设备掉线或权限不足问题，避免在安装/启动阶段长时间等待后报错。"
                        if is_zh
                        else "Catches disconnected devices or missing root privileges upfront instead of timing out mid-run."
                    ),
                    "inputs": [sample["name"], "ADB 设备状态" if is_zh else "ADB Device Status"],
                    "outputs": ["预检通过凭证" if is_zh else "Pre-Flight Check"],
                    "will_run": True,
                    "skip_reason": "",
                    "estimated_hint": "< 0.5s",
                    "preflight_status": "pass" if is_apk else "block",
                    "troubleshooting": [
                        "请先在终端执行 `adb devices` 与 `adb shell su -c id` 验证真机连接。"
                        if is_zh
                        else "Verify connectivity with `adb devices` and `adb shell su -c id`."
                    ],
                },
                {
                    "id": "scan_inspect",
                    "order": 2,
                    "title_key": "stage.scan_inspect.title",
                    "title": "深度壳识别与引擎调度决策" if is_zh else "Deep Packer Scan & Strategy Routing",
                    "what_it_does": (
                        "识别具体加固壳及保护层级，自动匹配最优脱壳引擎（Memory / Frida / eBPF）与反检测参数。"
                        if is_zh
                        else "Identifies the exact packer family and protection tier, routing to the optimal dump engine (Memory / Frida / eBPF) and anti-detection profile."
                    ),
                    "why_it_matters": (
                        "不同加固壳对注入方式敏感度不同，精准路由可显著提升脱壳成功率并减少应用闪退。"
                        if is_zh
                        else "Matching engine strategy to the packer avoids crashes and maximizes DEX recovery rate."
                    ),
                    "inputs": [sample["name"]],
                    "outputs": ["加固判定与引擎策略" if is_zh else "Packer Verdict & Engine Route"],
                    "will_run": True,
                    "skip_reason": "",
                    "estimated_hint": "0.5 - 2s",
                    "preflight_status": "pass" if is_apk else "block",
                    "troubleshooting": [
                        "如自动路由不理想，可在下方参数区手动指定 Memory 或 Frida 引擎。"
                        if is_zh
                        else "You can override auto-routing by manually selecting Memory, Frida, or eBPF below."
                    ],
                },
                {
                    "id": "dynamic_dump",
                    "order": 3,
                    "title_key": "stage.dynamic_dump.title",
                    "title": "真机动态脱壳与 DEX 去重" if is_zh else "Live Device Dynamic DEX Dump",
                    "what_it_does": (
                        f"在真机启动目标应用并等待 {timeout_s}s，利用 {engine or '自动推荐'} 引擎从内存/ART 钩子捕获解密后的 DEX 并自动去重。"
                        if is_zh
                        else f"Launches the target app on device (wait {timeout_s}s), dumps decrypted DEX payloads via {engine or 'auto'} engine, and deduplicates overlapping dumps."
                    ),
                    "why_it_matters": (
                        "这是突破整体 DEX 加密壳的核心步骤，直接获取解密落地前的真实业务逻辑字节码。"
                        if is_zh
                        else "Core step to bypass whole-DEX encryption and capture decrypted business logic directly from process memory."
                    ),
                    "inputs": [sample["name"], "已连接 Root 真机" if is_zh else "Connected Rooted Device"],
                    "outputs": ["去重后的脱壳 DEX 文件集" if is_zh else "Deduplicated Dumped DEX Set"],
                    "will_run": True,
                    "skip_reason": "",
                    "estimated_hint": f"{timeout_s + 5} - {timeout_s + 20}s",
                    "preflight_status": dev_status,
                    "troubleshooting": [
                        "若应用启动慢导致脱壳不完整，可将超时调大至 30~60 秒并勾选「反检测保护」。"
                        if is_zh
                        else "Increase timeout to 30-60s and keep Anti-Detection enabled if the app initializes slowly or detects Frida."
                    ],
                },
                {
                    "id": "active_invoke",
                    "order": 4,
                    "title_key": "stage.active_invoke.title",
                    "title": "深度主动调用与方法体回填" if is_zh else "Deep Active Method Invoke & Merge",
                    "what_it_does": (
                        "通过 Frida 主动枚举类并触发被抽取方法的类初始化/调用，捕获运行时还原的 CodeItem 并合并回 DEX。"
                        if is_zh
                        else "Uses Frida to enumerate classes and actively trigger method resolution, capturing runtime CodeItems and merging them back into dumped DEX files."
                    ),
                    "why_it_matters": (
                        "专门克制「函数抽取」型加固壳，将被清空/NOP 填充的方法体逐一补全。"
                        if is_zh
                        else "Specifically defeats function-extraction packers by restoring NOP-filled method bodies."
                    ),
                    "inputs": ["脱壳 DEX + 运行中目标进程" if is_zh else "Dumped DEXs + Live Process"],
                    "outputs": ["合并完整方法体的 DEX" if is_zh else "Merged CodeItem DEXs"],
                    "will_run": effective_deep,
                    "skip_reason": (
                        ""
                        if effective_deep
                        else ("标准模式默认跳过主动调用（开启「深度主动调用」或切换至「真机深度模式」即可启用）" if is_zh else "Skipped in Standard mode (enable Deep Active Invoke or select Live Deep mode)")
                    ),
                    "estimated_hint": f"{timeout_s + 10}s" if effective_deep else "0s",
                    "preflight_status": (dev_status if effective_deep else "skip"),
                    "troubleshooting": [
                        "主动调用需真机运行与本机版本匹配的 frida-server。"
                        if is_zh
                        else "Active invocation requires a matching frida-server running on the Android device."
                    ],
                },
                {
                    "id": "repair_verify",
                    "order": 5,
                    "title_key": "stage.repair_verify.title",
                    "title": "脱壳 DEX 自动修复与质量校验" if is_zh else "DEX Repair & Quality Verification",
                    "what_it_does": (
                        "修复脱壳 DEX 的头魔数、大小、SHA-1 与 Adler32 校验和，评估方法体覆盖率并打包下载。"
                        if is_zh
                        else "Repairs dumped DEX headers, sizes, SHA-1 and Adler32 checksums, evaluates code coverage, and bundles artifacts."
                    ),
                    "why_it_matters": (
                        "确保脱壳产物可直接导入 JADX、Bytecode Viewer 或回填重打包。"
                        if is_zh
                        else "Ensures dumped DEX binaries open cleanly in JADX and pass structural verification."
                    ),
                    "inputs": ["脱壳原始 DEX" if is_zh else "Raw Dumped DEXs"],
                    "outputs": ["修复对比报告与 DEX ZIP" if is_zh else "Repair Diff & DEX ZIP"],
                    "will_run": True,
                    "skip_reason": "",
                    "estimated_hint": "1 - 3s",
                    "preflight_status": dev_status,
                    "troubleshooting": [
                        "如覆盖率偏低，可尝试勾选深度主动调用模式重跑。"
                        if is_zh
                        else "If code coverage is low, re-run with Deep Active Invoke enabled."
                    ],
                },
                {
                    "id": "repack_report",
                    "order": 6,
                    "title_key": "stage.repack_report.title",
                    "title": "重打包未加固 APK 与审计报告" if is_zh else "Repack Unpacked APK & Audit Report",
                    "what_it_does": (
                        "将修复后的脱壳 DEX 替换回原 APK，并输出完整的商用审计报告。"
                        if is_zh
                        else "Rebuilds an unpacked APK with repaired DEXs and exports a comprehensive commercial audit report."
                    ),
                    "why_it_matters": (
                        "生成可直接复测与归档的最终交付物。"
                        if is_zh
                        else "Produces final deliverable APK and audit report artifacts."
                    ),
                    "inputs": ["修复后 DEX + 原始 APK" if is_zh else "Repaired DEXs + Base APK"],
                    "outputs": ["脱壳重打包 APK" if is_zh else "Unpacked APK", "HTML 审计报告" if is_zh else "HTML Audit Report"],
                    "will_run": bool(effective_repack or generate_report),
                    "skip_reason": "",
                    "estimated_hint": "1 - 4s",
                    "preflight_status": dev_status if (effective_repack or generate_report) else "skip",
                    "troubleshooting": [
                        "重打包产物需重新签名后安装。"
                        if is_zh
                        else "Re-sign the repacked APK with apksigner before installing."
                    ],
                },
            ]

        return {
            "sample_id": sample["id"],
            "sample_name": sample["name"],
            "sample_kind": sample["kind"],
            "mode": selected_mode,
            "recommended_mode": rec_mode,
            "recommendation_reason": rec_reason,
            "packer_name": scan.get("packer_name"),
            "protection_level": prot,
            "packer_explanation": _packer_plain_explanation(scan, is_zh),
            "can_run": blocking_count == 0,
            "blocking_count": blocking_count,
            "warning_count": warning_count,
            "device_count": len(devices),
            "online_device_count": len(online_devices),
            "available_engines": avail_engines,
            "preflight_checks": checks,
            "stages": stages,
            "options": {
                "engine": engine,
                "deep": effective_deep,
                "timeout": timeout_s,
                "anti_detect": anti_detect,
                "repack": effective_repack,
                "generate_report": generate_report,
                "lang": _normalize_lang(lang),
            },
        }

    @app.post("/api/v1/pipeline/plan")
    def api_v1_pipeline_plan():
        body = request.get_json(silent=True) or {}
        sample_id = str(body.get("sample_id", "")).strip()
        if not sample_id:
            return jsonify(error="Missing 'sample_id'", code="BAD_REQUEST"), 400
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404

        mode = body.get("mode")
        if mode is not None and mode != "" and mode not in PIPELINE_MODES:
            return jsonify(error=f"Invalid pipeline mode: {mode!r}", code="BAD_REQUEST"), 400

        engine = str(body.get("engine", ""))
        if engine not in {"", "memory", "frida", "ebpf"}:
            return jsonify(error=f"Invalid engine: {engine!r}", code="BAD_REQUEST"), 400

        try:
            timeout_s = _parse_int(body.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400

        repack_val = body.get("repack")
        repack = None if repack_val is None else _parse_bool(repack_val, default=False)
        plan = _build_pipeline_plan(
            sample=sample,
            mode=mode or None,
            engine=engine,
            deep=_parse_bool(body.get("deep"), default=False),
            timeout_s=timeout_s,
            anti_detect=_parse_bool(body.get("anti_detect"), default=True),
            repack=repack,
            generate_report=_parse_bool(body.get("generate_report"), default=True),
            lang=_normalize_lang(body.get("lang", "en")),
            check_devices=_parse_bool(body.get("check_devices"), default=True),
            refresh_doctor=_parse_bool(body.get("refresh_doctor"), default=False),
        )
        return jsonify(plan)

    def _launch_deep_pipeline_job(
        *,
        sample: dict[str, Any],
        mode: str,
        engine: str,
        timeout_s: int,
        deep: bool,
        anti_detect: bool,
        repack: bool,
        generate_report: bool,
        lang: str,
    ) -> str:
        is_zh = _normalize_lang(lang) == "zh"
        plan = _build_pipeline_plan(
            sample=sample,
            mode=mode,
            engine=engine,
            deep=deep,
            timeout_s=timeout_s,
            anti_detect=anti_detect,
            repack=repack,
            generate_report=generate_report,
            lang=lang,
            check_devices=mode in {"device_standard", "device_deep"},
        )
        initial_stages = [
            {
                "id": st["id"],
                "stage_id": st["id"],
                "order": st["order"],
                "title": st["title"],
                "title_key": st["title_key"],
                "will_run": st["will_run"],
                "skip_reason": st["skip_reason"],
                "status": "pending" if st["will_run"] else "skipped",
                "duration_ms": 0,
                "summary": st["skip_reason"] if not st["will_run"] else "",
                "metrics": {},
                "artifacts": [],
                "next_hint": "",
                "logs": [],
            }
            for st in plan["stages"]
        ]

        job_id = job_mgr.create_job(
            job_type="pipeline",
            apk=sample["name"],
            apk_hash=sample["id"],
            sample_id=sample["id"],
            phase="intake",
            extra={"mode": mode, "lang": _normalize_lang(lang), "stages": initial_stages},
        )
        with lock:
            sample["last_job_id"] = job_id

        output_dir = sample["work_dir"] / f"pipeline_{mode}_{job_id}"
        output_dir.mkdir(parents=True, exist_ok=True)

        def _offline_worker() -> None:
            t0 = time.monotonic()
            try:
                # ── Stage 1: Intake ──
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "intake", 8)
                job_mgr.update_stage(
                    job_id,
                    "intake",
                    status="running",
                    log_message=(
                        f"开始入库校验：{sample['name']}（{sample['kind'].upper()}）"
                        if is_zh
                        else f"Starting intake fingerprint for {sample['name']} ({sample['kind'].upper()})"
                    ),
                )
                dex_entries = _list_sample_dex_entries(sample)
                intake_metrics = {
                    "kind": sample["kind"].upper(),
                    "size_mb": round(sample["size_bytes"] / (1024 * 1024), 2),
                    "dex_count": len(dex_entries),
                    "sha256_short": sample["sha256"][:16],
                }
                job_mgr.set_phase_data(job_id, "intake", intake_metrics)
                job_mgr.update_stage(
                    job_id,
                    "intake",
                    status="done",
                    duration_ms=int((time.monotonic() - st0) * 1000),
                    summary=(
                        f"SHA-256 {sample['sha256'][:12]}… · {len(dex_entries)} 个 DEX · {intake_metrics['size_mb']} MB"
                        if is_zh
                        else f"SHA-256 {sample['sha256'][:12]}… · {len(dex_entries)} DEX · {intake_metrics['size_mb']} MB"
                    ),
                    metrics=intake_metrics,
                    next_hint=(
                        "已完成沙箱隔离准备，进入加固识别与 APK 剖析。"
                        if is_zh
                        else "Sandbox workspace isolated; proceeding to packer scan & APK intelligence."
                    ),
                    log_message=(
                        f"入库校验完成：发现 {len(dex_entries)} 个 DEX 文件。"
                        if is_zh
                        else f"Intake verified: {len(dex_entries)} DEX file(s) inventoried."
                    ),
                )

                if job_mgr.is_cancelled(job_id):
                    return

                # ── Stage 2: Deep Scan & APK Inspect ──
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "scan_inspect", 24)
                if sample["kind"] == "apk":
                    job_mgr.update_stage(
                        job_id,
                        "scan_inspect",
                        status="running",
                        log_message=(
                            "正在匹配 24 类商用加固特征并解析 Manifest/ELF..."
                            if is_zh
                            else "Matching 24 packer signature families and inspecting Manifest/ELF..."
                        ),
                    )
                    scan_dict = _scan_apk_rich(sample["path"])
                    with lock:
                        sample["scan_result"] = scan_dict
                    insp_dict = _ensure_apk_inspect(sample, force=False)
                    job_mgr.set_phase_data(job_id, "scan", scan_dict)
                    job_mgr.set_phase_data(job_id, "inspect", {
                        "risk_score": insp_dict.get("risk_score", 0),
                        "risk_grade": insp_dict.get("risk_grade", "A"),
                        "native_libs": len(insp_dict.get("native_libs") or []),
                        "findings": len(insp_dict.get("findings") or []),
                    })
                    packer_lbl = scan_dict.get("packer_name") or ("未检测到加固壳" if is_zh else "No packer")
                    scan_metrics = {
                        "packer": packer_lbl,
                        "protection_level": scan_dict.get("protection_level", "none"),
                        "confidence_pct": round(float(scan_dict.get("confidence", 0)) * 100),
                        "risk_score": insp_dict.get("risk_score", 0),
                        "risk_grade": insp_dict.get("risk_grade", "A"),
                        "native_libs": len(insp_dict.get("native_libs") or []),
                        "findings": len(insp_dict.get("findings") or []),
                    }
                    job_mgr.update_stage(
                        job_id,
                        "scan_inspect",
                        status="done",
                        duration_ms=int((time.monotonic() - st0) * 1000),
                        summary=(
                            f"{packer_lbl} · 风险评级 {scan_metrics['risk_grade']} ({scan_metrics['risk_score']}/100) · {scan_metrics['native_libs']} 个 SO"
                            if is_zh
                            else f"{packer_lbl} · Grade {scan_metrics['risk_grade']} ({scan_metrics['risk_score']}/100) · {scan_metrics['native_libs']} SOs"
                        ),
                        metrics=scan_metrics,
                        next_hint=(
                            "可前往「扫描与安全情报」查看完整证据矩阵与危险权限详情。"
                            if is_zh
                            else "Open Scan & Intelligence to inspect the full evidence matrix and manifest findings."
                        ),
                        log_message=(
                            f"扫描剖析完成：加固={packer_lbl}，风险分={scan_metrics['risk_score']}，发现项={scan_metrics['findings']}。"
                            if is_zh
                            else f"Scan & inspect done: packer={packer_lbl}, risk={scan_metrics['risk_score']}, findings={scan_metrics['findings']}."
                        ),
                    )
                else:
                    job_mgr.update_stage(
                        job_id,
                        "scan_inspect",
                        status="skipped",
                        duration_ms=0,
                        summary=(
                            "当前样本为 DEX/目录，自动跳过 APK Manifest 扫描"
                            if is_zh
                            else "Skipped APK manifest scan for raw DEX sample"
                        ),
                        log_message=(
                            "跳过 APK 扫描（纯 DEX 样本）。"
                            if is_zh
                            else "Skipped APK scan for raw DEX sample."
                        ),
                    )

                if job_mgr.is_cancelled(job_id):
                    return

                # ── Stage 3: Extract DEX ──
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "extract_dex", 40)
                src_dex_dir = output_dir / "extracted_dex"
                extracted: list[Path] = []
                if dex_entries:
                    job_mgr.update_stage(
                        job_id,
                        "extract_dex",
                        status="running",
                        log_message=(
                            f"正在提取 {len(dex_entries)} 个 DEX 文件至沙箱目录..."
                            if is_zh
                            else f"Extracting {len(dex_entries)} DEX file(s) into sandbox..."
                        ),
                    )
                    extracted = _extract_sample_dex_files(sample, src_dex_dir)
                    total_bytes = sum(p.stat().st_size for p in extracted)
                    ext_metrics = {
                        "extracted_dex_count": len(extracted),
                        "total_kb": round(total_bytes / 1024, 1),
                        "dex_names": [p.name for p in extracted[:8]],
                    }
                    job_mgr.set_phase_data(job_id, "extract_dex", ext_metrics)
                    job_mgr.update_stage(
                        job_id,
                        "extract_dex",
                        status="done",
                        duration_ms=int((time.monotonic() - st0) * 1000),
                        summary=(
                            f"成功提取 {len(extracted)} 个 DEX（共 {ext_metrics['total_kb']} KB）"
                            if is_zh
                            else f"Extracted {len(extracted)} DEX file(s) ({ext_metrics['total_kb']} KB total)"
                        ),
                        metrics=ext_metrics,
                        next_hint=(
                            "可随时进入「APK 与 DEX 浏览器」浏览类树与 Dalvik 反汇编。"
                            if is_zh
                            else "Jump to APK & DEX Inspector to browse class trees and Dalvik disassembly."
                        ),
                        log_message=(
                            f"DEX 提取完成：{', '.join(ext_metrics['dex_names'])}"
                            if is_zh
                            else f"DEX extracted: {', '.join(ext_metrics['dex_names'])}"
                        ),
                    )
                else:
                    job_mgr.update_stage(
                        job_id,
                        "extract_dex",
                        status="skipped",
                        duration_ms=0,
                        summary="未发现顶层明文 DEX 文件" if is_zh else "No top-level DEX files found",
                        log_message="跳过 DEX 提取：样本无顶层 DEX。" if is_zh else "Skipped DEX extraction: no top-level DEX files.",
                    )

                if job_mgr.is_cancelled(job_id):
                    return

                # ── Stage 4: Repair & Before/After Verify Diff ──
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "repair_verify", 60)
                repaired_dir = output_dir / "repaired_dex"
                repaired_files: list[Path] = []
                if extracted:
                    repaired_dir.mkdir(parents=True, exist_ok=True)
                    job_mgr.update_stage(
                        job_id,
                        "repair_verify",
                        status="running",
                        log_message=(
                            f"正在对 {len(extracted)} 个 DEX 执行非破坏性修复与前后对比校验..."
                            if is_zh
                            else f"Running non-destructive repair & before/after verification on {len(extracted)} DEX file(s)..."
                        ),
                    )
                    diffs = []
                    after_verifies = []
                    for dp in extracted:
                        diff, out_p = _repair_dex_with_diff(dp, repaired_dir)
                        diffs.append(diff)
                        if diff.get("after"):
                            after_verifies.append(diff["after"])
                        if out_p and out_p.exists():
                            repaired_files.append(out_p)

                    zip_path = output_dir / f"{Path(sample['name']).stem}_repaired_dex.zip"
                    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                        for rf in repaired_files:
                            zf.write(rf, arcname=rf.name)
                    rep_art = _register_artifact(zip_path, zip_path.name, "repaired_dex_bundle", "application/zip")
                    job_mgr.add_artifact(job_id, rep_art)

                    with lock:
                        sample["repair_diffs"] = diffs
                        sample["verify_results"] = after_verifies
                        sample["repaired_dir"] = repaired_dir
                        sample["artifacts"] = [rep_art, *sample.get("artifacts", [])][:20]

                    resolved_total = sum(len(d.get("resolved_issues", [])) for d in diffs)
                    valid_after = sum(1 for v in after_verifies if v.get("valid"))
                    avg_health = round(
                        sum(float(v.get("health_score", 0)) for v in after_verifies) / max(1, len(after_verifies)), 1
                    )
                    rep_metrics = {
                        "dex_repaired": len(diffs),
                        "issues_resolved": resolved_total,
                        "valid_after": valid_after,
                        "avg_health_after": avg_health,
                    }
                    job_mgr.set_phase_data(job_id, "repair", rep_metrics)
                    job_mgr.update_stage(
                        job_id,
                        "repair_verify",
                        status="done",
                        duration_ms=int((time.monotonic() - st0) * 1000),
                        summary=(
                            f"修复 {len(diffs)} 个 DEX · 解决 {resolved_total} 项异常 · 修复后健康分 {avg_health}/100"
                            if is_zh
                            else f"Repaired {len(diffs)} DEX · {resolved_total} issue(s) resolved · Avg health {avg_health}/100"
                        ),
                        metrics=rep_metrics,
                        artifacts=[rep_art],
                        next_hint=(
                            "前往「修复与校验实验室」查看逐文件修复前后差异，或直接下载修复后的 DEX ZIP。"
                            if is_zh
                            else "Open Repair & Verify Lab to review per-file before/after diffs or download the repaired DEX ZIP."
                        ),
                        log_message=(
                            f"DEX 修复与校验完成：有效 {valid_after}/{len(diffs)}，解决 {resolved_total} 项问题。"
                            if is_zh
                            else f"Repair & verify complete: {valid_after}/{len(diffs)} valid, {resolved_total} issue(s) resolved."
                        ),
                    )
                else:
                    job_mgr.update_stage(
                        job_id,
                        "repair_verify",
                        status="skipped",
                        duration_ms=0,
                        summary="无 DEX 可供修复校验" if is_zh else "No DEX files available to repair",
                    )

                if job_mgr.is_cancelled(job_id):
                    return

                # ── Stage 5: VMP, Native & Xref/IOC Analysis ──
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "vmp_xref", 78)
                if repaired_files:
                    job_mgr.update_stage(
                        job_id,
                        "vmp_xref",
                        status="running",
                        log_message=(
                            "正在分析方法体 VMP 虚拟化桩并构建反射与 URL/IP IOC 交叉引用..."
                            if is_zh
                            else "Analyzing method bodies for VMP stubs and indexing reflection & URL/IP IOCs..."
                        ),
                    )
                    target_dexs = repaired_files[:6]
                    total_m = normal_c = nop_c = vmp_c = 0
                    all_vmp_methods: list[dict[str, Any]] = []
                    all_call_graph: list[dict[str, Any]] = []
                    dispatcher_counts: dict[str, int] = {}
                    class_counts: dict[str, int] = {}
                    per_dex: list[dict[str, Any]] = []
                    for dp in target_dexs:
                        raw = dp.read_bytes()
                        rep = _analyze_vmp_dex_bytes(raw, dp.name)
                        total_m += rep["total_methods"]
                        normal_c += rep["normal_count"]
                        nop_c += rep["nop_count"]
                        vmp_c += rep["vmp_count"]
                        per_dex.append(
                            {
                                "dex": dp.name,
                                "total_methods": rep["total_methods"],
                                "normal_count": rep["normal_count"],
                                "nop_count": rep["nop_count"],
                                "vmp_count": rep["vmp_count"],
                                "vmp_ratio": rep.get("vmp_ratio", 0.0),
                            }
                        )
                        for m in rep.get("vmp_methods", []):
                            cls = m.get("class_name") or m.get("class") or "unknown"
                            meth = m.get("method_name") or m.get("method") or ""
                            if len(all_vmp_methods) < 300:
                                all_vmp_methods.append({**m, "class": cls, "class_name": cls, "method": meth, "method_name": meth, "dex": dp.name})
                            class_counts[cls] = class_counts.get(cls, 0) + 1
                            if m.get("target"):
                                dispatcher_counts[m["target"]] = dispatcher_counts.get(m["target"], 0) + 1
                        for edge in rep.get("call_graph", []):
                            if len(all_call_graph) < 300:
                                all_call_graph.append({**edge, "dex": dp.name})

                    vmp_ratio = round(vmp_c / max(1, total_m), 4)
                    vmp_risk = min(100, int(round(vmp_ratio * 250 + (20 if vmp_c > 0 else 0))))
                    vmp_verdict = "heavy_vmp" if vmp_ratio >= 0.15 else "partial_vmp" if vmp_c > 0 else "clean"
                    merged_vmp = {
                        "dex_analyzed": len(per_dex),
                        "total_dex": len(repaired_files),
                        "total_methods": total_m,
                        "normal_count": normal_c,
                        "nop_count": nop_c,
                        "vmp_count": vmp_c,
                        "vmp_ratio": vmp_ratio,
                        "risk_score": vmp_risk,
                        "verdict": vmp_verdict,
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

                    xref_summary = _analyze_xref_dex_bytes(repaired_files[0].read_bytes(), limit=100)
                    xref_summary["dex_name"] = repaired_files[0].name
                    with lock:
                        sample["vmp_result"] = merged_vmp
                        sample["xref_result"] = xref_summary

                    ioc_urls = len((xref_summary.get("iocs") or {}).get("urls") or [])
                    refl_cnt = int((xref_summary.get("counts") or {}).get("reflection_calls") or 0)
                    vmp_metrics = {
                        "total_methods": total_m,
                        "vmp_stubs": vmp_c,
                        "nop_methods": nop_c,
                        "reflection_calls": refl_cnt,
                        "ioc_urls": ioc_urls,
                        "verdict": vmp_verdict,
                    }
                    job_mgr.set_phase_data(job_id, "vmp_xref", vmp_metrics)
                    job_mgr.update_stage(
                        job_id,
                        "vmp_xref",
                        status="done",
                        duration_ms=int((time.monotonic() - st0) * 1000),
                        summary=(
                            f"分析 {total_m} 个方法 · VMP 桩 {vmp_c} · NOP {nop_c} · 反射 {refl_cnt} · URL IOC {ioc_urls}"
                            if is_zh
                            else f"{total_m} methods · {vmp_c} VMP stubs · {nop_c} NOP · {refl_cnt} reflection · {ioc_urls} URLs"
                        ),
                        metrics=vmp_metrics,
                        next_hint=(
                            "进入「VMP 与原生分析」查看调度器聚类、ELF 缓解与所有提取出的 URL/IP。"
                            if is_zh
                            else "Open VMP & Native Studio to explore dispatcher clusters, ELF mitigations, and extracted IOCs."
                        ),
                        log_message=(
                            f"VMP & Xref 完成：判定={vmp_verdict}，VMP 桩={vmp_c}，URL IOC={ioc_urls}。"
                            if is_zh
                            else f"VMP & Xref done: verdict={vmp_verdict}, vmp_stubs={vmp_c}, urls={ioc_urls}."
                        ),
                    )
                else:
                    job_mgr.update_stage(
                        job_id,
                        "vmp_xref",
                        status="skipped",
                        duration_ms=0,
                        summary="无 DEX 可供 VMP/Xref 分析" if is_zh else "No DEX files available for VMP/Xref",
                    )

                if job_mgr.is_cancelled(job_id):
                    return

                # ── Stage 6: Optional Repack & Commercial Audit Report ──
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "repack_report", 92)
                do_repack = bool(repack and sample["kind"] == "apk" and repaired_files)
                stage_arts: list[dict[str, Any]] = []
                if do_repack or generate_report:
                    job_mgr.update_stage(
                        job_id,
                        "repack_report",
                        status="running",
                        log_message=(
                            "正在生成最终交付产物（重打包 APK / 商用审计报告）..."
                            if is_zh
                            else "Building final deliverables (repacked APK / commercial audit report)..."
                        ),
                    )
                    repacked_name = ""
                    if do_repack:
                        from unpack.repack.repacker import Repacker

                        repack_out = output_dir / "repacked"
                        repacker = Repacker()
                        try:
                            rr = repacker.repack(sample["path"], repaired_dir, repack_out, strip_signatures=True)
                        except TypeError:
                            rr = repacker.repack(sample["path"], repaired_dir, repack_out)
                        if rr.success and rr.output_path:
                            r_art = _register_artifact(
                                rr.output_path,
                                rr.output_path.name,
                                "repacked_apk",
                                "application/vnd.android.package-archive",
                            )
                            stage_arts.append(r_art)
                            job_mgr.add_artifact(job_id, r_art)
                            repacked_name = r_art["name"]
                            with lock:
                                sample["artifacts"] = [r_art, *sample.get("artifacts", [])][:20]

                    report_name = ""
                    if generate_report:
                        html_body, _, ext = _render_commercial_report(sample=sample, fmt="html", lang=lang)
                        rep_file = output_dir / f"{Path(sample['name']).stem}_audit_{_normalize_lang(lang)}.{ext}"
                        rep_file.write_text(html_body, encoding="utf-8")
                        h_art = _register_artifact(rep_file, rep_file.name, "audit_report_html", "text/html; charset=utf-8")
                        stage_arts.append(h_art)
                        job_mgr.add_artifact(job_id, h_art)
                        report_name = h_art["name"]
                        with lock:
                            sample["artifacts"] = [h_art, *sample.get("artifacts", [])][:20]

                    rep_stage_metrics = {
                        "repacked_apk": repacked_name or ("未启用" if is_zh else "skipped"),
                        "audit_report": report_name or ("未启用" if is_zh else "skipped"),
                        "artifact_count": len(stage_arts),
                    }
                    job_mgr.set_phase_data(job_id, "repack_report", rep_stage_metrics)
                    job_mgr.update_stage(
                        job_id,
                        "repack_report",
                        status="done",
                        duration_ms=int((time.monotonic() - st0) * 1000),
                        summary=(
                            f"已生成 {len(stage_arts)} 个可下载交付产物"
                            if is_zh
                            else f"Generated {len(stage_arts)} downloadable deliverable artifact(s)"
                        ),
                        metrics=rep_stage_metrics,
                        artifacts=stage_arts,
                        next_hint=(
                            "全部离线管线阶段已完成！前往「报告与导出」在线预览或下载多格式审计报告。"
                            if is_zh
                            else "All offline pipeline stages complete! Visit Reports & Export to preview or export HTML/Markdown/SARIF/JSON."
                        ),
                        log_message=(
                            f"交付阶段完成，共产出 {len(stage_arts)} 个文件。"
                            if is_zh
                            else f"Deliverables ready: {len(stage_arts)} artifact(s) registered."
                        ),
                    )
                else:
                    job_mgr.update_stage(
                        job_id,
                        "repack_report",
                        status="skipped",
                        duration_ms=0,
                        summary="未开启重打包或报告导出" if is_zh else "Repack and report export not selected",
                    )

                job_mgr.finish(job_id, status="done", duration_ms=int((time.monotonic() - t0) * 1000))
            except Exception as exc:
                job_mgr.log(job_id, f"Pipeline error: {exc}", level="error")
                job_mgr.finish(job_id, status="failed", error=str(exc), duration_ms=int((time.monotonic() - t0) * 1000))

        def _device_worker() -> None:
            t0 = time.monotonic()
            try:
                from unpack.core.dedup import dedup_dex_files
                from unpack.core.dispatcher import Dispatcher
                from unpack.core.reporter import Reporter
                from unpack.core.scanner import PackerScanner, ProtectionLevel
                from unpack.repair.dex_repair import DexRepairPipeline

                # Stage 1: Intake
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "intake", 10)
                job_mgr.update_stage(
                    job_id,
                    "intake",
                    status="running",
                    log_message="检查 APK 与设备预检状态..." if is_zh else "Checking APK and device pre-flight...",
                )
                if sample["kind"] != "apk":
                    msg = "真机动态脱壳仅支持 APK 样本" if is_zh else "Live device unpacking requires an APK sample"
                    job_mgr.update_stage(job_id, "intake", status="failed", duration_ms=int((time.monotonic() - st0) * 1000), summary=msg, log_message=msg, log_level="error")
                    job_mgr.finish(job_id, status="failed", error=msg, duration_ms=int((time.monotonic() - t0) * 1000))
                    return
                job_mgr.update_stage(
                    job_id,
                    "intake",
                    status="done",
                    duration_ms=int((time.monotonic() - st0) * 1000),
                    summary=f"{sample['name']} · {round(sample['size_bytes'] / (1024 * 1024), 2)} MB",
                    metrics={"size_mb": round(sample["size_bytes"] / (1024 * 1024), 2)},
                )

                # Stage 2: Scan
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "scan_inspect", 25)
                job_mgr.update_stage(
                    job_id,
                    "scan_inspect",
                    status="running",
                    log_message="运行加固特征识别与策略路由..." if is_zh else "Running PackerScanner & engine routing...",
                )
                apk_path: Path = sample["path"]
                scan_result = PackerScanner().scan(apk_path, verbose=True)
                scan_dict = _scan_apk_rich(apk_path)
                with lock:
                    sample["scan_result"] = scan_dict
                job_mgr.set_phase_data(job_id, "scan", scan_dict)
                job_mgr.update_stage(
                    job_id,
                    "scan_inspect",
                    status="done",
                    duration_ms=int((time.monotonic() - st0) * 1000),
                    summary=f"{scan_dict.get('packer_name') or 'None'} ({scan_dict.get('protection_level', 'none')})",
                    metrics={
                        "packer": scan_dict.get("packer_name") or "none",
                        "protection_level": scan_dict.get("protection_level", "none"),
                    },
                )

                if job_mgr.is_cancelled(job_id):
                    return

                # Stage 3: Dynamic Dump
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "dynamic_dump", 45)
                job_mgr.update_stage(
                    job_id,
                    "dynamic_dump",
                    status="running",
                    log_message=(
                        f"调度真机脱壳引擎 engine={engine or 'auto'}, timeout={timeout_s}s..."
                        if is_zh
                        else f"Dispatching live dump engine={engine or 'auto'}, timeout={timeout_s}s..."
                    ),
                )
                dump_result = Dispatcher().dispatch(
                    apk=apk_path,
                    scan_result=scan_result,
                    output_dir=output_dir,
                    force_engine=engine or None,
                    timeout=timeout_s if timeout_s > 0 else None,
                    anti_detect=anti_detect,
                )
                if not dump_result.dex_files:
                    err = dump_result.error or ("未捕获到 DEX 文件（请确认已连接 Root 真机）" if is_zh else "No DEX files dumped (check rooted ADB device)")
                    job_mgr.update_stage(
                        job_id,
                        "dynamic_dump",
                        status="failed",
                        duration_ms=int((time.monotonic() - st0) * 1000),
                        summary=err,
                        next_hint=(
                            "若当前没有连接 Root 真机，可一键切换至「离线深度审计管线」立即完成静态剖析与报告。"
                            if is_zh
                            else "No rooted device attached? Switch to Offline Deep Audit to analyze immediately without a device."
                        ),
                        log_message=err,
                        log_level="error",
                    )
                    job_mgr.finish(job_id, status="failed", error=err, duration_ms=int((time.monotonic() - t0) * 1000))
                    return

                unique = dedup_dex_files(output_dir)
                dump_metrics = {
                    "dex_dumped": len(dump_result.dex_files),
                    "unique_dex": len(unique),
                    "engine": dump_result.engine.value,
                }
                job_mgr.set_phase_data(job_id, "dump", dump_metrics)
                job_mgr.update_stage(
                    job_id,
                    "dynamic_dump",
                    status="done",
                    duration_ms=int((time.monotonic() - st0) * 1000),
                    summary=f"{len(unique)} unique DEX via {dump_result.engine.value}",
                    metrics=dump_metrics,
                )

                # Stage 4: Active Invoke
                if mode == "device_deep" or deep:
                    st0 = time.monotonic()
                    job_mgr.set_phase(job_id, "active_invoke", 65)
                    job_mgr.update_stage(job_id, "active_invoke", status="running", log_message="Running Frida active invocation...")
                    merged_cnt = 0
                    try:
                        from unpack.engines.active_invoke import ActiveInvoker
                        from unpack.repair.codeitem_merger import CodeItemMerger
                        from unpack.utils.apk import get_package_name

                        pkg = get_package_name(apk_path)
                        if pkg:
                            inv_res = ActiveInvoker(wait_seconds=timeout_s, anti_detect=anti_detect).invoke(pkg, output_dir)
                            if inv_res.code_items:
                                merger = CodeItemMerger()
                                merged_cnt = sum(merger.merge(d, inv_res.code_items).methods_merged for d in unique)
                        job_mgr.update_stage(
                            job_id,
                            "active_invoke",
                            status="done",
                            duration_ms=int((time.monotonic() - st0) * 1000),
                            summary=f"Merged {merged_cnt} methods",
                            metrics={"methods_merged": merged_cnt},
                        )
                    except ImportError:
                        job_mgr.update_stage(
                            job_id,
                            "active_invoke",
                            status="skipped",
                            duration_ms=int((time.monotonic() - st0) * 1000),
                            summary="Frida unavailable",
                        )

                # Stage 5: Repair & Verify
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "repair_verify", 82)
                job_mgr.update_stage(job_id, "repair_verify", status="running", log_message=f"Repairing {len(unique)} dumped DEX file(s)...")
                repaired_out = output_dir / "repaired"
                repaired_out.mkdir(parents=True, exist_ok=True)
                diffs = []
                for dp in unique:
                    diff, _ = _repair_dex_with_diff(dp, repaired_out)
                    diffs.append(diff)
                zip_path = output_dir / f"{Path(sample['name']).stem}_dumped_repaired.zip"
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for rf in sorted(repaired_out.glob("*.dex")):
                        zf.write(rf, arcname=rf.name)
                art = _register_artifact(zip_path, zip_path.name, "pipeline_dex_bundle", "application/zip")
                job_mgr.add_artifact(job_id, art)
                rep_obj = Reporter().evaluate(repaired_out, scan_result)
                with lock:
                    sample["repair_diffs"] = diffs
                    sample["quality_report"] = rep_obj.to_dict()
                    sample["repaired_dir"] = repaired_out
                job_mgr.update_stage(
                    job_id,
                    "repair_verify",
                    status="done",
                    duration_ms=int((time.monotonic() - st0) * 1000),
                    summary=f"{len(diffs)} DEX · coverage {round(rep_obj.code_coverage * 100)}%",
                    metrics={"dex_count": len(diffs), "coverage_pct": round(rep_obj.code_coverage * 100)},
                    artifacts=[art],
                )

                # Stage 6: Repack & Report
                st0 = time.monotonic()
                job_mgr.set_phase(job_id, "repack_report", 95)
                stage_arts = []
                if generate_report:
                    html_body, _, ext = _render_commercial_report(sample=sample, fmt="html", lang=lang)
                    rep_file = output_dir / f"{Path(sample['name']).stem}_audit_{_normalize_lang(lang)}.{ext}"
                    rep_file.write_text(html_body, encoding="utf-8")
                    h_art = _register_artifact(rep_file, rep_file.name, "audit_report_html", "text/html; charset=utf-8")
                    stage_arts.append(h_art)
                    job_mgr.add_artifact(job_id, h_art)
                job_mgr.update_stage(
                    job_id,
                    "repack_report",
                    status="done",
                    duration_ms=int((time.monotonic() - st0) * 1000),
                    summary=f"{len(stage_arts)} artifact(s) ready",
                    artifacts=stage_arts,
                )
                job_mgr.finish(job_id, status="done", duration_ms=int((time.monotonic() - t0) * 1000))
            except Exception as exc:
                job_mgr.log(job_id, f"Pipeline error: {exc}", level="error")
                job_mgr.finish(job_id, status="failed", error=str(exc), duration_ms=int((time.monotonic() - t0) * 1000))

        worker_fn = _offline_worker if mode in {"offline_audit", "repair_repack"} else _device_worker
        threading.Thread(target=worker_fn, daemon=True).start()
        return job_id

    @app.post("/api/v1/jobs/pipeline")
    def api_v1_jobs_pipeline():
        body = request.get_json(silent=True) or {}
        sample_id = str(body.get("sample_id", "")).strip()
        if not sample_id:
            return jsonify(error="Missing 'sample_id'", code="BAD_REQUEST"), 400
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404

        mode = str(body.get("mode") or "offline_audit").strip()
        if mode not in PIPELINE_MODES:
            return jsonify(error=f"Invalid pipeline mode: {mode!r}", code="BAD_REQUEST"), 400
        engine = str(body.get("engine", ""))
        if engine not in {"", "memory", "frida", "ebpf"}:
            return jsonify(error=f"Invalid engine: {engine!r}", code="BAD_REQUEST"), 400
        try:
            timeout_s = _parse_int(body.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400

        job_id = _launch_deep_pipeline_job(
            sample=sample,
            mode=mode,
            engine=engine,
            timeout_s=timeout_s,
            deep=_parse_bool(body.get("deep"), default=(mode == "device_deep")),
            anti_detect=_parse_bool(body.get("anti_detect"), default=True),
            repack=_parse_bool(body.get("repack"), default=(mode == "repair_repack")),
            generate_report=_parse_bool(body.get("generate_report"), default=True),
            lang=_normalize_lang(body.get("lang", "en")),
        )
        return jsonify(job_id=job_id, sample_id=sample_id, mode=mode), 202

    # ── Async Pipeline (Studio v1 + SSE — Backward Compatible) ──

    def _launch_pipeline_job(
        *,
        sample: dict[str, Any],
        engine: str,
        timeout_s: int,
        deep: bool,
        anti_detect: bool,
        start_from: str,
    ) -> str:
        job_id = job_mgr.create_job(
            job_type="pipeline",
            apk=sample["name"],
            apk_hash=sample["id"],
            sample_id=sample["id"],
            phase="scanning" if start_from in {"scan", "scan_only"} else start_from,
        )
        with lock:
            sample["last_job_id"] = job_id

        output_dir = sample["work_dir"] / f"output_{job_id}"
        output_dir.mkdir(parents=True, exist_ok=True)

        if start_from not in {"scan", "scan_only"} and sample.get("scan_result"):
            job_mgr.set_phase_data(job_id, "scan", sample["scan_result"])

        def _worker() -> None:
            t0 = time.monotonic()
            try:
                from unpack.core.dedup import dedup_dex_files
                from unpack.core.dispatcher import Dispatcher
                from unpack.core.reporter import Reporter
                from unpack.core.scanner import PackerScanner, ProtectionLevel
                from unpack.repair.dex_repair import DexRepairPipeline

                apk_path: Path = sample["path"]
                scan_result = None

                # Phase 1: Scan
                if start_from in {"scan", "scan_only"} or sample.get("scan_result") is None:
                    if job_mgr.is_cancelled(job_id):
                        return
                    job_mgr.set_phase(job_id, "scanning", 15)
                    job_mgr.log(job_id, f"Scanning {sample['name']} with PackerScanner...", phase="scanning")
                    scanner = PackerScanner()
                    scan_result = scanner.scan(apk_path, verbose=True)
                    scan_dict = _scan_apk_rich(apk_path)
                    with lock:
                        sample["scan_result"] = scan_dict
                    job_mgr.set_phase_data(job_id, "scan", scan_dict)
                    job_mgr.log(
                        job_id,
                        f"Scan complete: packer={scan_dict.get('packer_name') or 'none'}, "
                        f"level={scan_dict.get('protection_level')}, "
                        f"confidence={round(float(scan_dict.get('confidence', 0)) * 100)}%",
                        phase="scanning",
                    )
                else:
                    scanner = PackerScanner()
                    scan_result = scanner.scan(apk_path)

                if start_from == "scan_only":
                    job_mgr.finish(job_id, status="done", duration_ms=int((time.monotonic() - t0) * 1000))
                    return

                unique: list[Path] = []

                # Phase 2: Dump (skipped if start_from == "repairing" and existing DEXs exist)
                if start_from == "repairing":
                    job_mgr.log(job_id, "Skipping dump stage (start_from=repairing); loading DEX set...", phase="repairing")
                    unique = _extract_sample_dex_files(sample, output_dir)
                    if not unique:
                        job_mgr.finish(job_id, status="failed", error="No DEX files found to repair", duration_ms=int((time.monotonic() - t0) * 1000))
                        return
                else:
                    if job_mgr.is_cancelled(job_id):
                        return
                    job_mgr.set_phase(job_id, "dumping", 35)
                    job_mgr.log(
                        job_id,
                        f"Dispatching dump engine={engine or 'auto'}, timeout={timeout_s}s, anti_detect={anti_detect}",
                        phase="dumping",
                    )
                    dispatcher = Dispatcher()
                    dump_result = dispatcher.dispatch(
                        apk=apk_path,
                        scan_result=scan_result,
                        output_dir=output_dir,
                        force_engine=engine or None,
                        timeout=timeout_s if timeout_s > 0 else None,
                        anti_detect=anti_detect,
                    )
                    if not dump_result.dex_files:
                        err = dump_result.error or "No DEX files dumped"
                        job_mgr.log(job_id, f"Dump failed: {err}", level="error", phase="dumping")
                        job_mgr.finish(job_id, status="failed", error=err, duration_ms=int((time.monotonic() - t0) * 1000))
                        return

                    unique = dedup_dex_files(output_dir)
                    removed = len(dump_result.dex_files) - len(unique)
                    dump_data = {
                        "dex_count": len(dump_result.dex_files),
                        "unique_dex_count": len(unique),
                        "so_count": len(dump_result.so_files),
                        "duration_ms": dump_result.duration_ms,
                        "engine": dump_result.engine.value,
                    }
                    if removed > 0:
                        dump_data["duplicates_removed"] = removed
                    job_mgr.set_phase_data(job_id, "dump", dump_data)
                    job_mgr.log(
                        job_id,
                        f"Dumped {len(dump_result.dex_files)} DEX ({len(unique)} unique) via {dump_result.engine.value}",
                        phase="dumping",
                    )

                    # Phase 3: Deep mode
                    if deep and scan_result.protection_level in (
                        ProtectionLevel.FUNCTION_EXTRACTION,
                        ProtectionLevel.VMP,
                    ):
                        if job_mgr.is_cancelled(job_id):
                            return
                        job_mgr.set_phase(job_id, "active_invoke", 55)
                        job_mgr.log(job_id, "Running active invocation for function-extracted methods...", phase="active_invoke")
                        try:
                            from unpack.engines.active_invoke import ActiveInvoker
                            from unpack.repair.codeitem_merger import CodeItemMerger
                            from unpack.utils.apk import get_package_name

                            pkg = get_package_name(apk_path)
                            if pkg:
                                invoker = ActiveInvoker(
                                    wait_seconds=timeout_s if timeout_s > 0 else 15,
                                    anti_detect=anti_detect,
                                )
                                inv_result = invoker.invoke(pkg, output_dir)
                                if inv_result.code_items:
                                    merger = CodeItemMerger()
                                    total_merged = sum(merger.merge(dex, inv_result.code_items).methods_merged for dex in unique)
                                    job_mgr.set_phase_data(
                                        job_id,
                                        "active_invoke",
                                        {
                                            "code_items_captured": len(inv_result.code_items),
                                            "methods_merged": total_merged,
                                        },
                                    )
                                    job_mgr.log(
                                        job_id,
                                        f"Active invoke merged {total_merged} method bodies.",
                                        phase="active_invoke",
                                    )
                        except ImportError:
                            job_mgr.log(job_id, "Active invoke skipped (Frida unavailable).", level="warn", phase="active_invoke")

                # Phase 4: Repair
                if job_mgr.is_cancelled(job_id):
                    return
                job_mgr.set_phase(job_id, "repairing", 75)
                job_mgr.log(job_id, f"Repairing {len(unique)} DEX file(s)...", phase="repairing")
                pipeline = DexRepairPipeline()
                repair_results = []
                for dex_path in unique:
                    rr = pipeline.repair(dex_path, in_place=True)
                    repair_results.append(
                        {
                            "file": dex_path.name,
                            "success": rr.success,
                            "actions": list(rr.actions),
                            "nop_methods": rr.nop_method_count,
                        }
                    )
                job_mgr.set_phase_data(job_id, "repair", repair_results)

                # Bundle repaired DEXs as artifact
                zip_path = output_dir / f"{Path(sample['name']).stem}_pipeline_dex.zip"
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for dp in unique:
                        zf.write(dp, arcname=dp.name)
                art = _register_artifact(zip_path, zip_path.name, "pipeline_dex_bundle", "application/zip")
                job_mgr.add_artifact(job_id, art)

                # Phase 5: Verify
                if job_mgr.is_cancelled(job_id):
                    return
                job_mgr.set_phase(job_id, "verifying", 90)
                job_mgr.log(job_id, "Evaluating DEX quality & verification report...", phase="verifying")
                reporter = Reporter()
                report = reporter.evaluate(output_dir, scan_result)
                rep_dict = report.to_dict()
                with lock:
                    sample["quality_report"] = rep_dict
                    sample["repaired_dir"] = output_dir
                job_mgr.set_phase_data(job_id, "report", rep_dict)
                job_mgr.log(
                    job_id,
                    f"Pipeline complete: {rep_dict['dex_count']} DEX, coverage={round(rep_dict['code_coverage'] * 100)}%",
                    phase="done",
                )
                job_mgr.finish(job_id, status="done", duration_ms=int((time.monotonic() - t0) * 1000))
            except Exception as exc:
                job_mgr.log(job_id, f"Pipeline error: {exc}", level="error")
                job_mgr.finish(job_id, status="failed", error=str(exc), duration_ms=int((time.monotonic() - t0) * 1000))

        threading.Thread(target=_worker, daemon=True).start()
        return job_id

    @app.post("/api/v1/samples/<sample_id>/pipeline")
    def api_v1_sample_pipeline(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404

        body = request.get_json(silent=True) or {}
        mode = body.get("mode")
        if mode in PIPELINE_MODES:
            engine = str(body.get("engine", ""))
            if engine not in {"", "memory", "frida", "ebpf"}:
                return jsonify(error=f"Invalid engine: {engine!r}", code="BAD_REQUEST"), 400
            try:
                timeout_s = _parse_int(body.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
            except ValueError as exc:
                return jsonify(error=str(exc), code="BAD_REQUEST"), 400
            job_id = _launch_deep_pipeline_job(
                sample=sample,
                mode=mode,
                engine=engine,
                timeout_s=timeout_s,
                deep=_parse_bool(body.get("deep"), default=(mode == "device_deep")),
                anti_detect=_parse_bool(body.get("anti_detect"), default=True),
                repack=_parse_bool(body.get("repack"), default=(mode == "repair_repack")),
                generate_report=_parse_bool(body.get("generate_report"), default=True),
                lang=_normalize_lang(body.get("lang", "en")),
            )
            return jsonify(job_id=job_id, sample_id=sample_id, mode=mode), 202

        if sample["kind"] != "apk":
            return jsonify(error="Pipeline requires an APK sample", code="UNSUPPORTED_KIND"), 400

        engine = str(body.get("engine", ""))
        if engine not in {"", "memory", "frida", "ebpf"}:
            return jsonify(error=f"Invalid engine: {engine!r}", code="BAD_REQUEST"), 400
        try:
            timeout_s = _parse_int(body.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400

        deep = _parse_bool(body.get("deep"), default=False)
        anti_detect = _parse_bool(body.get("anti_detect"), default=True)
        start_from = str(body.get("start_from", "scan"))
        if start_from not in {"scan", "scan_only", "dumping", "repairing"}:
            return jsonify(error=f"Invalid start_from: {start_from!r}", code="BAD_REQUEST"), 400

        job_id = _launch_pipeline_job(
            sample=sample,
            engine=engine,
            timeout_s=timeout_s,
            deep=deep,
            anti_detect=anti_detect,
            start_from=start_from,
        )
        return jsonify(job_id=job_id, sample_id=sample_id), 202

    # ── Jobs & SSE Streaming ──

    @app.get("/api/v1/jobs")
    def api_v1_jobs():
        return jsonify(jobs=job_mgr.list_all())

    @app.get("/api/v1/jobs/<job_id>")
    def api_v1_job_detail(job_id: str):
        job = job_mgr.get(job_id)
        if job is None:
            return jsonify(error="Job not found", code="NOT_FOUND"), 404
        return jsonify(job)

    @app.post("/api/v1/jobs/<job_id>/cancel")
    def api_v1_job_cancel(job_id: str):
        if not job_mgr.cancel(job_id):
            return jsonify(error="Job not found", code="NOT_FOUND"), 404
        return jsonify(cancelled=True, job_id=job_id)

    @app.get("/api/v1/jobs/<job_id>/events")
    def api_v1_job_events(job_id: str):
        snapshot, sub_q = job_mgr.subscribe(job_id)
        if snapshot is None:
            return jsonify(error="Job not found", code="NOT_FOUND"), 404

        def _stream():
            try:
                yield f"event: snapshot\ndata: {json.dumps(snapshot)}\n\n"
                if snapshot["status"] in {"done", "failed", "cancelled"}:
                    return
                while True:
                    try:
                        event, payload = sub_q.get(timeout=15.0)
                        yield f"event: {event}\ndata: {json.dumps(payload)}\n\n"
                        if event in {"done", "failed", "cancelled"}:
                            return
                    except queue.Empty:
                        cur = job_mgr.get(job_id)
                        if cur is None or cur["status"] in {"done", "failed", "cancelled"}:
                            if cur is not None:
                                yield f"event: {cur['status']}\ndata: {json.dumps({'status': cur['status'], 'phase': cur['phase'], 'error': cur.get('error')})}\n\n"
                            return
                        yield ": keepalive\n\n"
            finally:
                job_mgr.unsubscribe(job_id, sub_q)

        return Response(
            stream_with_context(_stream()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/v1/artifacts/<token>/download")
    def api_v1_artifact_download(token: str):
        with lock:
            meta = artifacts.get(token)
        if meta is None or not Path(meta["path"]).exists():
            return jsonify(error="Artifact not found", code="NOT_FOUND"), 404
        return send_file(
            meta["path"],
            mimetype=meta["mimetype"],
            as_attachment=True,
            download_name=meta["name"],
        )

    # =======================================================================
    # Persistent Workspace & Session History API
    # =======================================================================

    @app.get("/api/v1/workspaces")
    def api_v1_workspaces_list():
        return jsonify(
            active_workspace_id=_active_ws_id(),
            workspaces=ws_store.list_workspaces(),
        )

    @app.post("/api/v1/workspaces")
    def api_v1_workspaces_create():
        body = request.get_json(silent=True) or {}
        name = str(body.get("name") or "").strip()
        if not name:
            return jsonify(error="Workspace name cannot be empty", code="BAD_REQUEST"), 400
        try:
            ws = ws_store.create_workspace(
                name=name,
                description=str(body.get("description") or ""),
                tags=body.get("tags"),
                notes=str(body.get("notes") or ""),
                pinned=_parse_bool(body.get("pinned"), default=False),
            )
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400
        if _parse_bool(body.get("activate"), default=False):
            _restore_workspace_samples(ws["id"])
        return jsonify(workspace=ws, active_workspace_id=_active_ws_id()), 201

    @app.get("/api/v1/workspaces/<ws_id>")
    def api_v1_workspace_detail(ws_id: str):
        ws = ws_store.get_workspace(ws_id)
        if ws is None:
            return jsonify(error="Workspace not found", code="NOT_FOUND"), 404
        if _parse_bool(request.args.get("activate"), default=False):
            _restore_workspace_samples(ws_id)
        return jsonify(workspace=ws, active_workspace_id=_active_ws_id())

    @app.post("/api/v1/workspaces/<ws_id>/activate")
    def api_v1_workspace_activate(ws_id: str):
        ws = ws_store.get_workspace(ws_id)
        if ws is None:
            return jsonify(error="Workspace not found", code="NOT_FOUND"), 404
        restored = _restore_workspace_samples(ws_id)
        runs = ws_store.list_pipeline_runs(workspace_id=ws_id, limit=50)
        analyses = ws_store.list_ai_analyses(workspace_id=ws_id, limit=50)
        return jsonify(
            workspace=ws,
            active_workspace_id=ws_id,
            samples=restored,
            pipeline_runs=runs,
            ai_analyses=analyses,
        )

    @app.patch("/api/v1/workspaces/<ws_id>")
    def api_v1_workspace_update(ws_id: str):
        body = request.get_json(silent=True) or {}
        try:
            updated = ws_store.update_workspace(
                ws_id,
                name=body.get("name"),
                description=body.get("description"),
                notes=body.get("notes"),
                tags=body.get("tags"),
                pinned=_parse_bool(body.get("pinned")) if "pinned" in body else None,
            )
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400
        if updated is None:
            return jsonify(error="Workspace not found", code="NOT_FOUND"), 404
        return jsonify(workspace=updated)

    @app.delete("/api/v1/workspaces/<ws_id>")
    def api_v1_workspace_delete(ws_id: str):
        if ws_id == DEFAULT_WORKSPACE_ID:
            return jsonify(error="Cannot delete the default workspace", code="BAD_REQUEST"), 400
        ok = ws_store.delete_workspace(ws_id)
        if not ok:
            return jsonify(error="Workspace not found", code="NOT_FOUND"), 404
        if _active_ws_id() == ws_id:
            _restore_workspace_samples(DEFAULT_WORKSPACE_ID)
        return jsonify(deleted=True, id=ws_id, active_workspace_id=_active_ws_id())

    @app.get("/api/v1/workspaces/<ws_id>/history")
    def api_v1_workspace_history(ws_id: str):
        ws = ws_store.get_workspace(ws_id)
        if ws is None:
            return jsonify(error="Workspace not found", code="NOT_FOUND"), 404
        try:
            limit = _parse_int(request.args.get("limit"), 50, min_val=1, max_val=200, name="limit")
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400
        saved_samples = ws_store.list_samples(workspace_id=ws_id)
        runs = ws_store.list_pipeline_runs(workspace_id=ws_id, limit=limit)
        analyses = ws_store.list_ai_analyses(workspace_id=ws_id, limit=limit)
        return jsonify(
            workspace=ws,
            samples=saved_samples,
            pipeline_runs=runs,
            ai_analyses=analyses,
        )

    @app.get("/api/v1/workspaces/<ws_id>/export")
    def api_v1_workspace_export(ws_id: str):
        try:
            bundle = ws_store.export_workspace_json(ws_id)
        except KeyError:
            return jsonify(error="Workspace not found", code="NOT_FOUND"), 404
        ws_name = _safe_filename(bundle["workspace"]["name"], "workspace")
        payload = json.dumps(bundle, indent=2, ensure_ascii=False)
        resp = Response(payload, mimetype="application/json; charset=utf-8")
        resp.headers["Content-Disposition"] = f'attachment; filename="{ws_name}_workspace.json"'
        return resp

    @app.post("/api/v1/workspaces/import")
    def api_v1_workspace_import():
        bundle = None
        name_override = None
        if "file" in request.files and request.files["file"].filename:
            try:
                raw_bytes = request.files["file"].read()
                bundle = json.loads(raw_bytes.decode("utf-8"))
                name_override = request.form.get("name") or None
            except Exception as exc:
                return jsonify(error=f"Invalid workspace JSON file: {exc}", code="BAD_REQUEST"), 400
        else:
            body = request.get_json(silent=True)
            if isinstance(body, dict) and "bundle" in body and isinstance(body["bundle"], dict):
                bundle = body["bundle"]
                name_override = body.get("name") or None
            elif isinstance(body, dict):
                bundle = body
        if not isinstance(bundle, dict):
            return jsonify(error="Provide a workspace JSON bundle", code="BAD_REQUEST"), 400
        try:
            restored = ws_store.import_workspace_json(bundle, name_override=name_override)
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400
        return jsonify(workspace=restored), 201

    # =======================================================================
    # AI Model Configuration & Embedded Reverse-Engineering AI Analysis API
    # =======================================================================

    @app.get("/api/v1/ai/config")
    def api_v1_ai_config_get():
        cfg = ai_config_store.load()
        return jsonify(config=cfg.to_public_dict(), presets=list_provider_presets())

    @app.put("/api/v1/ai/config")
    def api_v1_ai_config_put():
        body = request.get_json(silent=True) or {}
        clear_key = _parse_bool(body.get("clear_api_key"), default=False)
        try:
            cfg = ai_config_store.update(body, clear_api_key=clear_key)
        except (ValueError, TypeError) as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400
        return jsonify(config=cfg.to_public_dict(), presets=list_provider_presets())

    @app.post("/api/v1/ai/test")
    def api_v1_ai_test():
        body = request.get_json(silent=True) or {}
        lang = _normalize_lang(body.get("lang", "zh"))
        override = body.get("config") if isinstance(body.get("config"), dict) else None
        if override is not None:
            stored = ai_config_store.load()
            merged = dict(stored.to_storage_dict())
            for k in ("enabled", "provider", "base_url", "model", "temperature", "max_tokens", "timeout_seconds"):
                if k in override and override[k] is not None:
                    merged[k] = override[k]
            incoming_key = str(override.get("api_key") or "").strip()
            if _parse_bool(override.get("clear_api_key"), default=False):
                merged["api_key"] = ""
            elif incoming_key and not is_masked_api_key(incoming_key):
                merged["api_key"] = incoming_key
            cfg = AIConfig.from_dict(merged)
            res = ai_test_connection(cfg, lang=lang)
        else:
            res = ai_test_connection(config_store=ai_config_store, lang=lang)
        return jsonify(res)

    @app.get("/api/v1/samples/<sample_id>/ai")
    def api_v1_sample_ai_history(sample_id: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        module = (request.args.get("module") or "").strip() or None
        items = ws_store.list_ai_analyses(
            workspace_id=sample.get("workspace_id") or _active_ws_id(),
            sample_id=sample_id,
            module=module,
            limit=50,
        )
        return jsonify(analyses=items)

    @app.post("/api/v1/samples/<sample_id>/ai/<module>")
    def api_v1_sample_ai_analyze(sample_id: str, module: str):
        sample = _get_sample_or_404(sample_id)
        if sample is None:
            return jsonify(error="Sample not found", code="NOT_FOUND"), 404
        mod = module.strip().lower()
        valid_modules = {"scan", "security", "method", "vmp_native", "pipeline_issue"}
        if mod not in valid_modules:
            return jsonify(error=f"Unsupported AI module: {module!r}", code="BAD_REQUEST"), 400

        body = request.get_json(silent=True) or {}
        lang = _normalize_lang(body.get("lang", "zh"))
        analyzer = AIAnalyzer(config_store=ai_config_store)

        try:
            if mod == "scan":
                scan_data = sample.get("scan_result")
                if scan_data is None and sample["kind"] == "apk" and _sample_file_exists(sample):
                    scan_data = _scan_apk_rich(sample["path"])
                    with lock:
                        sample["scan_result"] = scan_data
                    _persist_sample(sample)
                insp_data = sample.get("inspect_result")
                if insp_data is None and sample["kind"] == "apk" and _sample_file_exists(sample):
                    insp_data = _ensure_apk_inspect(sample, force=False)
                result = analyzer.analyze_scan(scan_data or {}, insp_data, lang=lang)

            elif mod == "security":
                insp_data = sample.get("inspect_result")
                if insp_data is None and sample["kind"] == "apk" and _sample_file_exists(sample):
                    insp_data = _ensure_apk_inspect(sample, force=False)
                if not insp_data:
                    insp_data = {
                        "file": sample["name"],
                        "sha256": sample["sha256"],
                        "findings": [],
                        "risk_score": 0,
                        "risk_grade": "A",
                    }
                result = analyzer.analyze_security(insp_data, findings=insp_data.get("findings"), lang=lang)

            elif mod == "method":
                disasm = body.get("disasm") if isinstance(body.get("disasm"), dict) else None
                cls_name = str(body.get("class_name") or "")
                if disasm is None:
                    dex_name = str(body.get("dex_name") or "")
                    meth_name = str(body.get("method_name") or "")
                    meth_idx = (
                        _parse_int(body.get("method_idx"), 0, min_val=0, name="method_idx")
                        if body.get("method_idx") not in (None, "")
                        else None
                    )
                    if not dex_name or not cls_name or not meth_name:
                        return jsonify(error="Provide 'disasm' or ('dex_name', 'class_name', 'method_name')", code="BAD_REQUEST"), 400
                    browser = _get_dex_browser(sample, dex_name)
                    if browser is None:
                        return jsonify(error=f"DEX '{dex_name}' not available on disk", code="FILE_UNAVAILABLE"), 400
                    disasm = browser.disassemble_method(cls_name, meth_name, method_idx=meth_idx)
                    if disasm is None:
                        return jsonify(error="Method not found", code="NOT_FOUND"), 404
                result = analyzer.analyze_method(disasm, class_name=cls_name or disasm.get("class_name", ""), lang=lang)

            elif mod == "vmp_native":
                vmp_data = sample.get("vmp_result")
                insp_data = sample.get("inspect_result") or {}
                xref_data = sample.get("xref_result")
                native_libs = insp_data.get("native_libs") if isinstance(insp_data, dict) else None
                result = analyzer.analyze_vmp_native(
                    vmp=vmp_data,
                    native_libs=native_libs,
                    xref=xref_data,
                    lang=lang,
                )

            else:  # pipeline_issue
                stage_data = body.get("stage") if isinstance(body.get("stage"), dict) else {"name": str(body.get("stage") or "pipeline")}
                error_text = str(body.get("error_text") or "")
                doc = _get_doctor_cached(check_devices=False)
                result = analyzer.analyze_pipeline_issue(stage_data, error_text=error_text, doctor=doc, lang=lang)

        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400
        except UnpackError as exc:
            code_val = exc.code.value if hasattr(exc.code, "value") else str(exc.code)
            status_code = 400 if code_val == "ENGINE_UNAVAILABLE" else 502
            return jsonify(error=exc.message, code=code_val, hint=exc.hint), status_code

        ws_id = sample.get("workspace_id") or _active_ws_id()
        saved = ws_store.save_ai_analysis(ws_id, sample_id, mod, result)
        with lock:
            cur_list = [x for x in (sample.get("ai_analyses") or []) if x.get("id") != saved["id"]]
            sample["ai_analyses"] = [saved, *cur_list][:50]

        all_for_mod = ws_store.list_ai_analyses(workspace_id=ws_id, sample_id=sample_id, module=mod, limit=25)
        return jsonify(analysis=saved, analyses=all_for_mod)

    # =======================================================================
    # Legacy Backward-Compatible Endpoints (Hardened)
    # =======================================================================

    @app.get("/api/cache")
    def api_cache():
        with lock:
            items = []
            for sid, s in samples.items():
                if s["kind"] != "apk":
                    continue
                item: dict[str, Any] = {
                    "hash": sid,
                    "filename": s["name"],
                    "size_mb": round(s["size_bytes"] / 1024 / 1024, 1),
                }
                if s.get("scan_result"):
                    item["packer"] = s["scan_result"].get("packer_name")
                if s.get("last_job_id"):
                    item["last_job"] = s["last_job_id"]
                items.append(item)
        return jsonify(items=items)

    @app.get("/api/engines")
    def api_engines():
        doc = _run_doctor_rich(check_devices=True)
        return jsonify(engines=doc.get("engines", []))

    @app.post("/api/scan")
    def api_scan():
        if "file" not in request.files:
            return jsonify(error="No file uploaded", code="NO_FILE"), 400
        f = request.files["file"]
        safe = _safe_filename(f.filename, "")
        if not safe or not safe.lower().endswith(".apk"):
            return jsonify(error="File must be an .apk", code="INVALID_FILE"), 400

        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            f.save(tmp)
            tmp_path = Path(tmp.name)

        try:
            from unpack.core.scanner import PackerScanner

            result = PackerScanner().scan(tmp_path, verbose=True)
            return jsonify(result.to_verbose_dict())
        except Exception as exc:
            return jsonify(error=str(exc), code="SCAN_ERROR"), 500
        finally:
            tmp_path.unlink(missing_ok=True)

    @app.post("/api/full")
    def api_full():
        engine = request.form.get("engine", "")
        if engine not in {"", "memory", "frida", "ebpf"}:
            return jsonify(error=f"Invalid engine: {engine!r}", code="BAD_REQUEST"), 400
        try:
            timeout_s = _parse_int(request.form.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400

        deep = _parse_bool(request.form.get("deep"), default=False)
        anti_detect = _parse_bool(request.form.get("anti_detect"), default=True)
        start_from = request.form.get("start_from", "scan")
        if start_from not in {"scan", "scan_only", "dumping", "repairing"}:
            return jsonify(error=f"Invalid start_from: {start_from!r}", code="BAD_REQUEST"), 400
        cached_hash = request.form.get("apk_hash", "")

        sample: dict[str, Any] | None = None
        if cached_hash:
            sample = _get_sample_or_404(cached_hash)
            if sample is None:
                return jsonify(error="Cached APK not found", code="NOT_FOUND"), 404
        elif "file" in request.files and request.files["file"].filename:
            f = request.files["file"]
            if not _safe_filename(f.filename, "").lower().endswith(".apk"):
                return jsonify(error="File must be an .apk", code="INVALID_FILE"), 400
            try:
                sample = _save_uploaded_file(f)
            except ValueError as exc:
                return jsonify(error=str(exc), code="INVALID_FILE"), 400
        else:
            return jsonify(error="No file uploaded and no cached APK specified", code="NO_FILE"), 400

        job_id = _launch_pipeline_job(
            sample=sample,
            engine=engine,
            timeout_s=timeout_s,
            deep=deep,
            anti_detect=anti_detect,
            start_from=start_from,
        )
        return jsonify(job_id=job_id, apk_hash=sample["id"])

    @app.get("/api/job/<job_id>")
    def api_job_status(job_id: str):
        job = job_mgr.get(job_id)
        if job is None:
            return jsonify(error="Job not found", code="NOT_FOUND"), 404
        return jsonify(job)

    @app.get("/api/job/<job_id>/export")
    def api_job_export(job_id: str):
        job = job_mgr.get(job_id)
        if job is None:
            return jsonify(error="Job not found", code="NOT_FOUND"), 404
        if job["status"] != "done":
            return jsonify(error="Job not finished yet", status=job["status"], code="JOB_NOT_READY"), 400

        return jsonify(
            {
                "tool": "unpack",
                "version": APP_VERSION,
                "apk": job.get("apk"),
                "phases": job.get("phases", {}),
                "prompt_hint": (
                    "This is an UNPACK scan/dump result. Analyze: "
                    "1) packer technology and version "
                    "2) protection mechanisms to expect "
                    "3) recommended next steps for deeper analysis "
                    "4) which classes/methods to focus on"
                ),
            }
        )

    @app.post("/api/dump")
    def api_dump():
        if "file" not in request.files or not request.files["file"].filename:
            return jsonify(error="No file uploaded", code="NO_FILE"), 400
        f = request.files["file"]
        try:
            timeout_s = _parse_int(request.form.get("timeout"), 15, min_val=1, max_val=300, name="timeout")
        except ValueError as exc:
            return jsonify(error=str(exc), code="BAD_REQUEST"), 400
        engine = request.form.get("engine", "")
        deep = _parse_bool(request.form.get("deep"), default=False)
        anti_detect = _parse_bool(request.form.get("anti_detect"), default=True)
        try:
            sample = _save_uploaded_file(f)
        except ValueError as exc:
            return jsonify(error=str(exc), code="INVALID_FILE"), 400
        job_id = _launch_pipeline_job(
            sample=sample,
            engine=engine,
            timeout_s=timeout_s,
            deep=deep,
            anti_detect=anti_detect,
            start_from="scan",
        )
        return jsonify(job_id=job_id)

    @app.get("/api/dump/<job_id>")
    def api_dump_status(job_id: str):
        job = job_mgr.get(job_id)
        if job is None:
            return jsonify(error="Job not found", code="NOT_FOUND"), 404
        return jsonify(job)

    @app.post("/api/repair")
    def api_repair():
        files = request.files.getlist("files")
        files = [f for f in files if f and f.filename]
        if not files:
            return jsonify(error="No files uploaded", code="NO_FILE"), 400
        in_place = _parse_bool(request.form.get("in_place"), default=False)

        from unpack.repair.dex_repair import DexRepairPipeline

        pipeline = DexRepairPipeline()
        results = []
        with tempfile.TemporaryDirectory(prefix="unpack_repair_") as td:
            for idx, f in enumerate(files):
                safe = _safe_filename(f.filename, f"file_{idx}.dex")
                fpath = Path(td) / f"{idx}_{safe}"
                f.save(str(fpath))
                rr = pipeline.repair(fpath, in_place=in_place)
                results.append(
                    {
                        "file": safe,
                        "success": rr.success,
                        "actions": list(rr.actions),
                        "nop_methods": rr.nop_method_count,
                    }
                )
        return jsonify(results=results)

    @app.post("/api/verify")
    def api_verify():
        files = request.files.getlist("files")
        files = [f for f in files if f and f.filename]
        if not files:
            return jsonify(error="No files uploaded", code="NO_FILE"), 400

        from unpack.repair.verifier import DexVerifier

        verifier = DexVerifier()
        results = []
        with tempfile.TemporaryDirectory(prefix="unpack_verify_") as td:
            for idx, f in enumerate(files):
                safe = _safe_filename(f.filename, f"file_{idx}.dex")
                fpath = Path(td) / f"{idx}_{safe}"
                f.save(str(fpath))
                vr = verifier.verify(fpath)
                results.append(
                    {
                        "file": safe,
                        "valid": vr.valid,
                        "issues": list(vr.issues),
                        "stats": dict(vr.stats),
                    }
                )
        return jsonify(results=results)

    return app


def main() -> None:
    app = create_app()
    print(f"UNPACK Studio v{APP_VERSION}: http://127.0.0.1:8080")
    app.run(host="127.0.0.1", port=8080, debug=False)


if __name__ == "__main__":
    main()
