"""Deep offline APK security & structural inspector.

Extracts manifest metadata, permissions with risk classification, Android
components with exported-surface detection, APK v1/v2/v3/v3.1 signing schemes
and X.509 certificate metadata, native ELF libraries across all ABIs, embedded
DEX metrics, and rule-based mobile security findings with a 0-100 risk score
and letter grade.

Works offline without a device. Uses ``androguard`` and ``cryptography`` when
available, with graceful pure-Python fallbacks for air-gapped or minimal
installations.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from unpack.analysis.native import NativeAnalyzer, NativeLibInfo, shannon_entropy
from unpack.core.errors import ApkValidationError, ErrorCode, UnpackError
from unpack.repair.verifier import DexVerifier
from unpack.utils.apk import find_sibling_splits, get_package_name

# Android dangerous permissions (AOSP protectionLevel=dangerous)
_DANGEROUS_PERMISSIONS: dict[str, tuple[str, str]] = {
    "android.permission.READ_SMS": ("high", "Read SMS messages"),
    "android.permission.SEND_SMS": ("high", "Send SMS messages"),
    "android.permission.RECEIVE_SMS": ("high", "Intercept incoming SMS"),
    "android.permission.READ_CALL_LOG": ("high", "Read call history"),
    "android.permission.PROCESS_OUTGOING_CALLS": ("high", "Monitor/redirect outgoing calls"),
    "android.permission.RECORD_AUDIO": ("high", "Record microphone audio"),
    "android.permission.CAMERA": ("medium", "Access device camera"),
    "android.permission.ACCESS_FINE_LOCATION": ("high", "Access precise GPS location"),
    "android.permission.ACCESS_COARSE_LOCATION": ("medium", "Access approximate location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("high", "Access location in background"),
    "android.permission.READ_CONTACTS": ("high", "Read user contacts"),
    "android.permission.WRITE_CONTACTS": ("medium", "Modify user contacts"),
    "android.permission.READ_EXTERNAL_STORAGE": ("medium", "Read shared external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("medium", "Write shared external storage"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("high", "All-files storage access"),
    "android.permission.READ_PHONE_STATE": ("medium", "Read phone state & device identifiers"),
    "android.permission.READ_PHONE_NUMBERS": ("medium", "Read phone number"),
    "android.permission.CALL_PHONE": ("medium", "Initiate phone calls"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("high", "Draw overlays over other apps"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("high", "Request installation of APKs"),
    "android.permission.QUERY_ALL_PACKAGES": ("medium", "Enumerate all installed packages"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("high", "Accessibility service control"),
    "android.permission.GET_ACCOUNTS": ("medium", "Discover device accounts"),
    "android.permission.BODY_SENSORS": ("medium", "Access body sensors"),
}

_SIGNATURE_PERMISSIONS: frozenset[str] = frozenset({
    "android.permission.WRITE_SETTINGS",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.READ_LOGS",
    "android.permission.DUMP",
    "android.permission.PACKAGE_USAGE_STATS",
})

_SUSPICIOUS_ASSET_KEYWORDS: tuple[str, ...] = (
    "shell", "jiagu", "protect", "sec", "shield", "guard",
    "stub", "encrypt", "reinforce", "mogosec", "ijiami",
    "vmp", "dex.dat", ".dgc", "aliprotect",
)

# APK Signing Block magic & scheme IDs
_APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_SCHEME_V2_ID = 0x7109871A
_SCHEME_V3_ID = 0xF05368C0
_SCHEME_V31_ID = 0x1B93AD61

_DEX_ROOT_RE = re.compile(r"^classes\d*\.dex$")
_CERT_ENTRY_RE = re.compile(r"^META-INF/.*\.(?:RSA|DSA|EC)$", re.IGNORECASE)


@dataclass
class ManifestInfo:
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int | None = None
    target_sdk: int | None = None
    compile_sdk: int | None = None
    app_name: str = ""
    application_class: str = ""
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool | None = None
    network_security_config: str = ""
    extract_native_libs: bool | None = None
    is_split_apk: bool = False
    sibling_splits: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "compile_sdk": self.compile_sdk,
            "app_name": self.app_name,
            "application_class": self.application_class,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "network_security_config": self.network_security_config,
            "extract_native_libs": self.extract_native_libs,
            "is_split_apk": self.is_split_apk,
            "sibling_splits": self.sibling_splits,
        }


@dataclass
class PermissionInfo:
    name: str
    short_name: str
    protection_level: str  # "dangerous" | "signature" | "normal" | "custom"
    risk: str  # "high" | "medium" | "low" | "info"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "short_name": self.short_name,
            "protection_level": self.protection_level,
            "risk": self.risk,
            "description": self.description,
        }


@dataclass
class ComponentInfo:
    name: str
    component_type: str  # "activity" | "service" | "receiver" | "provider"
    exported: bool = False
    permission: str = ""
    intent_filters: list[str] = field(default_factory=list)
    is_launcher: bool = False
    risk_flag: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.component_type,
            "exported": self.exported,
            "permission": self.permission,
            "intent_filters": self.intent_filters,
            "is_launcher": self.is_launcher,
            "risk_flag": self.risk_flag,
        }


@dataclass
class ComponentsInfo:
    activities: list[ComponentInfo] = field(default_factory=list)
    services: list[ComponentInfo] = field(default_factory=list)
    receivers: list[ComponentInfo] = field(default_factory=list)
    providers: list[ComponentInfo] = field(default_factory=list)

    @property
    def exported_count(self) -> int:
        all_c = self.activities + self.services + self.receivers + self.providers
        return sum(1 for c in all_c if c.exported)

    @property
    def unprotected_exported_count(self) -> int:
        all_c = self.activities + self.services + self.receivers + self.providers
        return sum(1 for c in all_c if c.exported and not c.permission and not c.is_launcher)

    def to_dict(self) -> dict[str, Any]:
        return {
            "activities": [c.to_dict() for c in self.activities],
            "services": [c.to_dict() for c in self.services],
            "receivers": [c.to_dict() for c in self.receivers],
            "providers": [c.to_dict() for c in self.providers],
            "counts": {
                "activities": len(self.activities),
                "services": len(self.services),
                "receivers": len(self.receivers),
                "providers": len(self.providers),
                "exported": self.exported_count,
                "unprotected_exported": self.unprotected_exported_count,
            },
        }


@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    sha256: str = ""
    sha1: str = ""
    not_before: str = ""
    not_after: str = ""
    key_algorithm: str = ""
    key_size: int = 0
    is_debug_cert: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "key_algorithm": self.key_algorithm,
            "key_size": self.key_size,
            "is_debug_cert": self.is_debug_cert,
        }


@dataclass
class SigningInfo:
    v1_signed: bool = False
    v2_signed: bool = False
    v3_signed: bool = False
    v31_signed: bool = False
    schemes: list[str] = field(default_factory=list)
    is_debug_cert: bool = False
    certificates: list[CertificateInfo] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "v1_signed": self.v1_signed,
            "v2_signed": self.v2_signed,
            "v3_signed": self.v3_signed,
            "v31_signed": self.v31_signed,
            "schemes": self.schemes,
            "is_debug_cert": self.is_debug_cert,
            "certificates": [c.to_dict() for c in self.certificates],
        }


@dataclass
class DexSummary:
    name: str
    size_bytes: int
    sha256: str
    version: str = ""
    class_count: int = 0
    method_count: int = 0
    field_count: int = 0
    string_count: int = 0
    methods_with_code: int = 0
    nop_methods: int = 0
    code_coverage: float = 0.0
    entropy: float = 0.0
    health_score: float = 100.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "version": self.version,
            "class_count": self.class_count,
            "method_count": self.method_count,
            "field_count": self.field_count,
            "string_count": self.string_count,
            "methods_with_code": self.methods_with_code,
            "nop_methods": self.nop_methods,
            "code_coverage": round(self.code_coverage, 4),
            "entropy": self.entropy,
            "health_score": round(self.health_score, 2),
        }


@dataclass
class SecurityFinding:
    rule_id: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    category: str
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ApkInspectResult:
    file: str
    sha256: str
    size_bytes: int
    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    signing: SigningInfo = field(default_factory=SigningInfo)
    permissions: list[PermissionInfo] = field(default_factory=list)
    components: ComponentsInfo = field(default_factory=ComponentsInfo)
    native_libs: list[NativeLibInfo] = field(default_factory=list)
    dex_files: list[DexSummary] = field(default_factory=list)
    assets_count: int = 0
    suspicious_assets: list[str] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)
    risk_score: int = 0
    risk_grade: str = "A"
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "manifest": self.manifest.to_dict(),
            "signing": self.signing.to_dict(),
            "permissions": [p.to_dict() for p in self.permissions],
            "components": self.components.to_dict(),
            "native_libs": [n.to_dict() for n in self.native_libs],
            "dex_files": [d.to_dict() for d in self.dex_files],
            "assets_count": self.assets_count,
            "suspicious_assets": self.suspicious_assets,
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "risk_grade": self.risk_grade,
            "warnings": self.warnings,
        }


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(131072), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_apk_sig_block_schemes(apk_path: Path) -> tuple[bool, bool, bool]:
    """Scan ZIP APK Signing Block before Central Directory for v2/v3/v3.1 IDs."""
    v2 = v3 = v31 = False
    try:
        size = apk_path.stat().st_size
        if size < 64:
            return False, False, False
        with apk_path.open("rb") as f:
            # Locate End of Central Directory (EOCD) in last 65KB
            tail_len = min(size, 65557)
            f.seek(size - tail_len)
            tail = f.read(tail_len)
            eocd_pos = tail.rfind(b"PK\x05\x06")
            if eocd_pos < 0 or eocd_pos + 22 > len(tail):
                return False, False, False
            cd_offset = struct.unpack_from("<I", tail, eocd_pos + 16)[0]
            if cd_offset < 32 or cd_offset > size:
                return False, False, False
            f.seek(cd_offset - 24)
            footer = f.read(24)
            if len(footer) != 24 or footer[8:24] != _APK_SIG_BLOCK_MAGIC:
                return False, False, False
            block_size = struct.unpack_from("<Q", footer, 0)[0]
            if block_size < 24 or block_size > cd_offset:
                return False, False, False
            block_start = cd_offset - block_size - 8
            if block_start < 0:
                return False, False, False
            f.seek(block_start)
            # Cap read to 2MB for safety
            block = f.read(min(block_size + 8, 2 * 1024 * 1024))
            pos = 8
            end = len(block) - 24
            while pos + 12 <= end:
                pair_len = struct.unpack_from("<Q", block, pos)[0]
                if pair_len < 4 or pos + 8 + pair_len > len(block):
                    break
                scheme_id = struct.unpack_from("<I", block, pos + 8)[0]
                if scheme_id == _SCHEME_V2_ID:
                    v2 = True
                elif scheme_id == _SCHEME_V3_ID:
                    v3 = True
                elif scheme_id == _SCHEME_V31_ID:
                    v31 = True
                pos += 8 + pair_len
    except OSError:
        return False, False, False
    return v2, v3, v31


def _parse_v1_certs(zf: zipfile.ZipFile, entries: list[str]) -> list[CertificateInfo]:
    certs: list[CertificateInfo] = []
    cert_entries = [e for e in entries if _CERT_ENTRY_RE.match(e)]
    if not cert_entries:
        return certs

    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError:
        return certs

    seen_fp: set[str] = set()
    for entry in cert_entries:
        try:
            raw = zf.read(entry)
            loaded = pkcs7.load_der_pkcs7_certificates(raw)
        except Exception:
            continue
        for cert in loaded:
            sha256 = cert.fingerprint(hashes.SHA256()).hex()
            if sha256 in seen_fp:
                continue
            seen_fp.add(sha256)
            sha1 = cert.fingerprint(hashes.SHA1()).hex()
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            is_debug = "android debug" in subject.lower() or "android debug" in issuer.lower()
            pub = cert.public_key()
            key_algo = type(pub).__name__.replace("_", "").replace("PublicKey", "")
            key_size = int(getattr(pub, "key_size", 0) or 0)
            nb = getattr(cert, "not_valid_before_utc", None) or getattr(cert, "not_valid_before", "")
            na = getattr(cert, "not_valid_after_utc", None) or getattr(cert, "not_valid_after", "")
            certs.append(
                CertificateInfo(
                    subject=subject,
                    issuer=issuer,
                    serial_number=format(cert.serial_number, "x"),
                    sha256=sha256,
                    sha1=sha1,
                    not_before=nb.isoformat() if hasattr(nb, "isoformat") else str(nb),
                    not_after=na.isoformat() if hasattr(na, "isoformat") else str(na),
                    key_algorithm=key_algo,
                    key_size=key_size,
                    is_debug_cert=is_debug,
                )
            )
    return certs


def _safe_int(val: Any) -> int | None:
    if val is None or val == "":
        return None
    try:
        return int(str(val))
    except (ValueError, TypeError):
        return None


def _parse_bool_attr(val: Any, default: bool | None = None) -> bool | None:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("true", "1", "-1", "0xffffffff"):
        return True
    if s in ("false", "0"):
        return False
    return default


def _classify_permission(perm: str) -> PermissionInfo:
    short = perm.rsplit(".", 1)[-1]
    if perm in _DANGEROUS_PERMISSIONS:
        risk, desc = _DANGEROUS_PERMISSIONS[perm]
        return PermissionInfo(
            name=perm,
            short_name=short,
            protection_level="dangerous",
            risk=risk,
            description=desc,
        )
    if perm in _SIGNATURE_PERMISSIONS:
        return PermissionInfo(
            name=perm,
            short_name=short,
            protection_level="signature",
            risk="medium",
            description="Privileged/signature Android permission",
        )
    if perm.startswith("android.permission."):
        return PermissionInfo(
            name=perm,
            short_name=short,
            protection_level="normal",
            risk="low",
            description="",
        )
    return PermissionInfo(
        name=perm,
        short_name=short,
        protection_level="custom",
        risk="info",
        description="Custom or third-party permission",
    )


class ApkInspector:
    """Deep offline structural & security inspector for Android APK files."""

    def __init__(self) -> None:
        self._native = NativeAnalyzer()
        self._verifier = DexVerifier()

    def inspect(
        self,
        apk_path: Path,
        deep_elf: bool = True,
        include_dex_metrics: bool = True,
    ) -> ApkInspectResult:
        if not apk_path.exists():
            raise UnpackError(
                f"APK not found: {apk_path}",
                code=ErrorCode.FILE_NOT_FOUND,
                exit_code=5,
            )
        if not zipfile.is_zipfile(apk_path):
            raise ApkValidationError(f"Not a valid ZIP/APK archive: {apk_path}")

        size_bytes = apk_path.stat().st_size
        sha256 = _file_sha256(apk_path)
        result = ApkInspectResult(
            file=apk_path.name,
            sha256=sha256,
            size_bytes=size_bytes,
        )

        # Sibling splits
        siblings = find_sibling_splits(apk_path)
        result.manifest.sibling_splits = [s.name for s in siblings]
        result.manifest.is_split_apk = bool(siblings)

        with zipfile.ZipFile(apk_path, "r") as zf:
            entries = zf.namelist()
            assets = [e for e in entries if e.startswith("assets/")]
            result.assets_count = len(assets)
            result.suspicious_assets = sorted(
                e for e in assets
                if any(kw in e.lower() for kw in _SUSPICIOUS_ASSET_KEYWORDS)
            )

            # 1. Manifest, permissions, components
            self._inspect_manifest(apk_path, zf, result)

            # 2. Signing schemes & certificates
            self._inspect_signing(apk_path, zf, entries, result)

            # 3. Native libraries across all ABIs
            self._inspect_native_libs(zf, entries, result, deep_elf=deep_elf)

            # 4. Embedded DEX metrics
            if include_dex_metrics:
                self._inspect_dex_files(zf, entries, result)

        # 5. Security findings & risk scoring
        self._evaluate_findings(result)
        return result

    def _inspect_manifest(
        self,
        apk_path: Path,
        zf: zipfile.ZipFile,
        result: ApkInspectResult,
    ) -> None:
        andro_ok = False
        try:
            os.environ.setdefault("LOGURU_LEVEL", "ERROR")
            try:
                from loguru import logger as _lg
                _lg.disable("androguard")
            except ImportError:
                pass
            from androguard.core.apk import APK as AndroAPK

            a = AndroAPK(str(apk_path))
            andro_ok = True
            m = result.manifest
            m.package = a.get_package() or ""
            m.version_name = str(a.get_androidversion_name() or "")
            m.version_code = str(a.get_androidversion_code() or "")
            m.min_sdk = _safe_int(a.get_min_sdk_version())
            m.target_sdk = _safe_int(a.get_target_sdk_version())
            m.compile_sdk = _safe_int(a.get_attribute_value("manifest", "compileSdkVersion"))
            try:
                m.app_name = str(a.get_app_name() or "")
            except Exception:
                m.app_name = ""
            m.application_class = str(a.get_attribute_value("application", "name") or "")
            m.debuggable = bool(_parse_bool_attr(a.get_attribute_value("application", "debuggable"), False))
            m.allow_backup = bool(_parse_bool_attr(a.get_attribute_value("application", "allowBackup"), True))
            m.uses_cleartext_traffic = _parse_bool_attr(
                a.get_attribute_value("application", "usesCleartextTraffic"), None
            )
            m.network_security_config = str(
                a.get_attribute_value("application", "networkSecurityConfig") or ""
            )
            m.extract_native_libs = _parse_bool_attr(
                a.get_attribute_value("application", "extractNativeLibs"), None
            )

            # Permissions
            perms = sorted(set(a.get_permissions() or []))
            result.permissions = [_classify_permission(p) for p in perms]

            # Components with exported & intent-filter analysis
            self._extract_components_androguard(a, result)
        except ImportError:
            result.warnings.append(
                "androguard not installed — manifest inspection used minimal binary fallback"
            )
        except Exception as exc:
            result.warnings.append(f"androguard manifest parse fallback: {exc}")

        if not andro_ok:
            result.manifest.package = get_package_name(apk_path) or ""
            from unpack.engines.rescan import ComponentExtractor
            ext = ComponentExtractor()
            strings = ext.extract_manifest_strings(apk_path)
            for s in strings:
                if s.startswith("android.permission."):
                    result.permissions.append(_classify_permission(s))
            # Deduplicate fallback permissions
            seen_p: set[str] = set()
            deduped: list[PermissionInfo] = []
            for p in result.permissions:
                if p.name not in seen_p:
                    seen_p.add(p.name)
                    deduped.append(p)
            result.permissions = sorted(deduped, key=lambda x: x.name)

    @staticmethod
    def _extract_components_androguard(a, result: ApkInspectResult) -> None:
        xml = a.get_android_manifest_xml()
        if xml is None:
            return
        ns = "{http://schemas.android.com/apk/res/android}"
        app_el = xml.find("application")
        if app_el is None:
            return

        mapping = [
            ("activity", "activity", result.components.activities),
            ("activity-alias", "activity", result.components.activities),
            ("service", "service", result.components.services),
            ("receiver", "receiver", result.components.receivers),
            ("provider", "provider", result.components.providers),
        ]

        for tag, comp_type, bucket in mapping:
            for el in app_el.findall(tag):
                name = el.get(f"{ns}name") or ""
                if not name:
                    continue
                if name.startswith(".") and result.manifest.package:
                    name = result.manifest.package + name
                perm = el.get(f"{ns}permission") or ""
                exported_raw = el.get(f"{ns}exported")

                actions: list[str] = []
                is_launcher = False
                has_filter = False
                for flt in el.findall("intent-filter"):
                    has_filter = True
                    for act in flt.findall("action"):
                        aname = act.get(f"{ns}name")
                        if aname:
                            actions.append(aname)
                            if aname == "android.intent.action.MAIN":
                                for cat in flt.findall("category"):
                                    if cat.get(f"{ns}name") == "android.intent.category.LAUNCHER":
                                        is_launcher = True

                if exported_raw is not None:
                    exported = exported_raw.lower() == "true"
                else:
                    # Pre-Android 12 implicit exported when intent-filter present
                    exported = has_filter

                risk_flag = ""
                if exported and not perm and not is_launcher:
                    risk_flag = "unprotected_exported"

                bucket.append(
                    ComponentInfo(
                        name=name,
                        component_type=comp_type,
                        exported=exported,
                        permission=perm,
                        intent_filters=actions[:10],
                        is_launcher=is_launcher,
                        risk_flag=risk_flag,
                    )
                )

    @staticmethod
    def _inspect_signing(
        apk_path: Path,
        zf: zipfile.ZipFile,
        entries: list[str],
        result: ApkInspectResult,
    ) -> None:
        sig = result.signing
        sig.v1_signed = any(_CERT_ENTRY_RE.match(e) for e in entries)
        sig.v2_signed, sig.v3_signed, sig.v31_signed = _detect_apk_sig_block_schemes(apk_path)

        schemes: list[str] = []
        if sig.v1_signed:
            schemes.append("v1")
        if sig.v2_signed:
            schemes.append("v2")
        if sig.v3_signed:
            schemes.append("v3")
        if sig.v31_signed:
            schemes.append("v3.1")
        sig.schemes = schemes

        certs = _parse_v1_certs(zf, entries)
        sig.certificates = certs
        sig.is_debug_cert = any(c.is_debug_cert for c in certs)

    def _inspect_native_libs(
        self,
        zf: zipfile.ZipFile,
        entries: list[str],
        result: ApkInspectResult,
        deep_elf: bool,
    ) -> None:
        so_entries = sorted(e for e in entries if e.startswith("lib/") and e.endswith(".so"))
        for entry in so_entries[:200]:
            parts = entry.split("/")
            abi = parts[1] if len(parts) >= 3 else ""
            basename = parts[-1]
            if not deep_elf:
                info_z = zf.getinfo(entry)
                result.native_libs.append(
                    NativeLibInfo(
                        name=basename,
                        path=entry,
                        abi=abi,
                        size_bytes=info_z.file_size,
                    )
                )
                continue
            try:
                data = zf.read(entry)
            except (KeyError, zipfile.BadZipFile, OSError):
                continue
            result.native_libs.append(
                self._native.analyze_bytes(data, name=basename, abi=abi, path=entry)
            )

    def _inspect_dex_files(
        self,
        zf: zipfile.ZipFile,
        entries: list[str],
        result: ApkInspectResult,
    ) -> None:
        dex_entries = sorted(e for e in entries if _DEX_ROOT_RE.match(e))
        for entry in dex_entries:
            try:
                data = zf.read(entry)
            except (KeyError, zipfile.BadZipFile, OSError):
                continue
            vr = self._verifier.verify_bytes(data)
            version = data[4:7].decode("ascii", errors="replace") if len(data) >= 8 and data[:4] == b"dex\n" else ""
            result.dex_files.append(
                DexSummary(
                    name=entry,
                    size_bytes=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                    version=version,
                    class_count=int(vr.stats.get("class_count", 0)),
                    method_count=int(vr.stats.get("method_count", 0)),
                    field_count=int(vr.stats.get("field_count", 0)),
                    string_count=int(vr.stats.get("string_count", 0)),
                    methods_with_code=int(vr.stats.get("methods_with_code", 0)),
                    nop_methods=int(vr.stats.get("nop_only_methods", 0)),
                    code_coverage=float(vr.stats.get("code_coverage", 0.0)),
                    entropy=shannon_entropy(data[: 2 * 1024 * 1024]),
                    health_score=vr.health_score,
                )
            )

    @staticmethod
    def _evaluate_findings(result: ApkInspectResult) -> None:
        findings: list[SecurityFinding] = []
        m = result.manifest
        s = result.signing

        if m.debuggable:
            findings.append(
                SecurityFinding(
                    rule_id="APK-MANIFEST-001",
                    severity="high",
                    category="manifest",
                    title="Application is debuggable",
                    description="android:debuggable=\"true\" allows arbitrary JDWP attachment and memory inspection on non-rooted devices.",
                    evidence="AndroidManifest.xml: android:debuggable=true",
                    remediation="Remove android:debuggable or set it to false for release builds.",
                )
            )

        if m.allow_backup:
            findings.append(
                SecurityFinding(
                    rule_id="APK-MANIFEST-002",
                    severity="medium",
                    category="manifest",
                    title="Application allows ADB backup",
                    description="android:allowBackup is enabled, potentially exposing private app data via adb backup on older Android versions.",
                    evidence="AndroidManifest.xml: android:allowBackup=true",
                    remediation="Set android:allowBackup=\"false\" or define strict dataExtractionRules.",
                )
            )

        if m.uses_cleartext_traffic is True:
            findings.append(
                SecurityFinding(
                    rule_id="APK-MANIFEST-003",
                    severity="medium",
                    category="network",
                    title="Cleartext HTTP traffic explicitly permitted",
                    description="android:usesCleartextTraffic=\"true\" allows unencrypted HTTP connections vulnerable to MitM.",
                    evidence="AndroidManifest.xml: usesCleartextTraffic=true",
                    remediation="Set android:usesCleartextTraffic=\"false\" and enforce TLS via networkSecurityConfig.",
                )
            )

        if m.target_sdk is not None and m.target_sdk < 28:
            findings.append(
                SecurityFinding(
                    rule_id="APK-MANIFEST-004",
                    severity="medium",
                    category="manifest",
                    title=f"Outdated targetSdkVersion ({m.target_sdk})",
                    description="Targeting API < 28 disables modern Android security defaults (cleartext restrictions, stricter exported rules).",
                    evidence=f"targetSdkVersion={m.target_sdk}",
                    remediation="Upgrade targetSdkVersion to a supported modern Android API level (>= 33).",
                )
            )

        if s.is_debug_cert:
            findings.append(
                SecurityFinding(
                    rule_id="APK-SIGN-001",
                    severity="high",
                    category="signing",
                    title="Signed with Android Debug certificate",
                    description="APK is signed with a development/debug key rather than a production release key.",
                    evidence=", ".join(c.subject for c in s.certificates if c.is_debug_cert),
                    remediation="Sign release APKs with a dedicated production keystore.",
                )
            )

        if s.v1_signed and not s.v2_signed and not s.v3_signed:
            findings.append(
                SecurityFinding(
                    rule_id="APK-SIGN-002",
                    severity="medium",
                    category="signing",
                    title="v1 JAR signature only (Janus-exposed on legacy Android)",
                    description="APK uses only v1 JAR signing without v2/v3 full-archive APK Signature Scheme.",
                    evidence=f"schemes={s.schemes}",
                    remediation="Sign APK with APK Signature Scheme v2/v3 via apksigner.",
                )
            )

        unprotected = result.components.unprotected_exported_count
        if unprotected > 0:
            samples = [
                c.name for c in (
                    result.components.activities
                    + result.components.services
                    + result.components.receivers
                    + result.components.providers
                )
                if c.exported and not c.permission and not c.is_launcher
            ][:5]
            findings.append(
                SecurityFinding(
                    rule_id="APK-COMP-001",
                    severity="medium" if unprotected < 5 else "high",
                    category="components",
                    title=f"{unprotected} exported component(s) without permission guard",
                    description="Exported components without an android:permission attribute can be invoked by arbitrary third-party apps.",
                    evidence=", ".join(samples),
                    remediation="Set android:exported=\"false\" or protect sensitive components with signature-level permissions.",
                )
            )

        high_perms = [p.short_name for p in result.permissions if p.risk == "high"]
        if len(high_perms) >= 3:
            findings.append(
                SecurityFinding(
                    rule_id="APK-PERM-001",
                    severity="medium",
                    category="permissions",
                    title=f"Requests {len(high_perms)} high-sensitivity permissions",
                    description="Broad high-risk permission footprint increases attack surface and privacy impact.",
                    evidence=", ".join(high_perms[:8]),
                    remediation="Apply least-privilege principle and remove unused dangerous permissions.",
                )
            )

        high_ent_sos = [n.name for n in result.native_libs if "high_entropy_packed" in n.risk_flags]
        if high_ent_sos:
            findings.append(
                SecurityFinding(
                    rule_id="APK-NATIVE-001",
                    severity="info",
                    category="native",
                    title=f"{len(high_ent_sos)} high-entropy native library(ies) detected",
                    description="ELF sections with Shannon entropy >= 7.2 strongly indicate packed, encrypted, or obfuscated native code (common in commercial packers/VMP).",
                    evidence=", ".join(high_ent_sos[:6]),
                    remediation="Inspect with dynamic memory dump (`unpack dump -e memory`) or native reverse engineering.",
                )
            )

        weak_elf = [
            n.name for n in result.native_libs
            if n.is_elf and (not n.is_pie or not n.has_nx or n.relro == "none")
        ]
        if weak_elf:
            findings.append(
                SecurityFinding(
                    rule_id="APK-NATIVE-002",
                    severity="low",
                    category="native",
                    title=f"{len(weak_elf)} native library(ies) missing standard ELF mitigations",
                    description="One or more ELF shared libraries lack PIE, NX stack, or RELRO hardening.",
                    evidence=", ".join(weak_elf[:6]),
                    remediation="Compile native libraries with `-fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack`.",
                )
            )

        nop_total = sum(d.nop_methods for d in result.dex_files)
        if nop_total > 0:
            findings.append(
                SecurityFinding(
                    rule_id="APK-DEX-001",
                    severity="info",
                    category="packing",
                    title=f"{nop_total} NOP-filled method(s) in APK DEX",
                    description="Methods whose bytecode is zeroed (NOP-only) at rest indicate function-extraction packing.",
                    evidence=f"nop_methods={nop_total}",
                    remediation="Use `unpack dump --deep` or `unpack rescan` to recover decrypted CodeItems at runtime.",
                )
            )

        result.findings = findings

        weights = {"critical": 25, "high": 16, "medium": 9, "low": 4, "info": 1}
        score = min(100, sum(weights.get(f.severity, 0) for f in findings))
        result.risk_score = score
        if score <= 10:
            result.risk_grade = "A"
        elif score <= 25:
            result.risk_grade = "B"
        elif score <= 45:
            result.risk_grade = "C"
        elif score <= 70:
            result.risk_grade = "D"
        else:
            result.risk_grade = "F"
