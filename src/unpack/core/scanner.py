from __future__ import annotations

import re
import struct
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ProtectionLevel(Enum):
    NONE = "none"
    DEX_ENCRYPTION = "dex_encryption"
    FUNCTION_EXTRACTION = "function_extraction"
    VMP = "vmp"
    DEX2C = "dex2c"
    UNKNOWN = "unknown"


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
    all_dex_info: list[dict] = field(default_factory=list)
    suspicious_assets: list[str] = field(default_factory=list)
    app_class: str | None = None
    all_candidates: list[dict] = field(default_factory=list)

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
        d["all_dex_info"] = self.all_dex_info
        d["suspicious_assets"] = self.suspicious_assets
        d["all_candidates"] = self.all_candidates
        return d

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
# Signature database — 24 vendors, ~170 indicators
# ---------------------------------------------------------------------------

@dataclass
class _PackerSig:
    so_files: list[str] = field(default_factory=list)
    asset_files: list[str] = field(default_factory=list)
    app_classes: list[str] = field(default_factory=list)
    dex_class_prefixes: list[str] = field(default_factory=list)
    cert_keywords: list[str] = field(default_factory=list)
    vmp_indicators: list[str] = field(default_factory=list)
    dex2c_indicators: list[str] = field(default_factory=list)
    version_hints: list[tuple[str, str]] = field(default_factory=list)


PACKER_SIGNATURES: dict[str, _PackerSig] = {
    # ── Chinese domestic packers ──────────────────────────────────────

    "360加固保": _PackerSig(
        so_files=[
            "libjiagu.so", "libjiagu_a64.so", "libjiagu_x86.so", "libjiagu_x64.so",
            "libprotectClass.so", "libjiagu_art.so", "libjiagu_ls.so",
            "libjgdtc.so", "libjgdtc_a64.so", "libjgdtc_x86.so",
        ],
        asset_files=[
            "libjiagu.so", "libjiagu_a64.so", "libjiagu_x86.so", "libjiagu_x64.so",
            ".appkey",
        ],
        app_classes=[
            "com.stub.StubApp",
            "com.qihoo.util.StubApp",
            "com.qihoo360.replugin.loader.a.PluginApp",
        ],
        dex_class_prefixes=["Lcom/stub/", "Lcom/qihoo/util/"],
        cert_keywords=["qihoo", "360"],
        vmp_indicators=["libjiagu_vmp.so", "libjiagu_ls.so"],
        dex2c_indicators=["libjgdtc.so", "libjgdtc_a64.so", "libjgdtc_x86.so"],
        version_hints=[
            ("libjgdtc.so", "v4 (dex2c)"),
            ("libjiagu_ls.so", "v4 (vmp)"),
            ("libjiagu_a64.so", "v3"),
            ("libjiagu_art.so", "v2 (art)"),
            ("libprotectClass.so", "v1"),
            ("monster.dex", "v1 (monster)"),
        ],
    ),

    "腾讯乐固": _PackerSig(
        so_files=[
            "libshell-super.so", "libshellx-super.so",
            "libshell-super.2019.so", "libshellx-super.2019.so",
            "libtxAppProtect.so",
            "libBugly.so", "libBugly-yaq.so", "libzBugly-yaq.so",
            "liblbs.so", "libmain.so", "libshell.so",
            "libtup.so", "liblegudb.so",
        ],
        asset_files=[
            "tosversion", "0OO00l111l1l", "o0oooOO0ooOo.dat",
            "00O000ll111l.dex", "000O00ll111l.dex",
            "0000000lllll.dex", "00000olllll.dex",
            "mix.dex", "mixz.dex",
        ],
        app_classes=[
            "com.tencent.StubShell.TxAppEntry",
            "com.tencent.bugly.legu.CrashModule",
        ],
        dex_class_prefixes=["Lcom/tencent/StubShell/"],
        cert_keywords=["tencent"],
        vmp_indicators=["libshell-super.2.so", "libshell-super.2019.so"],
        dex2c_indicators=[],
        version_hints=[
            ("libshell-super.2019.so", "v3 (2019+)"),
            ("libshellx-super.2019.so", "v3 (2019+ x86)"),
            ("libBugly-yaq.so", "v3 (yaq)"),
            ("libshell-super.so", "v2"),
            ("libtup.so", "v1"),
            ("liblegudb.so", "v1"),
        ],
    ),

    "腾讯御安全": _PackerSig(
        so_files=[
            "libtosprotection.so",
            "libtosprotection.armeabi.so", "libtosprotection.armeabi-v7a.so",
            "libtosprotection.x86.so",
        ],
        asset_files=["t86", "tosversion"],
        app_classes=["com.tencent.tos.TosApplication"],
        dex_class_prefixes=["Lcom/tencent/tos/"],
        cert_keywords=[],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[
            ("libtosprotection.x86.so", "multi-arch"),
            ("libtosprotection.so", "default"),
        ],
    ),

    "梆梆安全": _PackerSig(
        so_files=[
            "libDexHelper.so", "libDexHelper-x86.so",
            "libSecShell.so", "libSecShell-x86.so",
            "libsecexe.so", "libsecmain.so",
            "libSecPreLaunch.so",
            "libsecsecsdk.so",
        ],
        asset_files=["classes.dgc", "secData0.jar"],
        app_classes=[
            "com.secshell.app.SecAppWrapper",
            "com.secshell.secData.SecAppApplication",
            "com.secshell.secData.ApplicationWrapper",
        ],
        dex_class_prefixes=["Lcom/secshell/"],
        cert_keywords=["bangcle", "secshell"],
        vmp_indicators=["libsecmain.so", "libSecPreLaunch.so"],
        dex2c_indicators=[],
        version_hints=[
            ("libDexHelper.so", "企业版"),
            ("libSecShell.so", "企业版"),
            ("libsecexe.so", "免费版"),
            ("libsecmain.so", "免费版"),
        ],
    ),

    "爱加密": _PackerSig(
        so_files=[
            "libexec.so", "libexecmain.so", "libexecv3.so",
            "libexecCrypto.so",
        ],
        asset_files=["ijiami.dat", "ijiami.ajm", "af.bin"],
        app_classes=[
            "s.h.e.l.l.S",
            "com.shell.SuperApplication",
        ],
        dex_class_prefixes=["Ls/h/e/l/l/"],
        cert_keywords=["ijiami"],
        vmp_indicators=["libexecv3vmp.so"],
        dex2c_indicators=[],
        version_hints=[
            ("libexecv3.so", "v3"),
            ("libexecv3vmp.so", "v3 (vmp)"),
            ("libexecmain.so", "v2"),
            ("libexec.so", "v1"),
        ],
    ),

    "网易易盾": _PackerSig(
        so_files=[
            "libnqshield.so", "libnqshieldx86.so",
            "libnesec.so",
        ],
        asset_files=["libreinforce.so"],
        app_classes=[
            "com.netease.nis.wrapper.MyApplication",
            "com.nq.shield.MyApplication",
        ],
        dex_class_prefixes=["Lcom/netease/nis/", "Lcom/nq/shield/"],
        cert_keywords=["netease"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[
            ("libnesec.so", "v2"),
            ("libnqshield.so", "v1"),
        ],
    ),

    "百度加固": _PackerSig(
        so_files=[
            "libbaiduprotect.so", "libbaiduprotect_x86.so",
            "libbaiduprotect_art.so", "libdl_fix.so",
        ],
        asset_files=["baiduprotect.jar", "baiduprotect1.jar"],
        app_classes=["com.baidu.protect.StubApplication"],
        dex_class_prefixes=["Lcom/baidu/protect/"],
        cert_keywords=["baidu"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[
            ("libbaiduprotect_art.so", "art-aware"),
            ("libbaiduprotect.so", "default"),
        ],
    ),

    "阿里聚安全": _PackerSig(
        so_files=[
            "libsgmain.so", "libsgsecuritybody.so",
            "libmobisec.so", "libfakejni.so",
            "libzuma.so", "libzumadata.so",
            "libpreverify1.so",
            "libdemolish.so", "libdemolishdata.so",
        ],
        asset_files=["aliprotect.dat"],
        app_classes=[
            "com.alibaba.wireless.security.open.SecurityGuardManager",
        ],
        dex_class_prefixes=[
            "Lcom/alibaba/wireless/security/",
            "Lcom/alibaba/security/",
            "Lcom/taobao/wireless/security/",
        ],
        cert_keywords=["alibaba", "taobao"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[
            ("libdemolish.so", "v2 (demolish)"),
            ("libzuma.so", "v2 (zuma)"),
            ("libsgmain.so", "v1"),
        ],
    ),

    "娜迦加固": _PackerSig(
        so_files=[
            "libchaosvmp.so", "libddog.so", "libfdog.so", "libedog.so",
        ],
        asset_files=["libchaosvmp.so"],
        app_classes=["com.naga.NagaApplication"],
        dex_class_prefixes=["Lcom/naga/"],
        cert_keywords=["nagain", "naga"],
        vmp_indicators=["libchaosvmp.so"],
        dex2c_indicators=[],
        version_hints=[
            ("libedog.so", "企业版"),
            ("libchaosvmp.so", "vmp"),
            ("libddog.so", "standard"),
        ],
    ),

    "通付盾": _PackerSig(
        so_files=["libegis.so", "libNSaferOnly.so"],
        asset_files=[],
        app_classes=["com.tongfudun.StubApplication"],
        dex_class_prefixes=["Lcom/tongfudun/"],
        cert_keywords=["tongfudun", "payegis"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[
            ("libNSaferOnly.so", "v2"),
            ("libegis.so", "v1"),
        ],
    ),

    "几维安全": _PackerSig(
        so_files=["libkwscmm.so", "libkwscr.so", "libkwslinker.so"],
        asset_files=[],
        app_classes=[],
        dex_class_prefixes=["Lcom/kiwisec/"],
        cert_keywords=["kiwisec"],
        vmp_indicators=["libkwscmm.so"],
        dex2c_indicators=[],
        version_hints=[
            ("libkwslinker.so", "v3 (linker)"),
            ("libkwscmm.so", "v2 (vmp)"),
            ("libkwscr.so", "v1"),
        ],
    ),

    "海云安": _PackerSig(
        so_files=["libitsec.so"],
        asset_files=["itse"],
        app_classes=["c.b.c.b"],
        dex_class_prefixes=[],
        cert_keywords=["haiyunan"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[],
    ),

    "中国移动加固": _PackerSig(
        so_files=[
            "libcmvmp.so",
            "libmogosec_dex.so", "libmogosec_sodecrypt.so",
            "libmogosecurity.so",
        ],
        asset_files=[
            "mogosec_classes", "mogosec_data",
            "mogosec_dexinfo", "mogosec_march",
        ],
        app_classes=["com.mogosec.AppMgr"],
        dex_class_prefixes=["Lcom/mogosec/"],
        cert_keywords=["cmcc", "mogosec"],
        vmp_indicators=["libcmvmp.so"],
        dex2c_indicators=[],
        version_hints=[
            ("libcmvmp.so", "vmp"),
            ("libmogosec_dex.so", "standard"),
        ],
    ),

    "珊瑚灵御": _PackerSig(
        so_files=["libreincp.so", "libreincp_x86.so"],
        asset_files=[],
        app_classes=["com.coral.util.StubApplication"],
        dex_class_prefixes=["Lcom/coral/"],
        cert_keywords=["coral"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[],
    ),

    "瑞星": _PackerSig(
        so_files=["librsprotect.so"],
        asset_files=[],
        app_classes=["com.rsprotect.MSApplication"],
        dex_class_prefixes=["Lcom/rsprotect/"],
        cert_keywords=["rising"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[],
    ),

    "顶象": _PackerSig(
        so_files=["libx3g.so"],
        asset_files=["x3g"],
        app_classes=[],
        dex_class_prefixes=[],
        cert_keywords=["dingxiang"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[],
    ),

    "盛大加固": _PackerSig(
        so_files=["libapssec.so"],
        asset_files=[],
        app_classes=[],
        dex_class_prefixes=[],
        cert_keywords=["shanda"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[],
    ),

    "网秦": _PackerSig(
        so_files=["libnqshield.so"],
        asset_files=[],
        app_classes=[],
        dex_class_prefixes=[],
        cert_keywords=["nqshield", "netqin"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[],
    ),

    "UU安全": _PackerSig(
        so_files=["libuusafe.jar.so", "libuusafe.so", "libuusafeempty.so"],
        asset_files=[],
        app_classes=[],
        dex_class_prefixes=[],
        cert_keywords=["uusafe"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[],
    ),

    "apktoolplus": _PackerSig(
        so_files=["libapktoolplus_jiagu.so"],
        asset_files=["jiagu_data.bin", "sign.bin"],
        app_classes=[],
        dex_class_prefixes=[],
        cert_keywords=[],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[],
    ),

    # ── International packers ─────────────────────────────────────────

    "DexProtector": _PackerSig(
        so_files=["libdexprotector.so", "libdexprotector_h.so"],
        asset_files=[
            "classes.dex.dat",
            "dp.arm-v7.so.dat", "dp.arm.so.dat",
            "dp.arm-v8.so.dat",
            "dp.x86.so.dat", "dp.x86_64.so.dat",
        ],
        app_classes=[],
        dex_class_prefixes=[],
        cert_keywords=["licel", "dexprotect"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[
            ("dp.arm-v8.so.dat", "v2 (arm64)"),
            ("dp.arm-v7.so.dat", "v1"),
            ("classes.dex.dat", "default"),
        ],
    ),

    "APKProtect": _PackerSig(
        so_files=["libAPKProtect.so"],
        asset_files=[],
        app_classes=[],
        dex_class_prefixes=[],
        cert_keywords=["apkprotect"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[],
    ),

    "LIAPP": _PackerSig(
        so_files=["libLIAPP.so", "liblockin.so"],
        asset_files=["LIAPP.ini", "LIAPPEgg.dex"],
        app_classes=[],
        dex_class_prefixes=[],
        cert_keywords=["lockin", "liapp"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[
            ("LIAPPEgg.dex", "egg packer"),
            ("LIAPP.ini", "standard"),
        ],
    ),

    "AppSealing": _PackerSig(
        so_files=["libcovault-appsec.so", "libcovault.so"],
        asset_files=[],
        app_classes=[],
        dex_class_prefixes=[],
        cert_keywords=["appsealing", "covault"],
        vmp_indicators=[],
        dex2c_indicators=[],
        version_hints=[],
    ),
}


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
        from androguard.core.apk import APK as AndroAPK
        a = AndroAPK(apk_zip.filename)
        return a.get_attribute_value("application", "name")
    except Exception:
        pass
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
            except Exception:
                pass
    return None


# ---------------------------------------------------------------------------
# DEX header helpers
# ---------------------------------------------------------------------------

_DEX_MAGIC = b"dex\n"


def _count_dex_classes(data: bytes) -> int | None:
    if len(data) < 96 or data[:4] != _DEX_MAGIC:
        return None
    try:
        class_defs_size = struct.unpack_from("<I", data, 96)[0]
        return class_defs_size
    except struct.error:
        return None


# ---------------------------------------------------------------------------
# SO export analysis (via LIEF, optional)
# ---------------------------------------------------------------------------

def _check_so_exports(apk_zip: zipfile.ZipFile, so_entry: str) -> list[str]:
    indicators: list[str] = []
    try:
        import lief
    except ImportError:
        return indicators

    try:
        data = apk_zip.read(so_entry)
    except KeyError:
        return indicators

    import tempfile, os
    fd, tmp = tempfile.mkstemp(suffix=".so")
    try:
        os.write(fd, data)
        os.close(fd)
        binary = lief.parse(tmp)
        if binary is None:
            return indicators
        exports = {sym.name for sym in binary.exported_symbols}
        vmp_keywords = {
            "vmp", "VMP", "vm_interpret", "vmInterpret", "bytecode_handler",
            "vmp_entry", "VmpEntry", "runVmp", "vmp_decode",
        }
        dex2c_keywords = {
            "dex2c", "java2c", "DtcLoader",
        }
        for kw in vmp_keywords:
            if any(kw in exp for exp in exports):
                indicators.append(f"vmp_export:{kw}")
        for kw in dex2c_keywords:
            if any(kw in exp for exp in exports):
                indicators.append(f"dex2c_export:{kw}")
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
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


class PackerScanner:
    def scan(self, apk_path: Path, verbose: bool = False, extra_apks: list[Path] | None = None) -> ScanResult:
        if not zipfile.is_zipfile(apk_path):
            return ScanResult(details="Not a valid ZIP/APK file")

        with zipfile.ZipFile(apk_path, "r") as zf:
            entries = set(zf.namelist())

            extra_zfs: list[zipfile.ZipFile] = []
            if extra_apks:
                for ep in extra_apks:
                    try:
                        ezf = zipfile.ZipFile(ep, "r")
                        entries.update(ezf.namelist())
                        extra_zfs.append(ezf)
                    except zipfile.BadZipFile:
                        continue

            all_zfs = [zf] + extra_zfs

            scores: dict[str, float] = {}
            all_matches: dict[str, list[str]] = {}

            dim_scores: dict[str, dict[str, float]] = {}

            for packer, sig in PACKER_SIGNATURES.items():
                score = 0.0
                matches: list[str] = []
                dims: dict[str, float] = {}

                s0 = score
                score, matches = self._check_so(entries, sig, score, matches)
                if score > s0: dims["so_files"] = score - s0

                s0 = score
                score, matches = self._check_assets(entries, sig, score, matches)
                if score > s0: dims["assets"] = score - s0

                s0 = score
                for azf in all_zfs:
                    score, matches = self._check_app_class(azf, sig, score, matches)
                    if score > s0:
                        break
                if score > s0: dims["app_class"] = score - s0

                has_other_signal = score > 0
                needs_dex_only = not sig.so_files and not sig.asset_files and not sig.app_classes
                if has_other_signal or needs_dex_only:
                    s0 = score
                    for azf in all_zfs:
                        azf_entries = set(azf.namelist())
                        score, matches = self._check_dex_classes(azf, azf_entries, sig, score, matches)
                        if score > s0:
                            break
                    if score > s0: dims["dex_classes"] = score - s0

                s0 = score
                score, matches = self._check_cert(entries, sig, score, matches)
                if score > s0: dims["cert"] = score - s0

                s0 = score
                score, matches = self._check_small_dex(zf, entries, score, matches, packer)
                if score > s0: dims["small_dex"] = score - s0

                if score > 0:
                    scores[packer] = score
                    all_matches[packer] = matches
                    dim_scores[packer] = dims

            for ezf in extra_zfs:
                try:
                    ezf.close()
                except Exception:
                    pass

            max_possible = (
                _WEIGHT_SO + _WEIGHT_ASSET + _WEIGHT_APP_CLASS
                + _WEIGHT_DEX_PREFIX + _WEIGHT_CERT + _WEIGHT_SMALL_DEX
            )

            if not scores:
                result = ScanResult(
                    protection_level=ProtectionLevel.NONE,
                    details="No known packer signatures found",
                )
            else:
                best = max(scores, key=scores.get)  # type: ignore[arg-type]
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

                result = ScanResult(
                    packer_name=best,
                    packer_version=version,
                    confidence=confidence,
                    protection_level=protection,
                    matched_signatures=all_matches[best],
                    score_breakdown=breakdown,
                    details=(
                        f"Detected {best}{version_str} "
                        f"(score {best_score:.1f}/{max_possible:.1f})"
                    ),
                )

            if verbose:
                self._populate_verbose(result, zf, apk_path, entries, scores, all_matches)

            return result

    def _populate_verbose(
        self, result: ScanResult, zf: zipfile.ZipFile,
        apk_path: Path, entries: set[str],
        scores: dict[str, float], all_matches: dict[str, list[str]],
    ):
        result.apk_info = {
            "filename": apk_path.name,
            "size_mb": apk_path.stat().st_size / 1024 / 1024,
            "dex_count": sum(1 for e in entries if e.endswith(".dex")),
            "so_count": sum(1 for e in entries if e.endswith(".so")),
        }

        from unpack.utils.apk import get_package_name
        result.apk_info["package"] = get_package_name(apk_path) or "unknown"

        result.all_so_files = sorted(
            e for e in entries if e.endswith(".so") and "arm64" in e
        )

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

        result.app_class = _extract_application_class(zf)

        result.all_candidates = sorted(
            [{"name": name, "score": score, "signatures": all_matches[name]}
             for name, score in scores.items()],
            key=lambda x: x["score"], reverse=True,
        )

    def _check_so(
        self, entries: set[str], sig: _PackerSig, score: float, matches: list[str],
    ) -> tuple[float, list[str]]:
        for so_name in sig.so_files:
            for entry in entries:
                if entry.startswith("lib/") and entry.endswith(so_name):
                    score += _WEIGHT_SO
                    matches.append(f"so:{entry}")
                    return score, matches
        return score, matches

    def _check_assets(
        self, entries: set[str], sig: _PackerSig, score: float, matches: list[str],
    ) -> tuple[float, list[str]]:
        for asset_name in sig.asset_files:
            candidate = f"assets/{asset_name}"
            if candidate in entries:
                score += _WEIGHT_ASSET
                matches.append(f"asset:{candidate}")
                return score, matches
        return score, matches

    def _check_app_class(
        self, zf: zipfile.ZipFile, sig: _PackerSig, score: float, matches: list[str],
    ) -> tuple[float, list[str]]:
        if not sig.app_classes:
            return score, matches
        app_class = _extract_application_class(zf)
        if app_class:
            for known in sig.app_classes:
                if known in app_class:
                    score += _WEIGHT_APP_CLASS
                    matches.append(f"app_class:{app_class}")
                    return score, matches
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
            except Exception:
                continue
            for prefix in sig.dex_class_prefixes:
                if prefix.encode("utf-8") in data:
                    score += _WEIGHT_DEX_PREFIX
                    matches.append(f"dex_class:{prefix}")
                    return score, matches
        return score, matches

    def _check_cert(
        self, entries: set[str], sig: _PackerSig, score: float, matches: list[str],
    ) -> tuple[float, list[str]]:
        if not sig.cert_keywords:
            return score, matches
        meta_entries = [e for e in entries if e.startswith("META-INF/")]
        meta_lower = " ".join(meta_entries).lower()
        for kw in sig.cert_keywords:
            if kw.lower() in meta_lower:
                score += _WEIGHT_CERT
                matches.append(f"cert_keyword:{kw}")
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
            except Exception:
                pass
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
