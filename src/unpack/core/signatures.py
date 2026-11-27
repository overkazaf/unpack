"""Packer signature database — 24 domestic and international Android packers."""

from __future__ import annotations

from dataclasses import dataclass, field


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


PackerSignature = _PackerSig


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

__all__ = ["PACKER_SIGNATURES", "PackerSignature", "_PackerSig"]
