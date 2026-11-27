"""Deep interactive pipeline planner and async job orchestrator."""

from __future__ import annotations

import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from unpack.studio.schemas import PIPELINE_MODES, get_logger, normalize_lang
from unpack.studio.services.analysis import (
    aggregate_vmp_analysis,
    analyze_xref_dex_bytes,
    repair_dex_with_diff,
    scan_apk_rich,
)
from unpack.studio.services.reporting import render_commercial_report

if TYPE_CHECKING:
    from unpack.studio.context import StudioContext

logger = get_logger("unpack.studio.pipeline")


def packer_plain_explanation(scan: dict[str, Any] | None, is_zh: bool) -> str:
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


def build_pipeline_plan(
    ctx: StudioContext,
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
    is_zh = normalize_lang(lang) == "zh"
    file_ok = ctx.sample_file_exists(sample)

    # Auto-scan APK only when source file exists on disk
    if sample["kind"] == "apk" and sample.get("scan_result") is None and file_ok:
        try:
            sc = scan_apk_rich(sample["path"])
            with ctx.lock:
                sample["scan_result"] = sc
        except Exception:
            logger.debug("Auto-scan failed during pipeline planning for %s", sample["id"], exc_info=True)

    scan = sample.get("scan_result") or {}
    doc = ctx.get_doctor_cached(check_devices=check_devices, force_refresh=refresh_doctor)
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

    checks = _build_preflight_checks(
        sample=sample,
        file_ok=file_ok,
        is_apk=is_apk,
        is_device_mode=is_device_mode,
        selected_mode=selected_mode,
        engine=engine,
        online_devices=online_devices,
        avail_engines=avail_engines,
        effective_repack=effective_repack,
        is_zh=is_zh,
    )
    blocking_count = sum(1 for c in checks if c["status"] == "block")
    warning_count = sum(1 for c in checks if c["status"] == "warn")

    stages = _build_stage_blueprints(
        sample=sample,
        is_apk=is_apk,
        is_device_mode=is_device_mode,
        effective_repack=effective_repack,
        effective_deep=effective_deep,
        generate_report=generate_report,
        engine=engine,
        timeout_s=timeout_s,
        online_devices=online_devices,
        avail_engines=avail_engines,
        is_zh=is_zh,
    )

    return {
        "sample_id": sample["id"],
        "sample_name": sample["name"],
        "sample_kind": sample["kind"],
        "mode": selected_mode,
        "recommended_mode": rec_mode,
        "recommendation_reason": rec_reason,
        "packer_name": scan.get("packer_name"),
        "protection_level": prot,
        "packer_explanation": packer_plain_explanation(scan, is_zh),
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
            "lang": normalize_lang(lang),
        },
    }


def _build_preflight_checks(
    *,
    sample: dict[str, Any],
    file_ok: bool,
    is_apk: bool,
    is_device_mode: bool,
    selected_mode: str,
    engine: str,
    online_devices: list[dict[str, Any]],
    avail_engines: list[str],
    effective_repack: bool,
    is_zh: bool,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if file_ok:
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
    else:
        checks.append(
            {
                "id": "sample_ready",
                "category": "sample",
                "status": "block" if is_device_mode else "warn",
                "title": (
                    "原始样本文件已离线（仅保留历史分析快照）"
                    if is_zh
                    else "Original sample file missing on disk (saved snapshot only)"
                ),
                "detail": (
                    f"{sample['name']} 的原路径已不存在（可能是项目目录移动或临时上传已清理）。"
                    if is_zh
                    else f"Source file for {sample['name']} is no longer at its previous path (repo moved or temporary upload cleaned)."
                ),
                "fix_hint": (
                    "请前往「样本库与导入」重新上传该文件或从本地样本库重新挂载，即可恢复完整扫描与真机脱壳。"
                    if is_zh
                    else "Re-upload the file or re-mount it from the Local Library in Samples & Intake to run fresh scans or live unpacking."
                ),
                "fallback_mode": "offline_audit" if is_device_mode else "",
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

    return checks


def _build_stage_blueprints(
    *,
    sample: dict[str, Any],
    is_apk: bool,
    is_device_mode: bool,
    effective_repack: bool,
    effective_deep: bool,
    generate_report: bool,
    engine: str,
    timeout_s: int,
    online_devices: list[dict[str, Any]],
    avail_engines: list[str],
    is_zh: bool,
) -> list[dict[str, Any]]:
    if not is_device_mode:
        has_dex = sample.get("dex_count", 0) > 0
        will_repack = bool(effective_repack and is_apk and has_dex)
        return [
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

    dev_status = "pass" if (online_devices and avail_engines and is_apk) else "block"
    return [
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


def launch_deep_pipeline_job(
    ctx: StudioContext,
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
    is_zh = normalize_lang(lang) == "zh"
    plan = build_pipeline_plan(
        ctx,
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

    job_id = ctx.job_mgr.create_job(
        job_type="pipeline",
        apk=sample["name"],
        apk_hash=sample["id"],
        sample_id=sample["id"],
        phase="intake",
        extra={"mode": mode, "lang": normalize_lang(lang), "stages": initial_stages},
    )
    with ctx.lock:
        sample["last_job_id"] = job_id

    output_dir = sample["work_dir"] / f"pipeline_{mode}_{job_id}"
    output_dir.mkdir(parents=True, exist_ok=True)

    if mode in {"offline_audit", "repair_repack"}:
        ctx.job_mgr.submit(
            lambda: _run_offline_worker(
                ctx,
                job_id=job_id,
                sample=sample,
                output_dir=output_dir,
                repack=repack,
                generate_report=generate_report,
                lang=lang,
                is_zh=is_zh,
            )
        )
    else:
        ctx.job_mgr.submit(
            lambda: _run_device_worker(
                ctx,
                job_id=job_id,
                sample=sample,
                output_dir=output_dir,
                mode=mode,
                engine=engine,
                timeout_s=timeout_s,
                deep=deep,
                anti_detect=anti_detect,
                repack=repack,
                generate_report=generate_report,
                lang=lang,
                is_zh=is_zh,
            )
        )
    return job_id


def _run_offline_worker(
    ctx: StudioContext,
    *,
    job_id: str,
    sample: dict[str, Any],
    output_dir: Path,
    repack: bool,
    generate_report: bool,
    lang: str,
    is_zh: bool,
) -> None:
    job_mgr = ctx.job_mgr
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
        dex_entries = ctx.list_sample_dex_entries(sample)
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
            if not ctx.sample_file_exists(sample):
                cached_scan = sample.get("scan_result") or {}
                cached_insp = sample.get("inspect_result") or {}
                if cached_scan or cached_insp:
                    job_mgr.set_phase_data(job_id, "scan", cached_scan)
                    job_mgr.update_stage(
                        job_id,
                        "scan_inspect",
                        status="done",
                        duration_ms=int((time.monotonic() - st0) * 1000),
                        summary=(
                            "原 APK 已离线，已复用工作区缓存的扫描与剖析快照"
                            if is_zh
                            else "Source APK missing on disk; reused saved workspace scan & inspect snapshot"
                        ),
                        next_hint=(
                            "如需重新扫描或提取 DEX，请在「样本库与导入」重新挂载或上传原 APK。"
                            if is_zh
                            else "Re-mount or re-upload the original APK in Samples & Intake for a fresh scan."
                        ),
                        log_message=(
                            "原 APK 文件已不在原路径，已自动复用工作区历史快照。"
                            if is_zh
                            else "Source APK unavailable on disk; reused persisted workspace snapshot."
                        ),
                        log_level="warn",
                    )
                else:
                    msg = (
                        "原始 APK 文件已不在原路径（可能目录已移动或临时上传已清理），请重新上传或从本地库挂载后再运行。"
                        if is_zh
                        else "Source APK file is missing on disk (directory moved or temp upload cleaned). Please re-upload or re-mount it."
                    )
                    job_mgr.update_stage(
                        job_id,
                        "scan_inspect",
                        status="failed",
                        duration_ms=int((time.monotonic() - st0) * 1000),
                        summary=msg,
                        log_message=msg,
                        log_level="error",
                    )
                    job_mgr.finish(job_id, status="failed", error=msg, duration_ms=int((time.monotonic() - t0) * 1000))
                    return
            else:
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
                scan_dict = scan_apk_rich(sample["path"])
                with ctx.lock:
                    sample["scan_result"] = scan_dict
                insp_dict = ctx.ensure_apk_inspect(sample, force=False)
                job_mgr.set_phase_data(job_id, "scan", scan_dict)
                job_mgr.set_phase_data(
                    job_id,
                    "inspect",
                    {
                        "risk_score": insp_dict.get("risk_score", 0),
                        "risk_grade": insp_dict.get("risk_grade", "A"),
                        "native_libs": len(insp_dict.get("native_libs") or []),
                        "findings": len(insp_dict.get("findings") or []),
                    },
                )
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
                summary=("当前样本为 DEX/目录，自动跳过 APK Manifest 扫描" if is_zh else "Skipped APK manifest scan for raw DEX sample"),
                log_message=("跳过 APK 扫描（纯 DEX 样本）。" if is_zh else "Skipped APK scan for raw DEX sample."),
            )
        if job_mgr.is_cancelled(job_id):
            return

        # ── Stage 3: Extract DEX ──
        st0 = time.monotonic()
        job_mgr.set_phase(job_id, "extract_dex", 40)
        src_dex_dir = output_dir / "extracted_dex"
        extracted: list[Path] = []
        if dex_entries and ctx.sample_file_exists(sample):
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
            extracted = ctx.extract_sample_dex_files(sample, src_dex_dir)
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
                log_message="跳过 DEX 提取：样本无顶层 DEX 或原文件已离线。" if is_zh else "Skipped DEX extraction: no top-level DEX files or source offline.",
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
                diff, out_p = repair_dex_with_diff(dp, repaired_dir)
                diffs.append(diff)
                if diff.get("after"):
                    after_verifies.append(diff["after"])
                if out_p and out_p.exists():
                    repaired_files.append(out_p)

            zip_path = output_dir / f"{Path(sample['name']).stem}_repaired_dex.zip"
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for rf in repaired_files:
                    zf.write(rf, arcname=rf.name)
            rep_art = ctx.register_artifact(zip_path, zip_path.name, "repaired_dex_bundle", "application/zip")
            job_mgr.add_artifact(job_id, rep_art)

            with ctx.lock:
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
            merged_vmp = aggregate_vmp_analysis(
                ((dp.name, dp.read_bytes()) for dp in target_dexs),
                total_dex=len(repaired_files),
            )
            xref_summary = analyze_xref_dex_bytes(repaired_files[0].read_bytes(), limit=100)
            xref_summary["dex_name"] = repaired_files[0].name
            with ctx.lock:
                sample["vmp_result"] = merged_vmp
                sample["xref_result"] = xref_summary

            ioc_urls = len((xref_summary.get("iocs") or {}).get("urls") or [])
            refl_cnt = int((xref_summary.get("counts") or {}).get("reflection_calls") or 0)
            vmp_metrics = {
                "total_methods": merged_vmp["total_methods"],
                "vmp_stubs": merged_vmp["vmp_count"],
                "nop_methods": merged_vmp["nop_count"],
                "reflection_calls": refl_cnt,
                "ioc_urls": ioc_urls,
                "verdict": merged_vmp["verdict"],
            }
            job_mgr.set_phase_data(job_id, "vmp_xref", vmp_metrics)
            job_mgr.update_stage(
                job_id,
                "vmp_xref",
                status="done",
                duration_ms=int((time.monotonic() - st0) * 1000),
                summary=(
                    f"分析 {merged_vmp['total_methods']} 个方法 · VMP 桩 {merged_vmp['vmp_count']} · NOP {merged_vmp['nop_count']} · 反射 {refl_cnt} · URL IOC {ioc_urls}"
                    if is_zh
                    else f"{merged_vmp['total_methods']} methods · {merged_vmp['vmp_count']} VMP stubs · {merged_vmp['nop_count']} NOP · {refl_cnt} reflection · {ioc_urls} URLs"
                ),
                metrics=vmp_metrics,
                next_hint=(
                    "进入「VMP 与原生分析」查看调度器聚类、ELF 缓解与所有提取出的 URL/IP。"
                    if is_zh
                    else "Open VMP & Native Studio to explore dispatcher clusters, ELF mitigations, and extracted IOCs."
                ),
                log_message=(
                    f"VMP & Xref 完成：判定={merged_vmp['verdict']}，VMP 桩={merged_vmp['vmp_count']}，URL IOC={ioc_urls}。"
                    if is_zh
                    else f"VMP & Xref done: verdict={merged_vmp['verdict']}, vmp_stubs={merged_vmp['vmp_count']}, urls={ioc_urls}."
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
        do_repack = bool(repack and sample["kind"] == "apk" and ctx.sample_file_exists(sample) and repaired_files)
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
                rr = Repacker().repack(sample["path"], repaired_dir, repack_out, strip_signatures=True)
                if rr.success and rr.output_path:
                    r_art = ctx.register_artifact(
                        rr.output_path,
                        rr.output_path.name,
                        "repacked_apk",
                        "application/vnd.android.package-archive",
                    )
                    stage_arts.append(r_art)
                    job_mgr.add_artifact(job_id, r_art)
                    repacked_name = r_art["name"]
                    with ctx.lock:
                        sample["artifacts"] = [r_art, *sample.get("artifacts", [])][:20]

            report_name = ""
            if generate_report:
                html_body, _, ext = render_commercial_report(sample=sample, fmt="html", lang=lang)
                rep_file = output_dir / f"{Path(sample['name']).stem}_audit_{normalize_lang(lang)}.{ext}"
                rep_file.write_text(html_body, encoding="utf-8")
                h_art = ctx.register_artifact(rep_file, rep_file.name, "audit_report_html", "text/html; charset=utf-8")
                stage_arts.append(h_art)
                job_mgr.add_artifact(job_id, h_art)
                report_name = h_art["name"]
                with ctx.lock:
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
        logger.exception("Offline pipeline job %s failed", job_id)
        job_mgr.log(job_id, f"Pipeline error: {exc}", level="error")
        job_mgr.finish(job_id, status="failed", error=str(exc), duration_ms=int((time.monotonic() - t0) * 1000))


def _run_device_worker(
    ctx: StudioContext,
    *,
    job_id: str,
    sample: dict[str, Any],
    output_dir: Path,
    mode: str,
    engine: str,
    timeout_s: int,
    deep: bool,
    anti_detect: bool,
    repack: bool,
    generate_report: bool,
    lang: str,
    is_zh: bool,
) -> None:
    job_mgr = ctx.job_mgr
    t0 = time.monotonic()
    try:
        from unpack.core.dedup import dedup_dex_files
        from unpack.core.dispatcher import Dispatcher
        from unpack.core.reporter import Reporter
        from unpack.core.scanner import PackerScanner

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
        if not ctx.sample_file_exists(sample):
            msg = (
                f"样本 {sample['name']} 的原始 APK 文件已不在原路径（可能目录已移动或临时上传已清理），请前往「样本库与导入」重新上传或从本地库重新挂载后再运行真机脱壳。"
                if is_zh
                else f"Original APK file for {sample['name']} is no longer on disk (directory moved or temp upload cleaned). Please re-upload or re-mount it from Local Library before running live device unpacking."
            )
            job_mgr.update_stage(
                job_id,
                "intake",
                status="failed",
                duration_ms=int((time.monotonic() - st0) * 1000),
                summary=msg,
                next_hint=(
                    "前往「样本库与导入」重新挂载或上传 APK，或在当前页面查看历史分析快照。"
                    if is_zh
                    else "Re-mount or re-upload the APK in Samples & Intake, or review the saved snapshot."
                ),
                log_message=msg,
                log_level="error",
            )
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
        scan_dict = scan_result.to_detailed_dict()
        with ctx.lock:
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
        dispatcher = Dispatcher(
            quiet=True,
            on_event=lambda lvl, msg: job_mgr.log(
                job_id,
                msg,
                level="warn" if lvl == "warn" else "info",
                phase="dynamic_dump",
            ),
        )
        dump_result = dispatcher.dispatch(
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
            diff, _ = repair_dex_with_diff(dp, repaired_out)
            diffs.append(diff)
        zip_path = output_dir / f"{Path(sample['name']).stem}_dumped_repaired.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rf in sorted(repaired_out.glob("*.dex")):
                zf.write(rf, arcname=rf.name)
        art = ctx.register_artifact(zip_path, zip_path.name, "pipeline_dex_bundle", "application/zip")
        job_mgr.add_artifact(job_id, art)
        rep_obj = Reporter().evaluate(repaired_out, scan_result)
        with ctx.lock:
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
        if repack:
            from unpack.repack.repacker import Repacker

            rr = Repacker().repack(apk_path, repaired_out, output_dir / "repacked", strip_signatures=True)
            if rr.success and rr.output_path:
                r_art = ctx.register_artifact(
                    rr.output_path,
                    rr.output_path.name,
                    "repacked_apk",
                    "application/vnd.android.package-archive",
                )
                stage_arts.append(r_art)
                job_mgr.add_artifact(job_id, r_art)
        if generate_report:
            html_body, _, ext = render_commercial_report(sample=sample, fmt="html", lang=lang)
            rep_file = output_dir / f"{Path(sample['name']).stem}_audit_{normalize_lang(lang)}.{ext}"
            rep_file.write_text(html_body, encoding="utf-8")
            h_art = ctx.register_artifact(rep_file, rep_file.name, "audit_report_html", "text/html; charset=utf-8")
            stage_arts.append(h_art)
            job_mgr.add_artifact(job_id, h_art)
        job_mgr.update_stage(
            job_id,
            "repack_report",
            status="done",
            duration_ms=int((time.monotonic() - st0) * 1000),
            summary=f"{len(stage_arts)} deliverable(s)",
            metrics={"artifact_count": len(stage_arts)},
            artifacts=stage_arts,
        )
        job_mgr.finish(job_id, status="done", duration_ms=int((time.monotonic() - t0) * 1000))
    except Exception as exc:
        logger.exception("Device pipeline job %s failed", job_id)
        job_mgr.log(job_id, f"Pipeline error: {exc}", level="error")
        job_mgr.finish(job_id, status="failed", error=str(exc), duration_ms=int((time.monotonic() - t0) * 1000))


def launch_legacy_pipeline_job(
    ctx: StudioContext,
    *,
    sample: dict[str, Any],
    engine: str,
    timeout_s: int,
    deep: bool,
    anti_detect: bool,
    start_from: str,
) -> str:
    job_id = ctx.job_mgr.create_job(
        job_type="pipeline",
        apk=sample["name"],
        apk_hash=sample["id"],
        sample_id=sample["id"],
        phase="scanning" if start_from in {"scan", "scan_only"} else start_from,
    )
    with ctx.lock:
        sample["last_job_id"] = job_id

    output_dir = sample["work_dir"] / f"pipeline_{job_id}"
    output_dir.mkdir(parents=True, exist_ok=True)

    def _worker() -> None:
        job_mgr = ctx.job_mgr
        t0 = time.monotonic()
        try:
            from unpack.core.dedup import dedup_dex_files
            from unpack.core.dispatcher import Dispatcher
            from unpack.core.reporter import Reporter
            from unpack.core.scanner import PackerScanner, ProtectionLevel
            from unpack.repair.dex_repair import DexRepairPipeline

            if not ctx.sample_file_exists(sample):
                msg = f"Source file for '{sample['name']}' is no longer on disk; please re-upload or re-mount it."
                job_mgr.log(job_id, msg, level="error", phase="intake")
                job_mgr.finish(job_id, status="failed", error=msg, duration_ms=int((time.monotonic() - t0) * 1000))
                return

            apk_path: Path = sample["path"]
            scanner = PackerScanner()
            if start_from in {"scan", "scan_only"} or sample.get("scan_result") is None:
                if job_mgr.is_cancelled(job_id):
                    return
                job_mgr.set_phase(job_id, "scanning", 15)
                job_mgr.log(job_id, f"Scanning {sample['name']} with PackerScanner...", phase="scanning")
                scan_result = scanner.scan(apk_path, verbose=True)
                scan_dict = scan_result.to_detailed_dict()
                with ctx.lock:
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
                scan_result = scanner.scan(apk_path)

            if start_from == "scan_only":
                job_mgr.finish(job_id, status="done", duration_ms=int((time.monotonic() - t0) * 1000))
                return

            if start_from == "repairing":
                job_mgr.log(job_id, "Skipping dump stage (start_from=repairing); loading DEX set...", phase="repairing")
                unique = ctx.extract_sample_dex_files(sample, output_dir)
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
                dump_result = Dispatcher(quiet=True).dispatch(
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
                dump_data: dict[str, Any] = {
                    "dex_count": len(dump_result.dex_files),
                    "unique_dex_count": len(unique),
                    "so_count": len(dump_result.so_files),
                    "duration_ms": dump_result.duration_ms,
                    "engine": dump_result.engine.value,
                }
                if removed > 0:
                    dump_data["duplicates_removed"] = removed
                job_mgr.set_phase_data(job_id, "dump", dump_data)

                if deep and scan_result.protection_level in (
                    ProtectionLevel.FUNCTION_EXTRACTION,
                    ProtectionLevel.VMP,
                ):
                    if job_mgr.is_cancelled(job_id):
                        return
                    job_mgr.set_phase(job_id, "active_invoke", 55)
                    try:
                        from unpack.engines.active_invoke import ActiveInvoker
                        from unpack.repair.codeitem_merger import CodeItemMerger
                        from unpack.utils.apk import get_package_name

                        pkg = get_package_name(apk_path)
                        if pkg:
                            inv_result = ActiveInvoker(
                                wait_seconds=timeout_s if timeout_s > 0 else 15,
                                anti_detect=anti_detect,
                            ).invoke(pkg, output_dir)
                            if inv_result.code_items:
                                merger = CodeItemMerger()
                                total_merged = sum(merger.merge(dex, inv_result.code_items).methods_merged for dex in unique)
                                job_mgr.set_phase_data(
                                    job_id,
                                    "active_invoke",
                                    {"code_items_captured": len(inv_result.code_items), "methods_merged": total_merged},
                                )
                    except ImportError:
                        job_mgr.log(job_id, "Active invoke skipped (Frida unavailable).", level="warn", phase="active_invoke")

            if job_mgr.is_cancelled(job_id):
                return
            job_mgr.set_phase(job_id, "repairing", 75)
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

            zip_path = output_dir / f"{Path(sample['name']).stem}_pipeline_dex.zip"
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for dp in unique:
                    zf.write(dp, arcname=dp.name)
            art = ctx.register_artifact(zip_path, zip_path.name, "pipeline_dex_bundle", "application/zip")
            job_mgr.add_artifact(job_id, art)

            if job_mgr.is_cancelled(job_id):
                return
            job_mgr.set_phase(job_id, "verifying", 90)
            rep_dict = Reporter().evaluate(output_dir, scan_result).to_dict()
            with ctx.lock:
                sample["quality_report"] = rep_dict
                sample["repaired_dir"] = output_dir
            job_mgr.set_phase_data(job_id, "report", rep_dict)
            job_mgr.finish(job_id, status="done", duration_ms=int((time.monotonic() - t0) * 1000))
        except Exception as exc:
            logger.exception("Legacy pipeline job %s failed", job_id)
            job_mgr.log(job_id, f"Pipeline error: {exc}", level="error")
            job_mgr.finish(job_id, status="failed", error=str(exc), duration_ms=int((time.monotonic() - t0) * 1000))

    ctx.job_mgr.submit(_worker)
    return job_id
