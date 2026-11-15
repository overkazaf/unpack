# 项目状态评估与待办清单（2026-11-15）

> 本文档记录 2026-11-15 的完成度评估结论、e2e 验证缺口和优化点，作为后续实现的 backlog。
> 评估方法：全量跑 303 个单元测试、批量扫描 14 个测试 APK、对已有 e2e 产物执行离线 verify。

## 一、完成度总览

| 维度 | 状态 |
|------|------|
| 单元测试 | ✅ 303/303 全过（~50s） |
| 三份 plan（advanced-features / deep-improvements / fart-parity） | ✅ 全部模块已落地，均有对应 `test_*.py` |
| 离线流水线（scan → dump → repair → verify） | ✅ 已有产物 verify 全绿：cloudmusic_final 18/18、kugou 31/31、cloudmusic_mem3 10/10 全部 valid 且无 issue |
| 真机 e2e | ⚠️ 13 个 e2e 目录中 8 个为空；三引擎只有 memory 引擎有真机产出 |

结论：**核心功能完成度 ~100%，真机验证完成度 ~40%**。

## 二、e2e 缺口（未测完，按优先级）

当前 `adb devices` 为空，续跑需先连接 root 真机。

### P0 — 引擎级验证缺口

| 优先级 | 目标 | 说明 |
|--------|------|------|
| P0-1 | `cloudmusic_frida/`（网易易盾 v2, conf 0.741） | **Frida 引擎真机零验证**。三引擎中唯一没有任何 e2e 产物，且代码量最大（673 行，5 策略 + 反检测模块） |
| P0-2 | `cloudmusic_ebpf/` | **eBPF 引擎真机零验证**。仓库已内置 `bpftrace-linux-arm64` 但从未跑通 |
| P0-3 | `bankabc/` + `bankabc_mem/`（梆梆企业版） | 两次尝试全部失败，产物为空；且扫描置信度仅 0.222（见优化点 3） |

### P1 — 未覆盖的保护场景

| 目标 | APK | 说明 |
|------|-----|------|
| `droidcrypt` | com.nemesis.droidcrypt.apk（5.9MB，无 SO，单 dex 9.2MB） | 自定义函数抽取样本，静态扫描报 NONE —— 正是 runtime fingerprint（`core/fingerprint.py`）该兜底的场景，**该路径从未验证** |
| `tongyi` | com.aliyun.tongyi.apk（阿里聚安全 v1, conf 0.37） | 目录已建但为空 |
| `dkplugin` | dkplugin.gor.tul.apk / dkplugin.xoh.guk.apk | 插件化壳，目录已建但为空 |

### P2 — 从未开始的样本（9 个 APK 无任何 e2e 产物）

weibo（234MB）、mm（186MB）、pinduoduo、hunyuan、fnetflix、kugou.lite、droidcrypt、dkplugin×2

### 测试 APK 壳识别矩阵（2026-11-15 实测）

| APK | Packer | Ver | Level | Conf |
|-----|--------|-----|-------|------|
| com.aliyun.tongyi | 阿里聚安全 | v1 | function_extraction | 0.37 |
| com.android.bankabc | 梆梆安全 | 企业版 | function_extraction | 0.222 |
| com.kugou.android | 腾讯乐固 | - | dex_encryption | 0.074 |
| com.netease.cloudmusic | 网易易盾 | v2 | function_extraction | 0.741 |
| 其余 10 个 | NONE | - | none | 0.0 |

## 三、优化点

### 1.（bug）reporter 重复计数原始与 repaired DEX

`core/reporter.py` 把 `classes_000.dex` 和 `classes_000_repaired.dex` 作为独立文件统计：
`e2e_test/cloudmusic_final/report.json` 中 `dex_count: 36`（实际 18 个）、`total_methods: 1,861,224`（实际约 93 万 × 2），覆盖率被重复稀释。
**修复方向**：统计前按原始文件名（去掉 `_repaired` 后缀）去重，只计 repaired 版本。

### 2. 扫描器召回不足

14 个测试 APK 有 10 个报 NONE。其中 weibo（234MB）、mm（186MB）大概率有厂商自研保护；`com.nemesis.droidcrypt` 命名即 crypt 却报 none。签名库（24 家）对自定义/厂商自研壳覆盖弱。
**修复方向**：扩充签名（weibo/mm 的自研保护特征）；对 NONE 结果给出 "unknown protection, 建议 dump + fingerprint" 的引导而不是静默。

### 3. 低置信度仍报 DETECTED，与设计不符

commit 7ed7ebc 描述 "<10% hidden, <20% shown as POSSIBLE"，但实测 kugou（conf 0.074）仍直接报出"腾讯乐固"厂商标签（无 hidden/POSSIBLE 标记）。
**复查位置**：`src/unpack/cli.py` / `cli_format.py` 的置信度阈值分支。

### 4. ~3800 行核心代码无专门单测

| 模块 | 行数 | 现状 |
|------|------|------|
| engines/active_invoke.py | 780 | 无专门测试 |
| engines/frida_engine.py | 673 | 无专门测试（脚本生成、策略选择可离线 mock 测） |
| engines/ebpf_engine.py | 621 | 无专门测试 |
| engines/memory_engine.py | 517 | 仅 `_find_child_pids`/`_sliding_dex_scan` 两个函数有测试 |
| web.py | 508 | 完全无测试（Flask app 可用 test client 离线测） |
| utils/adb.py / utils/apk.py | 83 / 212 | 无专门测试 |

### 5. e2e 结果不可追溯

`.gitignore` 同时排除 `e2e_test/` 和 `test_apks/`，跑出的 report.json 也不归档，失败后无现场可查。
**修复方向**：每次 e2e 自动写 manifest（命令行 + 时间 + report.json 摘要）并提交；或把 e2e 报告目录移出 ignore。

### 6. web.py 进程态与临时目录

`_jobs`/`_cache` 为进程内 dict（重启即失）；`tempfile.mkdtemp` 创建的缓存目录无清理机制。

## 四、建议实施顺序

1. 离线可做（无需真机）：优化点 1（reporter 去重）、4（补 web.py / frida_engine 脚本生成单测）、5（e2e manifest）
2. 接真机后：P0-1 frida 引擎 → P0-2 ebpf 引擎 → P0-3 bankabc → P1 droidcrypt（fingerprint 路径）
3. 依据 e2e 结果回补：优化点 2（扫描器召回）、3（置信度显示逻辑）
