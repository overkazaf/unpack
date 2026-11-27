"""Interactive onboarding wizard commands: ``guide`` and ``wizard``."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Optional

import typer

from unpack import __version__
from unpack.cli import common
from unpack.cli.commands.studio import web
from unpack.cli.format import (
    C_ACCENT,
    C_DIM,
    C_INFO,
    C_LABEL,
    C_OK,
    C_WARN,
    format_bytes,
    print_inspect_apk,
    print_inspect_dex,
    print_repair_summary,
    print_scan_result,
    print_verify_summary,
    render_header,
    render_kv_card,
    render_pipeline_blueprint,
    render_table,
    render_wizard_step,
    safe,
)
from unpack.core.pipeline import build_pipeline_plan
from unpack.i18n import t
from unpack.logging_config import get_logger

logger = get_logger(__name__)

_GUIDE_SCENARIOS: tuple[str, ...] = ("audit", "dex", "repair", "pipeline", "web")


def _discover_local_samples(scenario: str) -> list[dict[str, Any]]:
    """Auto-discover local APK/DEX samples in test_apks/, e2e_test/, and workspace."""
    found: list[dict[str, Any]] = []
    seen: set[Path] = set()
    roots = [Path("test_apks"), Path("e2e_test"), Path(".")]

    want_ext = (".apk",)
    if scenario == "dex":
        want_ext = (".dex", ".apk")
    elif scenario == "repair":
        want_ext = (".dex",)

    for root in roots:
        if not root.exists():
            continue
        if scenario == "repair" and root.is_dir():
            for cand_dir in (root / "unpacked", root / "dex"):
                if cand_dir.is_dir() and list(cand_dir.glob("*.dex")):
                    res = cand_dir.resolve()
                    if res not in seen:
                        seen.add(res)
                        found.append({"path": cand_dir, "type": "DEX dir", "size": None})
        pattern_iter = sorted(root.iterdir()) if root == Path(".") else sorted(root.rglob("*"))
        for p in pattern_iter:
            if not p.is_file():
                continue
            if p.suffix.lower() not in want_ext:
                continue
            if any(part.startswith(".") for part in p.parts):
                continue
            res = p.resolve()
            if res in seen:
                continue
            seen.add(res)
            found.append(
                {
                    "path": p,
                    "type": p.suffix.lstrip(".").upper(),
                    "size": p.stat().st_size,
                }
            )
            if len(found) >= 8:
                return found
    return found


def _build_guide_plan(
    scenario: str,
    target: Path,
    *,
    lang: str,
    has_device: bool,
) -> tuple[list[dict[str, str]], list[str]]:
    """Return plain-language stages and copyable CLI commands for a wizard goal."""
    lf = " --lang zh" if lang == "zh" else ""
    if scenario == "audit":
        stages = [
            {
                "stage": t("pipe.stage.scan.title", lang),
                "purpose": t("pipe.stage.scan.desc", lang),
                "prereq": t("pipe.stage.scan.prereq", lang),
                "output": "Packer verdict + evidence chain",
            },
            {
                "stage": t("pipe.stage.inspect.title", lang),
                "purpose": t("pipe.stage.inspect.desc", lang),
                "prereq": t("pipe.stage.inspect.prereq", lang),
                "output": "Manifest, signing, permissions & ELF report",
            },
            {
                "stage": f"3. {t('pipe.stage.report.title', lang)}",
                "purpose": t("pipe.stage.report.desc", lang),
                "prereq": t("pipe.stage.report.prereq", lang),
                "output": "audit.html",
            },
        ]
        cmds = [
            f"unpack scan {target} -v{lf}",
            f"unpack inspect {target} --permissions{lf}",
            f"unpack report {target} -F html -o audit.html{lf}",
        ]
        return stages, cmds

    if scenario == "dex":
        stages = [
            {
                "stage": "1. DEX Overview & Classes" if lang == "en" else "1. DEX 概览与类目录浏览",
                "purpose": "Inspect DEX header, class/method counts & NOP health" if lang == "en" else "查看 DEX 文件头、类与方法数量以及 NOP 抽取健康度",
                "prereq": t("pipe.stage.scan.prereq", lang),
                "output": "Classes & health table",
            },
            {
                "stage": "2. Method & Dalvik Disassembly" if lang == "en" else "2. 方法列表与 Dalvik 反汇编",
                "purpose": "Drill into a target class and disassemble Dalvik instructions" if lang == "en" else "展开指定类的方法清单，并对目标方法进行 Dalvik 字节码反汇编",
                "prereq": t("pipe.stage.scan.prereq", lang),
                "output": "Instruction listing",
            },
        ]
        cmds = [
            f"unpack inspect {target} --classes{lf}",
            f"unpack inspect {target} --methods com.example.MainActivity{lf}",
            f"unpack inspect {target} --disasm com.example.MainActivity::onCreate{lf}",
        ]
        return stages, cmds

    if scenario == "repair":
        stages = [
            {
                "stage": f"1. {t('pipe.stage.repair.title', lang)}",
                "purpose": t("pipe.stage.repair.desc", lang),
                "prereq": t("pipe.stage.repair.prereq", lang),
                "output": "*_repaired.dex",
            },
            {
                "stage": f"2. {t('pipe.stage.verify.title', lang)}",
                "purpose": t("pipe.stage.verify.desc", lang),
                "prereq": t("pipe.stage.verify.prereq", lang),
                "output": "PASS / FAIL integrity table",
            },
        ]
        cmds = [
            f"unpack repair {target}{lf}",
            f"unpack verify {target}{lf}",
        ]
        return stages, cmds

    if scenario == "pipeline":
        stages = [
            {
                "stage": t("pipe.stage.scan.title", lang),
                "purpose": t("pipe.stage.scan.desc", lang),
                "prereq": t("pipe.stage.scan.prereq", lang),
                "output": "Packer & recommended flags",
            },
            {
                "stage": t("pipe.stage.dump.title", lang),
                "purpose": t("pipe.stage.dump.desc", lang, engine="auto"),
                "prereq": t("pipe.stage.dump.prereq", lang, engine="auto"),
                "output": "./unpacked/*.dex",
            },
            {
                "stage": f"3. {t('pipe.stage.repair.title', lang)} & {t('pipe.stage.verify.title', lang)}",
                "purpose": t("pipe.stage.verify.desc", lang),
                "prereq": t("pipe.stage.verify.prereq", lang),
                "output": "./unpacked/report.json",
            },
        ]
        cmds = [f"unpack dump {target} --explain{lf}"]
        if has_device:
            cmds.append(f"unpack dump {target} --deep -o ./unpacked --report-html audit.html{lf}")
        else:
            cmds.append(f"unpack pipeline {target} --mode offline -o ./unpacked --execute{lf}")
        return stages, cmds

    # web
    stages = [
        {
            "stage": "1. Launch Unpack Studio" if lang == "en" else "1. 启动 Unpack Studio 本地服务",
            "purpose": t("guide.goal.web.desc", lang),
            "prereq": "Python Flask (`pip install -e '.[web]'`)" if lang == "en" else "需安装 Flask（`pip install -e '.[web]'`）",
            "output": "http://127.0.0.1:8080",
        }
    ]
    cmds = ["unpack web --port 8080"]
    return stages, cmds


def _run_guide(
    *,
    scenario: str | None = None,
    target: Path | None = None,
    non_interactive: bool = False,
    execute: bool = False,
    no_devices: bool = False,
    lang: str | None = None,
) -> None:
    eff = common.apply_lang(lang)
    common.console.print()
    render_header(
        common.console,
        t("guide.title", eff),
        subtitle=t("guide.subtitle", eff),
        meta=f"v{__version__}",
    )

    # ── Step 1: Environment Readiness Check ──
    render_wizard_step(common.console, 1, 5, t("guide.step1.title", eff), t("guide.step1.sub", eff), lang=eff)
    with common.spinner(t("cli.spinner.doctor", eff)):
        doc = common.run_doctor_dict(check_devices=not no_devices)
    checks = doc.get("checks") or []
    passed = sum(1 for c in checks if str(c.get("status", "")).lower() == "pass")
    warned = sum(1 for c in checks if str(c.get("status", "")).lower() == "warn")
    failed = sum(1 for c in checks if str(c.get("status", "")).lower() == "fail")
    devices = doc.get("devices") or []
    rooted = sum(1 for d in devices if d.get("rooted") or d.get("root"))
    ready_engines = [str(e["name"]) for e in (doc.get("engines") or []) if e.get("available")]

    if devices:
        dev_summary = f"[{C_OK}]{safe(t('guide.env.device_ready', eff, count=len(devices), rooted=rooted, engines=', '.join(ready_engines) or 'none'))}[/]"
    else:
        dev_summary = f"[{C_WARN}]{safe(t('guide.env.device_none', eff))}[/]"

    render_kv_card(
        common.console,
        t("fmt.title.doctor", eff),
        [
            (t("guide.env.offline_label", eff), f"[{C_OK}]{safe(t('guide.env.offline_ready', eff))}[/]"),
            (t("guide.env.device_label", eff), dev_summary),
            (t("guide.env.checks_summary", eff), t("guide.env.checks_detail", eff, passed=passed, warn=warned, fail=failed)),
        ],
        border_style=C_INFO,
        title_style=f"bold {C_INFO}",
    )

    # ── Step 2: Goal Picker ──
    render_wizard_step(common.console, 2, 5, t("guide.step2.title", eff), t("guide.step2.sub", eff), lang=eff)
    goal_rows = []
    for idx, key in enumerate(_GUIDE_SCENARIOS, start=1):
        goal_rows.append(
            [
                f"[{C_INFO}]{idx}[/]",
                f"[{C_LABEL}]{safe(t(f'guide.goal.{key}.name', eff))}[/] [{C_DIM}]({key})[/]",
                f"[{C_OK if key in ('audit', 'dex', 'repair') else C_ACCENT}]{safe(t(f'guide.goal.{key}.tag', eff))}[/]",
                safe(t(f"guide.goal.{key}.desc", eff)),
            ]
        )
    render_table(
        common.console,
        [
            (t("guide.col.num", eff), {"width": 3, "justify": "right"}),
            (t("guide.col.goal", eff), {}),
            (t("guide.col.mode", eff), {"width": 18}),
            (t("guide.col.what", eff), {}),
        ],
        goal_rows,
    )

    chosen_scenario: str
    if scenario:
        norm_s = scenario.strip().lower()
        if norm_s.isdigit() and 1 <= int(norm_s) <= len(_GUIDE_SCENARIOS):
            chosen_scenario = _GUIDE_SCENARIOS[int(norm_s) - 1]
        elif norm_s in _GUIDE_SCENARIOS:
            chosen_scenario = norm_s
        else:
            common.fail_error(
                f"Unknown scenario: {scenario}",
                hint=f"Valid scenarios: {', '.join(_GUIDE_SCENARIOS)}",
            )
    elif non_interactive:
        chosen_scenario = "audit"
    else:
        raw_choice = typer.prompt(t("guide.prompt.goal", eff), default="1").strip().lower()
        if raw_choice.isdigit() and 1 <= int(raw_choice) <= len(_GUIDE_SCENARIOS):
            chosen_scenario = _GUIDE_SCENARIOS[int(raw_choice) - 1]
        elif raw_choice in _GUIDE_SCENARIOS:
            chosen_scenario = raw_choice
        else:
            chosen_scenario = "audit"

    # ── Step 3: Target Selection ──
    render_wizard_step(common.console, 3, 5, t("guide.step3.title", eff), t("guide.step3.sub", eff), lang=eff)
    chosen_target: Path
    if chosen_scenario == "web":
        chosen_target = Path("http://127.0.0.1:8080")
    else:
        discovered = _discover_local_samples(chosen_scenario)
        if discovered:
            s_rows = [
                [
                    f"[{C_INFO}]{idx}[/]",
                    f"[path]{safe(item['path'])}[/]",
                    safe(item["type"]),
                    format_bytes(item["size"]),
                ]
                for idx, item in enumerate(discovered, start=1)
            ]
            render_table(
                common.console,
                [
                    (t("guide.col.num", eff), {"width": 3, "justify": "right"}),
                    (t("guide.col.sample", eff), {}),
                    (t("guide.col.type", eff), {"width": 8}),
                    (t("guide.col.size", eff), {"justify": "right"}),
                ],
                s_rows,
                title=t("guide.discovered_title", eff, count=len(discovered)),
            )
        else:
            common.console.print(f"  [{C_DIM}]{safe(t('guide.no_local_targets', eff))}[/]")

        default_placeholder = Path("./unpacked") if chosen_scenario == "repair" else Path("sample.apk")
        if target is not None:
            chosen_target = target
        elif non_interactive:
            chosen_target = discovered[0]["path"] if discovered else default_placeholder
        else:
            default_in = "1" if discovered else str(default_placeholder)
            raw_t = typer.prompt(t("guide.prompt.target", eff), default=default_in).strip()
            if raw_t.isdigit() and 1 <= int(raw_t) <= len(discovered):
                chosen_target = discovered[int(raw_t) - 1]["path"]
            else:
                chosen_target = Path(raw_t)

        common.console.print(f"  [{C_OK}]▸[/] {safe(t('guide.selected_target', eff, target=chosen_target))}")
        if chosen_target.exists() and chosen_target.is_file() and chosen_target.suffix.lower() == ".apk":
            try:
                from unpack.core.scanner import PackerScanner

                preview = PackerScanner().scan(chosen_target, verbose=False)
                if preview.packer_name:
                    common.console.print(
                        f"  [{C_INFO}]ℹ[/] {safe(t('guide.preview_packer', eff, packer=preview.packer_name, level=preview.protection_level.value, conf=preview.confidence))}"
                    )
                else:
                    common.console.print(f"  [{C_DIM}]ℹ {safe(t('guide.preview_clean', eff))}[/]")
            except Exception as exc:
                logger.debug("Quick scan preview failed for %s: %s", chosen_target, exc)

    # ── Step 4: Plain-Language Execution Plan Preview ──
    render_wizard_step(common.console, 4, 5, t("guide.step4.title", eff), t("guide.step4.sub", eff), lang=eff)
    plan_stages, plan_cmds = _build_guide_plan(
        chosen_scenario,
        chosen_target,
        lang=eff,
        has_device=bool(devices),
    )
    goal_name = t(f"guide.goal.{chosen_scenario}.name", eff)
    render_table(
        common.console,
        [
            (t("guide.col.stage", eff), {}),
            (t("guide.col.purpose", eff), {}),
            (t("guide.col.prereq", eff), {}),
            (t("guide.col.output", eff), {}),
        ],
        [
            [
                f"[{C_LABEL}]{safe(s['stage'])}[/]",
                safe(s["purpose"]),
                f"[{C_DIM}]{safe(s['prereq'])}[/]",
                f"[{C_INFO}]{safe(s['output'])}[/]",
            ]
            for s in plan_stages
        ],
        title=t("guide.plan_title", eff, goal=goal_name),
    )

    common.console.print(f"\n[{C_LABEL}]{safe(t('guide.commands_title', eff))}[/]")
    for cmd in plan_cmds:
        common.console.print(f"  [{C_INFO}]$[/] [cmd]{safe(cmd)}[/]")

    # ── Step 5: Optional Immediate Execution ──
    render_wizard_step(common.console, 5, 5, t("guide.step5.title", eff), t("guide.step5.sub", eff), lang=eff)
    should_run = execute
    if not non_interactive and not execute:
        ans = typer.prompt(t("guide.prompt.execute", eff), default="n").strip().lower()
        should_run = ans in ("y", "yes", "是")

    if not should_run:
        note = t("guide.non_interactive_note", eff) if non_interactive else t("guide.exec_cancelled", eff)
        common.console.print(f"  [{C_DIM}]{safe(note)}[/]")
        return

    if chosen_scenario != "web" and not chosen_target.exists():
        common.console.print(f"  [{C_WARN}]![/] {safe(t('guide.exec_skipped_missing', eff, target=chosen_target))}")
        return

    common.console.print(f"  [{C_INFO}]▸[/] {safe(t('guide.exec_starting', eff))}")
    if chosen_scenario == "audit":
        from unpack.core.scanner import PackerScanner

        res = PackerScanner().scan(chosen_target, verbose=True)
        print_scan_result(common.console, res, chosen_target, lang=eff)
        data = common.inspect_apk_dict(chosen_target)
        print_inspect_apk(common.console, data, lang=eff)
    elif chosen_scenario == "dex":
        if chosen_target.suffix.lower() in (".dex", ".cdex"):
            data = common.inspect_dex_dict(chosen_target, show_classes=True)
            print_inspect_dex(common.console, data.get("overview") or {}, classes=data.get("classes"), lang=eff)
        else:
            data = common.inspect_apk_dict(chosen_target)
            print_inspect_apk(common.console, data, lang=eff)
    elif chosen_scenario == "repair":
        dex_paths = common.discover_dex_paths(chosen_target)
        if not dex_paths:
            common.fail_error(t("cli.no_dex_found", eff))
        from unpack.repair.dex_repair import DexRepairPipeline
        from unpack.repair.verifier import DexVerifier

        rp = DexRepairPipeline()
        rep_items = []
        for p in dex_paths:
            rr = rp.repair(p)
            rep_items.append(
                {
                    "file": p.name,
                    "success": rr.success,
                    "actions": rr.actions,
                    "nop_methods": rr.nop_method_count,
                }
            )
        print_repair_summary(common.console, rep_items, lang=eff)
        ver = DexVerifier()
        ver_items = [
            {"file": p.name, "valid": (vr := ver.verify(p)).valid, "issues": vr.issues, "stats": vr.stats}
            for p in dex_paths
        ]
        print_verify_summary(common.console, ver_items, lang=eff)
    elif chosen_scenario == "pipeline":
        plan = build_pipeline_plan(
            chosen_target,
            mode="auto",
            check_devices=not no_devices,
            lang=eff,
        )
        render_pipeline_blueprint(common.console, plan, lang=eff)
    elif chosen_scenario == "web":
        web(port=8080, host="127.0.0.1")

    common.console.print(f"  [{C_OK}]✓[/] {safe(t('guide.exec_done', eff))}")


def guide(
    scenario: Annotated[
        Optional[str],
        typer.Option("--scenario", "-s", help="Goal preset: audit | dex | repair | pipeline | web"),
    ] = None,
    target: Annotated[
        Optional[Path],
        typer.Option("--target", "-t", help="Target APK, DEX, or directory path"),
    ] = None,
    non_interactive: Annotated[
        bool,
        typer.Option("--non-interactive", "-y", help="Run without interactive prompts (ideal for scripts & CI)"),
    ] = False,
    execute: Annotated[
        bool,
        typer.Option("--execute", "-x", help="Execute the generated workflow immediately"),
    ] = False,
    no_devices: Annotated[
        bool,
        typer.Option("--no-devices", help="Skip live ADB device probing during environment check"),
    ] = False,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """Interactive onboarding wizard: check environment, pick a goal, preview & run."""
    _run_guide(
        scenario=scenario,
        target=target,
        non_interactive=non_interactive,
        execute=execute,
        no_devices=no_devices,
        lang=lang,
    )


def wizard(
    scenario: Annotated[
        Optional[str],
        typer.Option("--scenario", "-s", help="Goal preset: audit | dex | repair | pipeline | web"),
    ] = None,
    target: Annotated[
        Optional[Path],
        typer.Option("--target", "-t", help="Target APK, DEX, or directory path"),
    ] = None,
    non_interactive: Annotated[
        bool,
        typer.Option("--non-interactive", "-y", help="Run without interactive prompts (ideal for scripts & CI)"),
    ] = False,
    execute: Annotated[
        bool,
        typer.Option("--execute", "-x", help="Execute the generated workflow immediately"),
    ] = False,
    no_devices: Annotated[
        bool,
        typer.Option("--no-devices", help="Skip live ADB device probing during environment check"),
    ] = False,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """Alias for `guide` — interactive step-by-step onboarding wizard."""
    _run_guide(
        scenario=scenario,
        target=target,
        non_interactive=non_interactive,
        execute=execute,
        no_devices=no_devices,
        lang=lang,
    )
