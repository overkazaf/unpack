"""AI provider configuration & reverse-engineering analysis command group: ``unpack ai``."""

from __future__ import annotations

import json
import tempfile
import zipfile
from pathlib import Path
from typing import Annotated, Any, Optional

import typer

from unpack.cli import common
from unpack.cli.format import (
    C_DIM,
    C_OK,
    print_ai_analysis,
    print_ai_config,
    print_ai_test_result,
    render_error,
    safe,
)
from unpack.i18n import t
from unpack.utils.fs import file_sha256

ai_app = typer.Typer(
    name="ai",
    help="Configure multi-provider AI models, test connectivity & run AI reverse-engineering analysis",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


@ai_app.command("show")
def ai_show(
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output public AI config & presets as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """Display current AI provider configuration (API key masked) and supported presets."""
    from unpack.core.ai_engine import AIConfigStore, list_provider_presets

    eff = common.apply_lang(lang)
    pub = AIConfigStore().load().to_public_dict()
    presets = list_provider_presets()
    payload = {"config": pub, "presets": presets}

    if output_json is not None and str(output_json) == "-":
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    print_ai_config(common.console, pub, presets=presets, lang=eff)
    if not pub.get("configured") and not common.is_quiet():
        common.console.print(f"\n  [{C_DIM}]{safe(t('ai.config_hint', eff))}[/]")
    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@ai_app.command("config")
def ai_config(
    provider: Annotated[
        Optional[str],
        typer.Option("--provider", "-p", help="Provider: openai | anthropic | gemini | deepseek | qwen | ollama | custom"),
    ] = None,
    model: Annotated[
        Optional[str],
        typer.Option("--model", "-m", help="Model name (e.g. gpt-4o-mini, deepseek-chat, qwen-plus)"),
    ] = None,
    base_url: Annotated[
        Optional[str],
        typer.Option("--base-url", help="Custom API base URL"),
    ] = None,
    api_key: Annotated[
        Optional[str],
        typer.Option("--api-key", "-k", help="API key (stored with 0600 permissions, never echoed raw)"),
    ] = None,
    enable: Annotated[
        Optional[bool],
        typer.Option("--enable/--disable", help="Enable or disable AI features"),
    ] = None,
    clear_key: Annotated[
        bool,
        typer.Option("--clear-key", help="Clear the stored API key"),
    ] = False,
    temperature: Annotated[
        Optional[float],
        typer.Option("--temperature", help="Sampling temperature (0.0 - 2.0)"),
    ] = None,
    timeout: Annotated[
        Optional[float],
        typer.Option("--timeout", help="HTTP timeout in seconds (3 - 300)"),
    ] = None,
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output updated public config as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """Save AI provider configuration securely (API key is masked in all output)."""
    from unpack.core.ai_engine import AIConfigStore

    eff = common.apply_lang(lang)
    payload: dict[str, Any] = {}
    if provider is not None:
        payload["provider"] = provider
    if model is not None:
        payload["model"] = model
    if base_url is not None:
        payload["base_url"] = base_url
    if api_key is not None:
        payload["api_key"] = api_key
    if enable is not None:
        payload["enabled"] = enable
    if temperature is not None:
        payload["temperature"] = temperature
    if timeout is not None:
        payload["timeout_seconds"] = timeout

    updated = AIConfigStore().update(payload, clear_api_key=clear_key)
    pub = updated.to_public_dict()

    if output_json is not None and str(output_json) == "-":
        print(json.dumps(pub, indent=2, ensure_ascii=False))
        return

    print_ai_config(common.console, pub, lang=eff)
    common.console.print(f"  [{C_OK}]✓[/] {safe(t('ai.config_saved', eff))}")
    if output_json:
        output_json.write_text(json.dumps(pub, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@ai_app.command("test")
def ai_test(
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output connectivity test result as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """Test connectivity to the configured AI model provider."""
    from unpack.core.ai_engine import test_connection

    eff = common.apply_lang(lang)
    json_stdout = output_json is not None and str(output_json) == "-"
    with common.spinner(t("ai.spinner.test", eff), enabled=not json_stdout):
        res = test_connection(lang=eff)

    if json_stdout:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        if not res.get("ok"):
            raise typer.Exit(common.EXIT_ERROR)
        return

    print_ai_test_result(common.console, res, lang=eff)
    if output_json:
        output_json.write_text(json.dumps(res, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
    if not res.get("ok"):
        raise typer.Exit(common.EXIT_ERROR)


@ai_app.command("analyze")
def ai_analyze(
    target: Annotated[Path, typer.Argument(help="Path to APK file, DEX file, or DEX directory")],
    module: Annotated[
        str,
        typer.Option("--module", "-m", help="Analysis module: scan | security | vmp | method"),
    ] = "scan",
    method: Annotated[
        Optional[str],
        typer.Option("--method", help="Target method (ClassName::methodName) for --module method"),
    ] = None,
    save_workspace: Annotated[
        Optional[str],
        typer.Option("--save-workspace", "-w", help="Workspace ID to archive sample & AI analysis"),
    ] = None,
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output AI analysis result as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Analysis & display language: en | zh | auto"),
    ] = None,
) -> None:
    """Run domain-expert AI reverse-engineering analysis on an APK or DEX target."""
    from unpack.core.ai_engine import AIAnalyzer
    from unpack.core.errors import UnpackError

    eff = common.apply_lang(lang)
    mod_l = module.strip().lower()
    json_stdout = output_json is not None and str(output_json) == "-"

    if mod_l not in ("scan", "security", "vmp", "method"):
        common.fail_error(
            f"Unsupported AI module: {module}",
            json_stdout=json_stdout,
            hint="Use --module scan | security | vmp | method",
        )
    if not target.exists():
        common.fail_missing("Target", target, json_stdout=json_stdout)
    if mod_l == "method" and (not method or "::" not in method):
        common.fail_error(t("ai.method.required", eff), json_stdout=json_stdout)

    analyzer = AIAnalyzer()
    scan_d: dict[str, Any] | None = None
    inspect_d: dict[str, Any] | None = None
    vmp_d: dict[str, Any] | None = None
    xref_d: dict[str, Any] | None = None

    try:
        with common.spinner(
            t("ai.spinner.analyze", eff, module=mod_l, name=target.name),
            enabled=not json_stdout,
        ):
            if mod_l == "scan":
                from unpack.core.scanner import PackerScanner

                scan_d = PackerScanner().scan(target, verbose=True).to_verbose_dict()
                if target.is_file() and target.suffix.lower() == ".apk":
                    inspect_d = common.inspect_apk_dict(target)
                result = analyzer.analyze_scan(scan_d, inspect=inspect_d, lang=eff)

            elif mod_l == "security":
                inspect_d = common.inspect_apk_dict(target)
                result = analyzer.analyze_security(
                    inspect_d,
                    findings=inspect_d.get("findings") or [],
                    lang=eff,
                )

            elif mod_l == "vmp":
                from unpack.analysis.vmp import VmpDetector

                native_libs: list[dict[str, Any]] | None = None
                dex_blobs: list[tuple[str, bytes]] = []
                if target.is_file() and target.suffix.lower() == ".apk":
                    inspect_d = common.inspect_apk_dict(target)
                    native_libs = inspect_d.get("native_libs") or []
                    with zipfile.ZipFile(target, "r") as zf:
                        for info in zf.infolist():
                            if info.filename.endswith(".dex") and "/" not in info.filename:
                                dex_blobs.append((info.filename, zf.read(info.filename)))
                else:
                    for p in common.discover_dex_paths(target):
                        dex_blobs.append((p.name, p.read_bytes()))

                det = VmpDetector()
                tot = norm = nops = vmps = 0
                v_methods: list[dict[str, Any]] = []
                c_graph: list[dict[str, Any]] = []
                for fname, blob in dex_blobs:
                    vr = det.analyze_dex(blob)
                    tot += vr.total_methods
                    norm += vr.normal_count
                    nops += vr.nop_count
                    vmps += vr.vmp_count
                    v_methods.extend({**m, "dex_file": fname} for m in vr.vmp_methods)
                    c_graph.extend({**c, "dex_file": fname} for c in vr.call_graph)
                vmp_d = {
                    "dex": target.name,
                    "total_methods": tot,
                    "normal_count": norm,
                    "nop_count": nops,
                    "vmp_count": vmps,
                    "vmp_methods": v_methods,
                    "call_graph": c_graph,
                }
                result = analyzer.analyze_vmp_native(
                    vmp=vmp_d,
                    native_libs=native_libs,
                    xref=xref_d,
                    lang=eff,
                )

            else:  # method
                assert method is not None
                cls_name, _meth_name = method.split("::", 1)
                disasm_dict: dict[str, Any] | None = None
                if target.is_file() and target.suffix.lower() in (".dex", ".cdex"):
                    dex_info = common.inspect_dex_dict(target, method_target=method)
                    disasm_dict = dex_info.get("disasm")
                elif target.is_file() and target.suffix.lower() == ".apk":
                    with zipfile.ZipFile(target, "r") as zf, tempfile.TemporaryDirectory() as td:
                        for info in zf.infolist():
                            if info.filename.endswith(".dex") and "/" not in info.filename:
                                tmp_dex = Path(td) / Path(info.filename).name
                                tmp_dex.write_bytes(zf.read(info.filename))
                                dex_info = common.inspect_dex_dict(tmp_dex, method_target=method)
                                if dex_info.get("disasm"):
                                    disasm_dict = dex_info["disasm"]
                                    break
                if not disasm_dict:
                    common.fail_error(
                        t("ai.method.not_found", eff, method=method, target=target.name),
                        json_stdout=json_stdout,
                    )
                result = analyzer.analyze_method(disasm_dict, class_name=cls_name, lang=eff)
    except UnpackError as exc:
        if json_stdout:
            print(json.dumps({"error": exc.message, "hint": exc.hint}, indent=2, ensure_ascii=False))
            raise typer.Exit(common.EXIT_ERROR)
        render_error(common.console, exc.message, hint=exc.hint, lang=eff)
        raise typer.Exit(common.EXIT_ERROR)

    res_dict = result.to_dict()

    saved_ws_label: str | None = None
    if save_workspace:
        from unpack.core.workspace_store import WorkspaceStore

        store = WorkspaceStore()
        try:
            sha = ""
            size_b = 0
            if target.is_file():
                sha = file_sha256(target)
                size_b = target.stat().st_size
            kind = "apk" if target.suffix.lower() == ".apk" else "dex"
            saved_sample = store.save_sample(
                save_workspace,
                {
                    "filename": target.name,
                    "sha256": sha,
                    "kind": kind,
                    "size_bytes": size_b,
                    "source_path": str(target.resolve()),
                    "scan_result": scan_d,
                    "inspect_result": inspect_d,
                    "vmp_result": vmp_d,
                    "xref_result": xref_d,
                },
            )
            store.save_ai_analysis(save_workspace, saved_sample["sample_id"], result.module, result)
            saved_ws_label = f"{save_workspace} ({saved_sample['sample_id']})"
            res_dict["saved_workspace"] = save_workspace
            res_dict["sample_id"] = saved_sample["sample_id"]
        finally:
            store.close()

    if json_stdout:
        print(json.dumps(res_dict, indent=2, ensure_ascii=False))
        return

    print_ai_analysis(common.console, res_dict, saved_workspace=saved_ws_label, lang=eff)
    if output_json:
        output_json.write_text(json.dumps(res_dict, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
