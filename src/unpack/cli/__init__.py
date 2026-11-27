"""UNPACK CLI package facade.

Assembles the Typer root application, global flags (``--lang``, ``--log-level``,
``--version``, ``--no-color``, ``--quiet``), bilingual root help, and all
command modules while re-exporting public contracts for 100% backward
compatibility.
"""

from __future__ import annotations

from typing import Annotated, Optional

from unpack.utils.apk import silence_androguard_logs

# Suppress androguard's loguru noise before any subcommand import can trigger it.
silence_androguard_logs()

import typer  # noqa: E402
from rich.table import Table  # noqa: E402

from unpack import __version__  # noqa: E402
from unpack.cli import common  # noqa: E402
from unpack.cli.commands.ai import ai_app  # noqa: E402
from unpack.cli.commands.analysis import vmp, xref  # noqa: E402
from unpack.cli.commands.dump import dump, rescan  # noqa: E402
from unpack.cli.commands.pipeline import _render_offline_pipeline, pipeline  # noqa: E402
from unpack.cli.commands.repair import export, reassemble, repack, repair, verify  # noqa: E402
from unpack.cli.commands.report import report  # noqa: E402
from unpack.cli.commands.scan import analyze, doctor, inspect, scan  # noqa: E402
from unpack.cli.commands.studio import web  # noqa: E402
from unpack.cli.commands.wizard import guide, wizard  # noqa: E402
from unpack.cli.commands.workspace import workspace_app  # noqa: E402
from unpack.cli.common import (  # noqa: E402
    CONFIDENCE_HIDE_THRESHOLD,
    CONFIDENCE_POSSIBLE_THRESHOLD,
    EXIT_DUMP_FAILED,
    EXIT_ERROR,
    EXIT_NO_DEVICE,
    EXIT_NO_PACKER,
    EXIT_NOT_FOUND,
    EXIT_OK,
    configure_consoles as _configure_consoles,
    discover_dex_paths as _discover_dex_paths,
    gate_low_confidence as _gate_low_confidence,
)
from unpack.cli.format import (  # noqa: E402
    C_DIM,
    C_INFO,
    C_LABEL,
    render_header,
    safe,
)
from unpack.core.pipeline import build_pipeline_plan, run_offline_pipeline  # noqa: E402
from unpack.i18n import get_lang, resolve_lang, set_lang, t, use_lang  # noqa: E402
from unpack.logging_config import configure_logging  # noqa: E402

# Re-export backward-compatible aliases for pipeline helpers
_run_offline_pipeline = _render_offline_pipeline


class _BilingualRootGroup(typer.core.TyperGroup):
    """Intercept root ``--help`` so ``--lang zh --help`` / ``-L zh --help`` / ``UNPACK_LANG=zh`` renders Chinese help."""

    def parse_args(self, ctx, args: list[str]) -> list[str]:
        found_lang: str | None = None
        found_no_color = False
        has_top_help = False

        idx = 0
        while idx < len(args):
            tok = args[idx]
            if tok in ("--help", "-h"):
                has_top_help = True
                idx += 1
                continue
            if tok == "--no-color":
                found_no_color = True
                idx += 1
                continue
            if tok in ("--lang", "-L"):
                if idx + 1 < len(args):
                    found_lang = args[idx + 1]
                    idx += 2
                    continue
                idx += 1
                continue
            if tok.startswith("--lang="):
                found_lang = tok.split("=", 1)[1]
                idx += 1
                continue
            if tok.startswith("-L") and len(tok) > 2:
                found_lang = tok[2:]
                idx += 1
                continue
            if tok == "--log-level":
                idx += 2 if idx + 1 < len(args) else 1
                continue
            if tok.startswith("-"):
                idx += 1
                continue
            # First positional token is a subcommand; let Typer handle subcommand `--help`.
            break

        if has_top_help and resolve_lang(found_lang) == "zh":
            _configure_consoles(no_color=found_no_color, quiet=False)
            with use_lang("zh"):
                _print_main_help()
            ctx.exit(EXIT_OK)

        return super().parse_args(ctx, args)


app = typer.Typer(
    name="unpack",
    cls=_BilingualRootGroup,
    help="Android APK unpacker & mobile security workbench: scan · inspect · dump · repair · verify · report",
    rich_markup_mode="rich",
    invoke_without_command=True,
)


def _version_callback(value: bool) -> None:
    if value:
        print(f"unpack {__version__}")
        raise typer.Exit(EXIT_OK)


def _print_main_help() -> None:
    eff = get_lang()
    common.console.print()
    render_header(
        common.console,
        "UNPACK",
        subtitle=t("cli.subtitle", eff),
        meta=f"v{__version__}",
    )

    groups: list[tuple[str, list[tuple[str, str]]]] = [
        (
            t("cli.group.onboarding", eff),
            [
                ("guide", t("cli.cmd.guide", eff)),
                ("wizard", t("cli.cmd.wizard", eff)),
                ("pipeline", t("cli.cmd.pipeline", eff)),
            ],
        ),
        (
            t("cli.group.recon", eff),
            [
                ("scan", t("cli.cmd.scan", eff)),
                ("inspect", t("cli.cmd.inspect", eff)),
                ("analyze", t("cli.cmd.analyze", eff)),
            ],
        ),
        (
            t("cli.group.unpack", eff),
            [
                ("dump", t("cli.cmd.dump", eff)),
                ("repair", t("cli.cmd.repair", eff)),
                ("verify", t("cli.cmd.verify", eff)),
                ("rescan", t("cli.cmd.rescan", eff)),
                ("reassemble", t("cli.cmd.reassemble", eff)),
                ("repack", t("cli.cmd.repack", eff)),
            ],
        ),
        (
            t("cli.group.post", eff),
            [
                ("vmp", t("cli.cmd.vmp", eff)),
                ("xref", t("cli.cmd.xref", eff)),
                ("export", t("cli.cmd.export", eff)),
            ],
        ),
        (
            t("cli.group.reporting", eff),
            [
                ("report", t("cli.cmd.report", eff)),
                ("doctor", t("cli.cmd.doctor", eff)),
                ("web", t("cli.cmd.web", eff)),
            ],
        ),
        (
            t("cli.group.ai_ws", eff),
            [
                ("ai", t("cli.cmd.ai", eff)),
                ("workspace", t("cli.cmd.workspace", eff)),
            ],
        ),
    ]

    cmd_table = Table(show_header=False, box=None, padding=(0, 2), pad_edge=False)
    cmd_table.add_column("cmd", style="cmd", min_width=12)
    cmd_table.add_column("desc")
    for idx, (group_name, items) in enumerate(groups):
        if idx > 0:
            cmd_table.add_row("", "")
        cmd_table.add_row(f"[{C_DIM}]{group_name.upper()}[/]", "")
        for name, desc in items:
            cmd_table.add_row(f"  {name}", desc)
    common.console.print(cmd_table)

    lang_flag = " --lang zh" if eff == "zh" else ""
    examples = [
        (f"unpack guide{lang_flag}", t("cli.example.guide", eff)),
        (f"unpack doctor{lang_flag}", t("cli.example.doctor", eff)),
        (f"unpack scan app.apk -v{lang_flag}", t("cli.example.scan", eff)),
        (f"unpack inspect app.apk --permissions{lang_flag}", t("cli.example.inspect", eff)),
        (f"unpack pipeline app.apk{lang_flag}", t("cli.example.pipeline", eff)),
        ("unpack dump app.apk --deep", t("cli.example.dump", eff)),
        ("unpack repair ./unpacked/ && unpack verify ./unpacked/", t("cli.example.repair", eff)),
        (f"unpack report ./unpacked/ --apk app.apk -F html -o audit.html{lang_flag}", t("cli.example.report", eff)),
        (f"unpack ai show{lang_flag}", t("cli.example.ai", eff)),
        (f"unpack workspace list{lang_flag}", t("cli.example.workspace", eff)),
        ("unpack web --port 8080", t("cli.example.web", eff)),
    ]
    common.console.print(f"\n[{C_LABEL}]{safe(t('cli.quickstart', eff))}[/]")
    for cmd, desc in examples:
        common.console.print(f"  [{C_INFO}]$[/] [cmd]{safe(cmd)}[/]  [{C_DIM}]# {safe(desc)}[/]")
    common.console.print(f"\n  [{C_DIM}]{safe(t('cli.global_flags', eff))}[/]\n")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show version and exit",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
    lang: Annotated[
        Optional[str],
        typer.Option(
            "--lang",
            "-L",
            help="Display language: en | zh | auto (default: en, or UNPACK_LANG)",
        ),
    ] = None,
    log_level: Annotated[
        Optional[str],
        typer.Option(
            "--log-level",
            help="Logging verbosity: debug | info | warning | error | critical | off (or UNPACK_LOG_LEVEL)",
        ),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable ANSI color output (also honors NO_COLOR)"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Reduce non-essential output, spinners, and hints"),
    ] = False,
) -> None:
    set_lang(lang)
    _configure_consoles(no_color=no_color, quiet=quiet)
    effective_level = log_level if log_level is not None else ("ERROR" if quiet else None)
    try:
        configure_logging(effective_level)
    except ValueError as exc:
        common.fail_error(str(exc), hint="Use --log-level debug | info | warning | error | critical | off")
    if ctx.invoked_subcommand is None:
        _print_main_help()
        raise typer.Exit()


# ── Register top-level commands & sub-command groups ─────────────────────────
app.command()(doctor)
app.command()(inspect)
app.command()(scan)
app.command()(analyze)
app.command()(dump)
app.command()(repair)
app.command()(verify)
app.command()(export)
app.command()(repack)
app.command()(rescan)
app.command()(reassemble)
app.command()(vmp)
app.command()(xref)
app.command()(report)
app.command()(pipeline)
app.command()(guide)
app.command()(wizard)
app.command()(web)
app.add_typer(ai_app, name="ai")
app.add_typer(workspace_app, name="workspace")


__all__ = [
    "CONFIDENCE_HIDE_THRESHOLD",
    "CONFIDENCE_POSSIBLE_THRESHOLD",
    "EXIT_DUMP_FAILED",
    "EXIT_ERROR",
    "EXIT_NOT_FOUND",
    "EXIT_NO_DEVICE",
    "EXIT_NO_PACKER",
    "EXIT_OK",
    "_configure_consoles",
    "_discover_dex_paths",
    "_gate_low_confidence",
    "_print_main_help",
    "_run_offline_pipeline",
    "ai_app",
    "analyze",
    "app",
    "build_pipeline_plan",
    "doctor",
    "dump",
    "export",
    "guide",
    "inspect",
    "main",
    "pipeline",
    "reassemble",
    "repack",
    "repair",
    "report",
    "rescan",
    "run_offline_pipeline",
    "scan",
    "verify",
    "vmp",
    "web",
    "wizard",
    "workspace_app",
    "xref",
]
