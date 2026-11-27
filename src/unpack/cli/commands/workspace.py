"""Persistent workspace storage command group: ``unpack workspace``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer

from unpack.cli import common
from unpack.cli.format import (
    C_DIM,
    C_INFO,
    C_LABEL,
    C_OK,
    print_workspace_detail,
    print_workspace_list,
    render_kv_card,
    safe,
)
from unpack.i18n import t

workspace_app = typer.Typer(
    name="workspace",
    help="Manage persistent workspaces, saved samples, pipeline runs & AI analysis history",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


@workspace_app.command("list")
def workspace_list(
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output workspace list as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """List saved workspaces with sample, pipeline run, and AI analysis counts."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = common.apply_lang(lang)
    store = WorkspaceStore()
    try:
        workspaces = store.list_workspaces()
    finally:
        store.close()

    if output_json is not None and str(output_json) == "-":
        print(json.dumps(workspaces, indent=2, ensure_ascii=False))
        return

    print_workspace_list(common.console, workspaces, lang=eff)
    if output_json:
        output_json.write_text(json.dumps(workspaces, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@workspace_app.command("show")
def workspace_show(
    ws_id: Annotated[str, typer.Argument(help="Workspace ID (e.g. default or ws_...)")],
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output full workspace snapshot as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """Show saved samples, pipeline run history, and AI analyses inside a workspace."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = common.apply_lang(lang)
    json_stdout = output_json is not None and str(output_json) == "-"
    store = WorkspaceStore()
    try:
        ws = store.get_workspace(ws_id)
        if ws is None:
            common.fail_error(
                t("ws.not_found", eff, ws_id=ws_id),
                json_stdout=json_stdout,
                code=common.EXIT_NOT_FOUND,
            )
        samples = store.list_samples(workspace_id=ws_id)
        runs = store.list_pipeline_runs(workspace_id=ws_id, limit=50)
        analyses = store.list_ai_analyses(workspace_id=ws_id, limit=50)
    finally:
        store.close()

    payload = {
        "workspace": ws,
        "samples": samples,
        "pipeline_runs": runs,
        "ai_analyses": analyses,
    }
    if json_stdout:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    print_workspace_detail(common.console, ws, samples, runs, analyses, lang=eff)
    if output_json:
        output_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@workspace_app.command("create")
def workspace_create(
    name: Annotated[str, typer.Argument(help="Workspace display name")],
    desc: Annotated[str, typer.Option("--desc", "-d", help="Optional description")] = "",
    tags: Annotated[Optional[str], typer.Option("--tags", "-t", help="Comma-separated tags")] = None,
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output created workspace as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """Create a new persistent workspace."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = common.apply_lang(lang)
    store = WorkspaceStore()
    try:
        tag_list = [x.strip() for x in tags.split(",") if x.strip()] if tags else None
        ws = store.create_workspace(name, description=desc, tags=tag_list)
    finally:
        store.close()

    if output_json is not None and str(output_json) == "-":
        print(json.dumps(ws, indent=2, ensure_ascii=False))
        return

    render_kv_card(
        common.console,
        t("ws.title.created", eff),
        [
            (t("ws.kv.id", eff), f"[{C_INFO}]{safe(ws['id'])}[/]"),
            (t("ws.kv.name", eff), f"[{C_LABEL}]{safe(ws['name'])}[/]"),
            (t("ws.kv.desc", eff), safe(ws.get("description") or "—")),
        ],
        border_style=C_OK,
        title_style=f"bold {C_OK}",
    )
    if output_json:
        output_json.write_text(json.dumps(ws, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")


@workspace_app.command("delete")
def workspace_delete(
    ws_id: Annotated[str, typer.Argument(help="Workspace ID to delete")],
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output deletion status as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """Delete a saved workspace and its archived snapshots."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = common.apply_lang(lang)
    json_stdout = output_json is not None and str(output_json) == "-"
    store = WorkspaceStore()
    try:
        deleted = store.delete_workspace(ws_id)
    except ValueError as exc:
        common.fail_error(str(exc), json_stdout=json_stdout)
    finally:
        store.close()

    if not deleted:
        common.fail_error(
            t("ws.not_found", eff, ws_id=ws_id),
            json_stdout=json_stdout,
            code=common.EXIT_NOT_FOUND,
        )

    payload = {"deleted": True, "id": ws_id}
    if json_stdout:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    common.console.print(f"  [{C_OK}]✓[/] {safe(t('ws.deleted', eff, ws_id=ws_id))}")


@workspace_app.command("export")
def workspace_export(
    ws_id: Annotated[str, typer.Argument(help="Workspace ID to export")],
    out: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Destination JSON file (omit or use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """Export a workspace and all saved samples, runs, and AI analyses to a JSON bundle."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = common.apply_lang(lang)
    to_stdout = out is None or str(out) == "-"
    store = WorkspaceStore()
    try:
        try:
            bundle = store.export_workspace_json(ws_id)
        except KeyError:
            common.fail_error(
                t("ws.not_found", eff, ws_id=ws_id),
                json_stdout=to_stdout,
                code=common.EXIT_NOT_FOUND,
            )
    finally:
        store.close()

    serialized = json.dumps(bundle, indent=2, ensure_ascii=False)
    if to_stdout:
        print(serialized)
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(serialized)
    common.console.print(f"  [{C_OK}]✓[/] {safe(t('ws.exported', eff, ws_id=ws_id, path=out))}")


@workspace_app.command("import")
def workspace_import(
    bundle_file: Annotated[Path, typer.Argument(help="Path to exported workspace JSON file")],
    name: Annotated[
        Optional[str],
        typer.Option("--name", "-n", help="Optional override name for the imported workspace"),
    ] = None,
    output_json: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Output imported workspace metadata as JSON (use - for stdout)"),
    ] = None,
    lang: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Display language: en | zh | auto"),
    ] = None,
) -> None:
    """Import a workspace snapshot JSON file into a newly restored workspace."""
    from unpack.core.workspace_store import WorkspaceStore

    eff = common.apply_lang(lang)
    json_stdout = output_json is not None and str(output_json) == "-"
    if not bundle_file.exists():
        common.fail_missing("Bundle", bundle_file, json_stdout=json_stdout)

    try:
        bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        common.fail_error(t("ws.invalid_bundle", eff, err=str(exc)), json_stdout=json_stdout)

    store = WorkspaceStore()
    try:
        try:
            restored = store.import_workspace_json(bundle, name_override=name)
        except ValueError as exc:
            common.fail_error(t("ws.invalid_bundle", eff, err=str(exc)), json_stdout=json_stdout)
    finally:
        store.close()

    if json_stdout:
        print(json.dumps(restored, indent=2, ensure_ascii=False))
        return

    render_kv_card(
        common.console,
        t("ws.title.imported", eff),
        [
            (t("ws.kv.id", eff), f"[{C_INFO}]{safe(restored['id'])}[/]"),
            (t("ws.kv.name", eff), f"[{C_LABEL}]{safe(restored['name'])}[/]"),
            (
                t("ws.kv.counts", eff),
                t(
                    "ws.counts_val",
                    eff,
                    samples=restored.get("sample_count", 0),
                    runs=restored.get("pipeline_run_count", 0),
                    ai=restored.get("ai_analysis_count", 0),
                ),
            ),
        ],
        border_style=C_OK,
        title_style=f"bold {C_OK}",
    )
    if output_json:
        output_json.write_text(json.dumps(restored, indent=2, ensure_ascii=False))
        common.console.print(f"  [{C_DIM}]{safe(t('cli.saved_to', eff, path=output_json))}[/]")
