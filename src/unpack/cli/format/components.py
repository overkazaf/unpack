"""Reusable Rich layout components for UNPACK CLI commands."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from unpack.cli.format.theme import (
    C_DIM,
    C_FAIL,
    C_HEADER,
    C_INFO,
    C_LABEL,
    eff_lang,
    safe,
)
from unpack.i18n import t


def render_header(
    console: Console,
    title: str,
    subtitle: str | None = None,
    meta: str | None = None,
) -> None:
    """Render a crisp, restrained section masthead."""
    left = f"[header]{safe(title)}[/]"
    if subtitle:
        left += f"  [{C_DIM}]{safe(subtitle)}[/]"
    if meta:
        left += f"  [{C_DIM}]· {safe(meta)}[/]"
    console.print(Rule(left, align="left", style=C_DIM))


def render_kv_card(
    console: Console,
    title: str,
    rows: list[tuple[str, str]],
    *,
    border_style: str = C_DIM,
    title_style: str = C_HEADER,
    box_style: box.Box = box.ROUNDED,
) -> None:
    """Render an aligned key-value summary card."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column("key", style=C_LABEL, no_wrap=True)
    grid.add_column("value")
    for k, v in rows:
        grid.add_row(safe(k), v)
    console.print(
        Panel(
            grid,
            title=f"[{title_style}] {safe(title)} [/]",
            title_align="left",
            border_style=border_style,
            box=box_style,
            padding=(0, 1),
        )
    )


def render_table(
    console: Console,
    columns: list[tuple[str, dict[str, Any]]],
    rows: Iterable[list[str]],
    *,
    title: str | None = None,
    caption: str | None = None,
    box_style: box.Box = box.SIMPLE_HEAVY,
) -> None:
    """Render a consistent minimal-grid table."""
    table = Table(
        title=f"[{C_LABEL}]{safe(title)}[/]" if title else None,
        title_justify="left",
        caption=f"[{C_DIM}]{safe(caption)}[/]" if caption else None,
        caption_justify="left",
        box=box_style,
        header_style=C_LABEL,
        border_style=C_DIM,
        pad_edge=False,
    )
    for col_name, kwargs in columns:
        table.add_column(col_name, **kwargs)
    for row in rows:
        table.add_row(*row)
    console.print(table)


def render_tree(console: Console, root_label: str, items: list[dict[str, Any]]) -> None:
    """Render a hierarchical Rich Tree from nested ``{label, children}`` dicts."""
    tree = Tree(f"[header]{safe(root_label)}[/]", guide_style=C_DIM)

    def _add(branch: Tree, nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            label = str(node.get("label") or node.get("name") or "")
            meta = node.get("meta")
            text = f"{safe(label)} [{C_DIM}]{safe(meta)}[/]" if meta else safe(label)
            child_branch = branch.add(text)
            children = node.get("children") or []
            if children:
                _add(child_branch, children)

    _add(tree, items)
    console.print(tree)


def render_pipeline_step(
    console: Console,
    step: int,
    total: int,
    label: str,
    detail: str | None = None,
    *,
    lang: str | None = None,
) -> None:
    """Render a clean numbered pipeline phase header."""
    eff = eff_lang(lang)
    prefix = t("fmt.step_prefix", eff, step=step, total=total)
    suffix = f"  [{C_DIM}]{safe(detail)}[/]" if detail else ""
    console.print(f"\n[{C_INFO}]▸[/] [{C_HEADER}]{safe(prefix)}[/]  [{C_LABEL}]{safe(label)}[/]{suffix}")


def render_wizard_step(
    console: Console,
    step: int,
    total: int,
    title: str,
    subtitle: str | None = None,
    *,
    lang: str | None = None,
) -> None:
    """Render a step header for the interactive onboarding wizard."""
    eff = eff_lang(lang)
    prefix = t("fmt.step_prefix", eff, step=step, total=total)
    console.print()
    render_header(console, f"{prefix} · {title}", subtitle=subtitle)


def render_error(
    console: Console,
    title: str,
    detail: str | None = None,
    hint: str | None = None,
    *,
    lang: str | None = None,
) -> None:
    """Render an actionable commercial error callout."""
    eff = eff_lang(lang)
    lines = [f"[{C_FAIL}]✗ {safe(title)}[/]"]
    if detail:
        lines.append(f"  {safe(detail)}")
    if hint:
        lines.append(f"  [{C_INFO}]{safe(t('fmt.hint_label', eff))}[/] {safe(hint)}")
    console.print("\n".join(lines))


def render_next_steps(
    console: Console,
    steps: list[tuple[str, str]],
    *,
    lang: str | None = None,
) -> None:
    """Render concise, runnable next-step command hints."""
    if not steps:
        return
    eff = eff_lang(lang)
    console.print(f"\n[{C_DIM}]{safe(t('fmt.next_steps', eff))}[/]")
    for cmd, desc in steps:
        console.print(f"  [{C_INFO}]$[/] [cmd]{safe(cmd)}[/]  [{C_DIM}]# {safe(desc)}[/]")
