"""UNPACK Studio web UI launcher command: ``web``."""

from __future__ import annotations

from typing import Annotated

import typer

from unpack.cli import common
from unpack.cli.format import C_HEADER, C_OK, render_error
from unpack.i18n import get_lang, t


def web(
    port: Annotated[int, typer.Option("--port", "-p", help="Port to listen on")] = 8080,
    host: Annotated[str, typer.Option("--host", help="Host to bind to")] = "127.0.0.1",
) -> None:
    """Launch Unpack Studio web UI.

    Opens a browser-based interface for scan, inspect, dump, repair, and verify.
    Requires flask: pip install -e '.[web]'
    """
    eff = get_lang()
    try:
        from unpack.web import create_app
    except ImportError:
        render_error(
            common.console,
            t("cli.web.no_flask", eff),
            hint=t("cli.web.no_flask_hint", eff),
            lang=eff,
        )
        raise typer.Exit(common.EXIT_ERROR)

    common.console.print(f"  [{C_OK}]✓[/] [{C_HEADER}]UNPACK Studio[/]  http://{host}:{port}")
    webapp = create_app()
    webapp.run(host=host, port=port, debug=False)
