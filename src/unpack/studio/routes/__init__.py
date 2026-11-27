"""Flask Blueprint registration for UNPACK Studio."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flask import current_app

if TYPE_CHECKING:
    from flask import Flask
    from unpack.studio.context import StudioContext


def get_ctx() -> StudioContext:
    return current_app.config["UNPACK_CTX"]


def register_blueprints(app: Flask) -> None:
    from unpack.studio.routes.ai import bp as ai_bp
    from unpack.studio.routes.analysis import bp as analysis_bp
    from unpack.studio.routes.legacy import bp as legacy_bp
    from unpack.studio.routes.pipeline import bp as pipeline_bp
    from unpack.studio.routes.repair_export import bp as repair_export_bp
    from unpack.studio.routes.samples import bp as samples_bp
    from unpack.studio.routes.system import bp as system_bp
    from unpack.studio.routes.workspaces import bp as workspaces_bp

    for bp in (
        system_bp,
        samples_bp,
        analysis_bp,
        repair_export_bp,
        pipeline_bp,
        workspaces_bp,
        ai_bp,
        legacy_bp,
    ):
        app.register_blueprint(bp)
