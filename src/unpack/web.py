"""UNPACK Studio — Compatibility facade for the modular ``unpack.studio`` package.

Preserves 100% backward compatibility for ``from unpack.web import create_app``,
``JobManager``, ``APP_VERSION``, ``main``, and console script ``unpack-web``.
"""

from __future__ import annotations

from unpack.studio import (
    ALLOWED_UPLOAD_EXTS,
    APP_VERSION,
    MAX_ARTIFACTS,
    MAX_DEX_CACHE,
    MAX_INSPECT_LOCKS,
    MAX_JOBS_RETAINED,
    JobManager,
    StudioContext,
    create_app,
    main,
)
from unpack.studio.schemas import (
    api_error,
    dir_fingerprint as _dir_fingerprint,
    file_sha256 as _file_sha256,
    normalize_lang as _normalize_lang,
    parse_bool as _parse_bool,
    parse_int as _parse_int,
    utc_now_iso as _utc_now_iso,
)
from unpack.studio.security import (
    discover_default_local_roots as _discover_default_local_roots,
    is_valid_apk_zip as _is_valid_apk_zip,
    is_valid_dex_header as _is_valid_dex_header,
    resolve_allowed_local_path as _resolve_allowed_local_path,
    safe_filename as _safe_filename,
)

__all__ = [
    "ALLOWED_UPLOAD_EXTS",
    "APP_VERSION",
    "JobManager",
    "MAX_ARTIFACTS",
    "MAX_DEX_CACHE",
    "MAX_INSPECT_LOCKS",
    "MAX_JOBS_RETAINED",
    "StudioContext",
    "api_error",
    "create_app",
    "main",
    "_dir_fingerprint",
    "_discover_default_local_roots",
    "_file_sha256",
    "_is_valid_apk_zip",
    "_is_valid_dex_header",
    "_normalize_lang",
    "_parse_bool",
    "_parse_int",
    "_resolve_allowed_local_path",
    "_safe_filename",
    "_utc_now_iso",
]

if __name__ == "__main__":
    main()
