"""Security helpers, local-library sandboxing, and HTTP security headers."""

from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from werkzeug.utils import secure_filename

if TYPE_CHECKING:
    from flask import Flask, Response

ALLOWED_UPLOAD_EXTS: frozenset[str] = frozenset({".apk", ".dex"})

# Tight CSP tailored for UNPACK Studio (100% air-gapped local assets + inline SVG/data icons).
STUDIO_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "frame-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'self'"
)


def safe_filename(raw: str | None, default: str = "upload.bin") -> str:
    """Return a traversal-safe single filename component."""
    if not raw or "\x00" in raw:
        return default
    base = Path(raw.replace("\\", "/")).name
    cleaned = secure_filename(base)
    if not cleaned or cleaned in {".", ".."}:
        return default
    return cleaned


def discover_default_local_roots() -> list[Path]:
    """Discover safe local sample directories (env override + test_apks/e2e_test)."""
    roots: list[Path] = []
    seen: set[Path] = set()

    def _add(p: Path) -> None:
        try:
            rp = p.resolve()
        except OSError:
            return
        if rp.exists() and rp.is_dir() and rp not in seen:
            seen.add(rp)
            roots.append(rp)

    env_roots = os.environ.get("UNPACK_LOCAL_ROOTS", "")
    if env_roots:
        for part in env_roots.split(os.pathsep):
            if part.strip():
                _add(Path(part.strip()))

    # studio/security.py -> parents[3] is repo root (or package parent when installed)
    repo_root = Path(__file__).resolve().parents[3]
    for base in (Path.cwd(), repo_root):
        for sub in ("test_apks", "e2e_test"):
            _add(base / sub)

    return roots


def resolve_allowed_local_path(raw_path: str, allowed_roots: list[Path]) -> Path | None:
    """Resolve ``raw_path`` and ensure it lies strictly inside an allowlisted root."""
    if not raw_path or "\x00" in raw_path:
        return None
    try:
        candidate = Path(raw_path).resolve()
    except OSError:
        return None
    if not candidate.exists():
        return None
    for root in allowed_roots:
        try:
            resolved_root = root.resolve()
            if candidate.is_relative_to(resolved_root):
                return candidate
        except OSError:
            continue
    return None


def is_valid_apk_zip(path: Path) -> bool:
    """Verify ``path`` is a valid ZIP archive containing APK markers."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = set(zf.namelist())
            return "AndroidManifest.xml" in names or any(n.endswith(".dex") for n in names)
    except (zipfile.BadZipFile, OSError):
        return False


def is_valid_dex_header(path: Path) -> bool:
    """Verify ``path`` starts with a valid DEX or CompactDex magic header."""
    try:
        with open(path, "rb") as f:
            magic = f.read(8)
        return len(magic) >= 4 and (magic[:4] == b"dex\n" or magic[:4] == b"cdex")
    except OSError:
        return False


def apply_security_headers(response: Response) -> Response:
    """Attach standard commercial HTTP security headers to every response."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    # Do not override CSP on downloaded/rendered standalone HTML audit reports
    content_disp = response.headers.get("Content-Disposition", "")
    if not content_disp.startswith("attachment") and not response.mimetype.startswith("text/event-stream"):
        response.headers.setdefault("Content-Security-Policy", STUDIO_CSP)
    return response


def register_security_middleware(app: Flask) -> None:
    """Register security-header after_request hook on ``app``."""
    app.after_request(apply_security_headers)
