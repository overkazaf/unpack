"""Shared filesystem, hashing, timestamp, and filename-sanitization helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SAFE_CHAR_RE = re.compile(r"[^A-Za-z0-9._-]+")
_MULTI_UNDERSCORE_RE = re.compile(r"_+")


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format with microseconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def resolve_unpack_home(base_dir: str | Path | None = None) -> Path:
    """Resolve the root UNPACK home directory (``base_dir`` > ``UNPACK_HOME`` > ``~/.unpack``)."""
    if base_dir is not None:
        return Path(base_dir).expanduser()
    env_home = os.environ.get("UNPACK_HOME", "").strip()
    if env_home:
        return Path(env_home).expanduser()
    return Path.home() / ".unpack"


def atomic_write_json(
    path: Path,
    payload: Any,
    *,
    mode: int | None = None,
    indent: int = 2,
) -> None:
    """Atomically write JSON to ``path`` using a same-directory temp file + ``os.replace``.

    When ``mode`` is provided on POSIX systems (e.g. ``0o600`` for secret config
    files), permissions are applied to the file descriptor before data is written
    so sensitive contents are never temporarily world-readable.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=indent, ensure_ascii=False, default=str)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        if mode is not None and os.name == "posix":
            os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        if mode is not None and os.name == "posix":
            os.chmod(path, mode)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def file_sha256(path: Path, *, chunk_size: int = 131072) -> str:
    """Compute the SHA-256 hex digest of ``path`` by streaming in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitize_filename(
    name: str,
    fallback: str = "file",
    *,
    max_length: int = 128,
) -> str:
    """Sanitize an untrusted filename into a safe single-component basename.

    Strips directory components (both ``/`` and ``\\``), neutralizes traversal
    segments (``..``, ``.``), replaces unsafe characters (e.g. ``:``, spaces,
    shell metacharacters, NUL bytes) with ``_``, and enforces ``max_length``.
    """
    raw = str(name or "").replace("\x00", "").replace("\\", "/").strip()
    leaf = raw.rsplit("/", 1)[-1]
    if leaf in ("", ".", ".."):
        return fallback

    cleaned = _SAFE_CHAR_RE.sub("_", leaf)
    cleaned = _MULTI_UNDERSCORE_RE.sub("_", cleaned)
    cleaned = cleaned.lstrip("._").rstrip("_")
    if not cleaned or cleaned in (".", ".."):
        return fallback

    if len(cleaned) > max_length:
        stem, dot, ext = cleaned.rpartition(".")
        if dot and stem and len(ext) <= 16:
            keep = max(1, max_length - len(ext) - 1)
            cleaned = f"{stem[:keep]}.{ext}"
        else:
            cleaned = cleaned[:max_length]

    return cleaned


__all__ = [
    "atomic_write_json",
    "file_sha256",
    "resolve_unpack_home",
    "sanitize_filename",
    "utc_now_iso",
]
