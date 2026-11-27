"""Structured logging configuration for UNPACK.

Library modules obtain loggers via :func:`get_logger` (a ``NullHandler`` is
attached to the ``unpack`` package logger by default so library callers never
see spurious stderr output). Entrypoints (CLI, Web Studio) call
:func:`configure_logging` once at startup.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import TextIO

DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_HANDLER_NAME = "unpack_stderr"

_LEVEL_MAP: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    "OFF": logging.CRITICAL + 10,
    "SILENT": logging.CRITICAL + 10,
}

# Library-safe default: attach NullHandler to package root logger once.
_pkg_logger = logging.getLogger("unpack")
if not _pkg_logger.handlers:
    _pkg_logger.addHandler(logging.NullHandler())


def _resolve_level(level: str | int | None) -> int:
    if isinstance(level, int):
        return level
    raw = level if level is not None else os.environ.get("UNPACK_LOG_LEVEL", "")
    text = str(raw or "").strip().upper()
    if not text:
        return logging.WARNING
    if text.isdigit():
        return int(text)
    if text in _LEVEL_MAP:
        return _LEVEL_MAP[text]
    raise ValueError(
        f"Invalid log level {level!r}. Expected one of: DEBUG, INFO, WARNING, ERROR, CRITICAL, OFF."
    )


def get_logger(name: str = "unpack") -> logging.Logger:
    """Return a standard :class:`logging.Logger` scoped to ``name``."""
    return logging.getLogger(name)


def configure_logging(
    level: str | int | None = None,
    *,
    stream: TextIO | None = None,
    fmt: str = DEFAULT_LOG_FORMAT,
    force: bool = False,
) -> logging.Logger:
    """Configure the ``unpack`` package logger for CLI or Web Studio runtime.

    Parameters
    ----------
    level:
        Log level name (``DEBUG``..``CRITICAL``/``OFF``) or numeric constant.
        When ``None``, honors ``UNPACK_LOG_LEVEL`` and defaults to ``WARNING``.
    stream:
        Target output stream (defaults to ``sys.stderr``).
    fmt:
        Log format string.
    force:
        Replace any existing UNPACK stderr handler when ``True``.
    """
    resolved_level = _resolve_level(level)
    logger = logging.getLogger("unpack")
    logger.setLevel(resolved_level)

    existing = [h for h in logger.handlers if getattr(h, "name", "") == _HANDLER_NAME]
    if force:
        for h in existing:
            logger.removeHandler(h)
        existing = []

    if not existing:
        handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
        handler.name = _HANDLER_NAME
        handler.setFormatter(logging.Formatter(fmt))
        handler.setLevel(resolved_level)
        logger.addHandler(handler)
    else:
        for h in existing:
            h.setLevel(resolved_level)
            h.setFormatter(logging.Formatter(fmt))

    return logger


__all__ = [
    "DEFAULT_LOG_FORMAT",
    "configure_logging",
    "get_logger",
]
