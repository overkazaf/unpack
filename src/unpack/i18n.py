"""Zero-dependency bilingual (English / Simplified Chinese) i18n engine for UNPACK.

Public API:
- ``SUPPORTED_LANGS``: ``("en", "zh")``
- ``TRANSLATIONS``: mapping of locale code to translation catalog dict
- ``resolve_lang(lang=None)``: normalize explicit lang, honor ``UNPACK_LANG``,
  and safely default to ``"en"`` so existing scripts/tests keep exact English tokens.
- ``set_lang(lang)`` / ``get_lang()`` / ``use_lang(lang)``: context-safe locale state.
- ``t(key, lang=None, **kwargs)``: translate a message key with safe formatting fallback.
"""

from __future__ import annotations

import locale
import os
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from unpack._i18n_en import CATALOG_EN
from unpack._i18n_zh import CATALOG_ZH

SUPPORTED_LANGS: tuple[str, ...] = ("en", "zh")

TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": CATALOG_EN,
    "zh": CATALOG_ZH,
}

_CURRENT_LANG: ContextVar[str | None] = ContextVar("unpack_lang", default=None)


def _detect_system_lang() -> str:
    """Detect Chinese vs English from standard POSIX locale environment variables."""
    for env_key in ("LC_ALL", "LC_MESSAGES", "LANG"):
        val = (os.environ.get(env_key) or "").strip().lower()
        if val:
            if val.startswith("zh"):
                return "zh"
            if val.startswith("en") or val in ("c", "posix"):
                return "en"
    try:
        loc = locale.getlocale()[0] or ""
        if loc.lower().startswith("zh"):
            return "zh"
    except Exception:
        pass
    return "en"


def _normalize_tag(raw: str) -> str | None:
    norm = raw.strip().lower().replace("_", "-")
    if not norm:
        return None
    if norm == "auto":
        return "auto"
    if norm == "zh" or norm.startswith("zh-"):
        return "zh"
    if norm == "en" or norm.startswith("en-"):
        return "en"
    return None


def resolve_lang(lang: str | None = None) -> str:
    """Resolve effective display language (``"en"`` or ``"zh"``).

    Precedence:
    1. Explicit ``lang`` argument (``"en"``, ``"zh"``, ``"zh-CN"``, ``"auto"``).
    2. ``UNPACK_LANG`` environment variable.
    3. Safe default ``"en"`` (unless ``"auto"`` was explicitly requested, in which
       case POSIX locale env vars are inspected).
    """
    if lang is not None:
        tag = _normalize_tag(str(lang))
        if tag in ("en", "zh"):
            return tag
        if tag == "auto":
            env_tag = _normalize_tag(os.environ.get("UNPACK_LANG") or "")
            if env_tag in ("en", "zh"):
                return env_tag
            return _detect_system_lang()
        return "en"

    env_raw = os.environ.get("UNPACK_LANG")
    if env_raw:
        env_tag = _normalize_tag(env_raw)
        if env_tag in ("en", "zh"):
            return env_tag
        if env_tag == "auto":
            return _detect_system_lang()

    return "en"


def set_lang(lang: str | None) -> str:
    """Set the active language for the current execution context.

    Passing ``None`` clears the explicit override so ``get_lang()`` falls back
    to ``resolve_lang(None)`` (honoring ``UNPACK_LANG`` or default ``"en"``).
    """
    if lang is None:
        _CURRENT_LANG.set(None)
        return resolve_lang(None)
    resolved = resolve_lang(lang)
    _CURRENT_LANG.set(resolved)
    return resolved


def get_lang() -> str:
    """Return the active language (``"en"`` or ``"zh"``) for this context."""
    current = _CURRENT_LANG.get()
    if current in SUPPORTED_LANGS:
        return current
    return resolve_lang(None)


@contextmanager
def use_lang(lang: str | None) -> Iterator[str]:
    """Temporarily switch active language within a ``with`` block."""
    resolved = resolve_lang(lang) if lang is not None else get_lang()
    token = _CURRENT_LANG.set(resolved)
    try:
        yield resolved
    finally:
        _CURRENT_LANG.reset(token)


def t(key: str, lang: str | None = None, **kwargs: object) -> str:
    """Translate ``key`` for ``lang`` (or active context language).

    Falls back to English catalog, then returns ``key`` verbatim if unknown.
    """
    eff_lang = resolve_lang(lang) if lang is not None else get_lang()
    catalog = TRANSLATIONS.get(eff_lang) or TRANSLATIONS["en"]
    template = catalog.get(key)
    if template is None:
        template = TRANSLATIONS["en"].get(key, key)
    if kwargs:
        try:
            return template.format(**kwargs)
        except (KeyError, ValueError, IndexError):
            return template
    return template


__all__ = [
    "CATALOG_EN",
    "CATALOG_ZH",
    "SUPPORTED_LANGS",
    "TRANSLATIONS",
    "get_lang",
    "resolve_lang",
    "set_lang",
    "t",
    "use_lang",
]
