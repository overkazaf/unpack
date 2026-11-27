"""Shared precompiled IOC (Indicator of Compromise) patterns for DEX/string analysis."""

from __future__ import annotations

import re

URL_RE = re.compile(r"https?://[^\s'\"<>]{4,}", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SECRET_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|"
    r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,})",
    re.IGNORECASE,
)
ANTI_ANALYSIS_RE = re.compile(
    r"(?:/system/bin/su|/sbin/su|frida-server|frida|/proc/self/maps|libfrida|xposed)",
    re.IGNORECASE,
)


def categorize_string(value: str) -> str:
    """Classify a DEX string literal into an IOC category."""
    if SECRET_RE.search(value):
        return "secret"
    if URL_RE.search(value):
        return "url"
    if ANTI_ANALYSIS_RE.search(value):
        return "anti_analysis"
    if IP_RE.search(value):
        return "ip"
    return "plain"


__all__ = [
    "ANTI_ANALYSIS_RE",
    "IP_RE",
    "SECRET_RE",
    "URL_RE",
    "categorize_string",
]
