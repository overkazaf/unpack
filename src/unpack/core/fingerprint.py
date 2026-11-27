"""Runtime packer behavior fingerprinting.

Probes a live process via ADB (``/proc/pid/maps``, ``/proc/pid/status``,
``/proc/pid/task/*/comm``) to build a behavioral profile of a running app
and estimate how likely it is to be a hardened/packed process at runtime
(ptrace self-protection, watchdog/anti-tamper threads, excessive Dalvik
anonymous mappings, custom linker namespaces, thread-count anomalies).

This module is standalone — it does not depend on :mod:`unpack.core.scanner`
or :mod:`unpack.core.dispatcher` and is not yet wired into the CLI.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

from unpack.logging_config import get_logger
from unpack.utils.adb import adb_shell, validate_pid

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Thread classification
# ---------------------------------------------------------------------------

_BENIGN_THREAD_NAMES: frozenset[str] = frozenset(
    {
        "main",
        "Binder:main",
        "FinalizerDaemon",
        "FinalizerWatchdogDaemon",
        "ReferenceQueueDaemon",
        "HeapTaskDaemon",
        "Signal Catcher",
        "JDWP",
        "Jit thread pool",
        "perfetto_hprof_listener",
        "ADB-JDWP Connection Control Thread",
    }
)

# Benign Binder threads are named "Binder:<pid>_N" — treat the whole family
# as benign regardless of the numeric suffix.
_BENIGN_THREAD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^Binder:\d+(_\d+)?$"),
    re.compile(r"^RenderThread$"),
    re.compile(r"^hwuiTask\d*$"),
)

_SUSPICIOUS_THREAD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^pool-\d+-thread-\d+$"),
    re.compile(r"^Thread-\d+$"),
    re.compile(r"^timer-\d+$"),
    re.compile(r".*watchdog.*", re.IGNORECASE),
    re.compile(r".*monitor.*", re.IGNORECASE),
    re.compile(r".*checker.*", re.IGNORECASE),
)

_DALVIK_ANON_MARKER = "[anon:dalvik-"


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class FingerprintResult:
    dalvik_anon_regions: int = 0
    watchdog_threads: list[str] = field(default_factory=list)
    has_ptrace_protection: bool = False
    custom_linker_ns: bool = False
    thread_count: int = 0

    @property
    def risk_score(self) -> float:
        score = 0.0
        if self.dalvik_anon_regions > 10:
            score += 0.2
        if self.watchdog_threads:
            score += min(0.3, len(self.watchdog_threads) * 0.1)
        if self.has_ptrace_protection:
            score += 0.2
        if self.custom_linker_ns:
            score += 0.15
        if self.thread_count > 30:
            score += 0.15
        return min(score, 1.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dalvik_anon_regions": self.dalvik_anon_regions,
            "watchdog_threads": self.watchdog_threads,
            "has_ptrace_protection": self.has_ptrace_protection,
            "custom_linker_ns": self.custom_linker_ns,
            "thread_count": self.thread_count,
            "risk_score": round(self.risk_score, 3),
        }


# ---------------------------------------------------------------------------
# PackerFingerprint
# ---------------------------------------------------------------------------


class PackerFingerprint:
    """Probes a live process over ADB to build a :class:`FingerprintResult`."""

    def probe(self, serial: str, pid: str) -> FingerprintResult:
        safe_pid = validate_pid(pid)
        result = FingerprintResult()

        maps_text = self._safe_shell(serial, f"cat /proc/{safe_pid}/maps", root=True)
        result.dalvik_anon_regions = self._count_dalvik_anon(maps_text)
        result.custom_linker_ns = self._has_custom_linker_ns(maps_text)

        status_text = self._safe_shell(serial, f"cat /proc/{safe_pid}/status", root=True)
        result.has_ptrace_protection = self._has_ptrace(status_text)

        comms = self._read_thread_comms(serial, safe_pid)
        result.thread_count = len(comms)
        result.watchdog_threads = self._find_watchdog_threads(comms)

        return result

    # -- probing helpers ----------------------------------------------------

    def _safe_shell(self, serial: str, cmd: str, root: bool = True) -> str:
        try:
            return adb_shell(serial, cmd, root=root)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            log.debug("PackerFingerprint adb_shell failed (%s): %s", cmd, exc)
            return ""

    def _read_thread_comms(self, serial: str, pid: str) -> list[str]:
        safe_pid = validate_pid(pid)
        out = self._safe_shell(
            serial, f"for f in /proc/{safe_pid}/task/*/comm; do cat \"$f\"; done", root=True
        )
        if not out:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]

    # -- parsing helpers ------------------------------------------------------

    def _count_dalvik_anon(self, maps_text: str) -> int:
        return sum(1 for line in maps_text.splitlines() if _DALVIK_ANON_MARKER in line)

    def _has_ptrace(self, status_text: str) -> bool:
        match = re.search(r"TracerPid:\s*(\d+)", status_text)
        return int(match.group(1)) > 0 if match else False

    def _has_custom_linker_ns(self, maps_text: str) -> bool:
        """Heuristic: a non-system linker/loader mapped outside the usual
        system library paths suggests a custom linker namespace used to
        hide/relocate native libraries at runtime."""
        for line in maps_text.splitlines():
            if "linker" not in line and "/apex/com.android.runtime" not in line:
                continue
            if "/system/" in line or "/apex/com.android.runtime" in line:
                continue
            if ".so" in line or "linker" in line:
                return True
        return False

    def _find_watchdog_threads(self, comms: list[str]) -> list[str]:
        flagged: list[str] = []
        for name in comms:
            if name in _BENIGN_THREAD_NAMES:
                continue
            if any(p.match(name) for p in _BENIGN_THREAD_PATTERNS):
                continue
            if any(p.match(name) for p in _SUSPICIOUS_THREAD_PATTERNS):
                flagged.append(name)
        return flagged
