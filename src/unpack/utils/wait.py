from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field

from unpack.logging_config import get_logger
from unpack.utils.adb import adb_shell, validate_pid

log = get_logger(__name__)


@dataclass
class WaitResult:
    waited_seconds: float
    reason: str  # "threads_stable" | "logcat_ready" | "max_wait" | "process_died"
    thread_counts: list[int] = field(default_factory=list)


_PACKER_DONE_KEYWORDS = [
    "decrypt finish",
    "unshell",
    "load dex success",
    "jiagu init done",
]


class SmartWaiter:
    def __init__(
        self,
        poll_interval: float = 1.0,
        stable_rounds: int = 3,
        max_wait: float = 30.0,
        min_wait: float = 3.0,
    ):
        self._poll_interval = poll_interval
        self._stable_rounds = stable_rounds
        self._max_wait = max_wait
        self._min_wait = min_wait

    def wait(self, serial: str, pid: str) -> WaitResult:
        safe_pid = validate_pid(pid)
        t0 = time.monotonic()
        thread_counts: list[int] = []
        stable_count = 0
        last_count = -1

        while True:
            elapsed = time.monotonic() - t0

            if elapsed >= self._max_wait:
                return WaitResult(
                    waited_seconds=elapsed,
                    reason="max_wait",
                    thread_counts=thread_counts,
                )

            count = self._get_thread_count(serial, safe_pid)
            if count is None:
                return WaitResult(
                    waited_seconds=elapsed,
                    reason="process_died",
                    thread_counts=thread_counts,
                )

            thread_counts.append(count)

            if count == last_count:
                stable_count += 1
            else:
                stable_count = 1
                last_count = count

            if stable_count >= self._stable_rounds and elapsed >= self._min_wait:
                return WaitResult(
                    waited_seconds=elapsed,
                    reason="threads_stable",
                    thread_counts=thread_counts,
                )

            if elapsed >= self._min_wait and self._check_logcat_ready(serial, safe_pid):
                return WaitResult(
                    waited_seconds=elapsed,
                    reason="logcat_ready",
                    thread_counts=thread_counts,
                )

            time.sleep(self._poll_interval)

    def _get_thread_count(self, serial: str, pid: str) -> int | None:
        try:
            safe_pid = validate_pid(pid)
            out = adb_shell(
                serial,
                f"ls /proc/{safe_pid}/task 2>/dev/null | wc -l",
                timeout=5,
                root=False,
            )
            count = int(out.strip())
            return count if count > 0 else None
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, OSError) as exc:
            log.debug("SmartWaiter thread count probe failed for pid=%s: %s", pid, exc)
            return None

    def _check_logcat_ready(self, serial: str, pid: str) -> bool:
        try:
            safe_pid = validate_pid(pid)
            out = adb_shell(
                serial,
                f"logcat -d --pid={safe_pid} -t 50 2>/dev/null",
                timeout=5,
                root=False,
            )
            lower = out.lower()
            for kw in _PACKER_DONE_KEYWORDS:
                if kw.lower() in lower:
                    return True
            if lower.count("displayed") >= 1:
                return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, OSError) as exc:
            log.debug("SmartWaiter logcat probe failed for pid=%s: %s", pid, exc)
        return False
