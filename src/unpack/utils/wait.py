from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field


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

            count = self._get_thread_count(serial, pid)
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

            if elapsed >= self._min_wait and self._check_logcat_ready(serial, pid):
                return WaitResult(
                    waited_seconds=elapsed,
                    reason="logcat_ready",
                    thread_counts=thread_counts,
                )

            time.sleep(self._poll_interval)

    def _get_thread_count(self, serial: str, pid: str) -> int | None:
        try:
            out = subprocess.check_output(
                ["adb", "-s", serial, "shell", f"ls /proc/{pid}/task 2>/dev/null | wc -l"],
                text=True, timeout=5,
            ).strip()
            count = int(out)
            return count if count > 0 else None
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            return None

    def _check_logcat_ready(self, serial: str, pid: str) -> bool:
        try:
            out = subprocess.check_output(
                ["adb", "-s", serial, "shell",
                 f"logcat -d --pid={pid} -t 50 2>/dev/null"],
                text=True, timeout=5,
            )
            lower = out.lower()
            for kw in _PACKER_DONE_KEYWORDS:
                if kw.lower() in lower:
                    return True
            if lower.count("displayed") >= 1:
                return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        return False
