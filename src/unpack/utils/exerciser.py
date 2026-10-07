from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass


@dataclass
class ExerciseResult:
    actions_performed: int = 0
    duration_seconds: float = 0.0


_INTERACTION_SEQUENCE = [
    "input swipe 500 1500 500 500 300",
    "input swipe 500 500 500 1500 300",
    "input tap 540 960",
    "input keyevent KEYCODE_BACK",
    "input keyevent KEYCODE_MENU",
    "input tap 540 400",
    "input swipe 200 960 800 960 200",
]


class AppExerciser:
    def __init__(self, rounds: int = 3, delay: float = 2.0):
        self._rounds = rounds
        self._delay = delay

    def exercise(self, serial: str, package_name: str) -> ExerciseResult:
        t0 = time.monotonic()
        actions = 0

        for round_num in range(self._rounds):
            for action in _INTERACTION_SEQUENCE:
                self._run_action(serial, package_name, action)
                actions += 1
                time.sleep(self._delay)

        return ExerciseResult(
            actions_performed=actions,
            duration_seconds=time.monotonic() - t0,
        )

    def _run_action(self, serial: str, package_name: str, action: str):
        try:
            subprocess.run(
                ["adb", "-s", serial, "shell", action],
                timeout=10, capture_output=True,
            )
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
