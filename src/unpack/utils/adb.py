from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass


@dataclass
class Device:
    serial: str
    state: str
    model: str | None = None


def list_devices() -> list[Device]:
    try:
        out = subprocess.check_output(
            ["adb", "devices", "-l"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError):
        return []

    devices = []
    for line in out.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            serial = parts[0]
            state = parts[1]
            model = None
            for p in parts[2:]:
                if p.startswith("model:"):
                    model = p.split(":", 1)[1]
            devices.append(Device(serial=serial, state=state, model=model))
    return devices


def get_device_serial(preferred: str | None = None) -> str | None:
    devices = [d for d in list_devices() if d.state == "device"]
    if not devices:
        return None
    if preferred:
        for d in devices:
            if d.serial == preferred:
                return d.serial
    return devices[0].serial


def get_package_name_from_device(serial: str, pid: int) -> str | None:
    try:
        out = subprocess.check_output(
            ["adb", "-s", serial, "shell", f"cat /proc/{pid}/cmdline"],
            text=True, timeout=5,
        )
        return out.strip().split("\x00")[0] or None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def shell(serial: str, cmd: str, timeout: int = 30) -> str:
    return subprocess.check_output(
        ["adb", "-s", serial, "shell", cmd],
        text=True, timeout=timeout,
    ).strip()


def adb_cmd(serial: str, *args: str, timeout: int = 15) -> str:
    cmd = ["adb", "-s", serial, *args]
    return subprocess.check_output(
        cmd, text=True, timeout=timeout, stderr=subprocess.STDOUT
    ).strip()


def adb_shell(serial: str, cmd: str, timeout: int = 30, root: bool = False) -> str:
    if root:
        cmd = f"su -c {shlex.quote(cmd)}"
    return adb_cmd(serial, "shell", cmd, timeout=timeout)


def check_root(serial: str) -> bool:
    try:
        out = adb_shell(serial, "id", root=True)
        return "uid=0" in out
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
