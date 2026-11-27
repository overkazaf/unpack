from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass

from unpack.logging_config import get_logger

log = get_logger(__name__)


@dataclass
class Device:
    serial: str
    state: str
    model: str | None = None


@dataclass(frozen=True)
class ProcMapRegion:
    """Parsed candidate DEX/Dalvik region from ``/proc/<pid>/maps``."""

    start: int
    end: int
    size: int
    perms: str
    path: str


def validate_pid(pid: str | int) -> str:
    """Validate that ``pid`` is a strictly positive decimal integer string."""
    raw = str(pid).strip()
    if not raw or not raw.isdigit() or int(raw) <= 0:
        raise ValueError(f"Invalid PID: {pid!r}")
    return raw


def parse_dex_map_regions(
    maps_text: str,
    *,
    min_size: int = 256,
    max_size: int = 256 * 1024 * 1024,
) -> list[ProcMapRegion]:
    """Parse ``/proc/<pid>/maps`` into non-system candidate DEX/Dalvik regions."""
    regions: list[ProcMapRegion] = []
    for line in maps_text.splitlines():
        parts = line.split()
        if not parts:
            continue
        path = parts[-1] if len(parts) > 5 else ""
        if "[anon:dalvik-" not in line and not any(k in path for k in (".vdex", ".apk", ".dex")):
            continue
        if any(k in path for k in ("/system/", "/apex/", "/vendor/", "/product/")):
            continue
        addr_range = parts[0]
        try:
            start_hex, end_hex = addr_range.split("-", 1)
            start = int(start_hex, 16)
            end = int(end_hex, 16)
        except ValueError:
            continue
        size = end - start
        if size < min_size or size > max_size:
            continue
        perms = parts[1] if len(parts) > 1 else ""
        regions.append(ProcMapRegion(start=start, end=end, size=size, perms=perms, path=path))
    return regions


def read_proc_mem(
    serial: str,
    pid: str | int,
    addr: int,
    size: int,
    *,
    block_size: int = 4096,
    timeout: int = 30,
) -> bytes:
    """Read ``size`` bytes at ``addr`` from ``/proc/<pid>/mem`` via rooted ADB."""
    safe_pid = validate_pid(pid)
    if addr < 0 or size <= 0:
        return b""

    if block_size <= 1:
        dd_cmd = f"dd if=/proc/{safe_pid}/mem bs=1 skip={addr} count={size} 2>/dev/null"
        offset = 0
    else:
        skip_blocks = addr // block_size
        offset = addr % block_size
        blocks = (size + offset + block_size - 1) // block_size
        dd_cmd = (
            f"dd if=/proc/{safe_pid}/mem bs={block_size} "
            f"skip={skip_blocks} count={blocks} 2>/dev/null"
        )

    try:
        raw = subprocess.check_output(
            ["adb", "-s", serial, "shell", "su", "-c", dd_cmd],
            timeout=timeout,
        )
        return raw[offset : offset + size]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        log.debug("read_proc_mem failed for pid=%s addr=%#x size=%d: %s", safe_pid, addr, size, exc)
        return b""


def list_devices() -> list[Device]:
    try:
        out = subprocess.check_output(
            ["adb", "devices", "-l"], text=True, timeout=5, stderr=subprocess.DEVNULL
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as exc:
        log.debug("adb devices failed: %s", exc)
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


def get_package_name_from_device(serial: str, pid: int | str) -> str | None:
    try:
        safe_pid = validate_pid(pid)
    except ValueError:
        return None
    try:
        out = subprocess.check_output(
            ["adb", "-s", serial, "shell", f"cat /proc/{safe_pid}/cmdline"],
            text=True, timeout=5,
        )
        return out.strip().split("\x00")[0] or None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        log.debug("get_package_name_from_device failed for pid=%s: %s", safe_pid, exc)
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


def adb_run(serial: str, *args: str, timeout: int = 10) -> subprocess.CompletedProcess[bytes]:
    """Run an ADB command capturing output without raising on non-zero exit."""
    return subprocess.run(
        ["adb", "-s", serial, *args],
        timeout=timeout,
        capture_output=True,
    )


def check_root(serial: str) -> bool:
    try:
        out = adb_shell(serial, "id", root=True)
        return "uid=0" in out
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False
