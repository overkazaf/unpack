"""Environment Doctor & Diagnostics API.

Probes the local Python environment, optional dependencies, external Android
reverse-engineering tools, connected ADB devices, and dump-engine readiness,
returning a structured :class:`DoctorReport` usable by CLI (`unpack doctor`)
and Web Studio (`/api/v1/doctor`).
"""

from __future__ import annotations

import importlib.metadata
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from unpack import __version__ as UNPACK_VERSION


@dataclass
class DiagnosticCheck:
    id: str
    category: str  # "runtime" | "dependency" | "tool" | "device" | "engine"
    name: str
    status: str  # "pass" | "warn" | "fail"
    summary: str
    version: str = ""
    detail: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "name": self.name,
            "status": self.status,
            "summary": self.summary,
            "version": self.version,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class DeviceInfo:
    serial: str
    state: str
    model: str = ""
    android_version: str = ""
    api_level: str = ""
    abi: str = ""
    rooted: bool = False
    has_bpftrace: bool = False
    frida_server_running: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "state": self.state,
            "model": self.model,
            "android_version": self.android_version,
            "api_level": self.api_level,
            "abi": self.abi,
            "rooted": self.rooted,
            "has_bpftrace": self.has_bpftrace,
            "frida_server_running": self.frida_server_running,
        }


@dataclass
class EngineStatus:
    name: str
    available: bool
    recommended: bool = False
    reason: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "recommended": self.recommended,
            "reason": self.reason,
            "remediation": self.remediation,
        }


@dataclass
class DoctorReport:
    overall_status: str  # "healthy" | "degraded" | "unhealthy"
    python_version: str
    unpack_version: str
    checks: list[DiagnosticCheck] = field(default_factory=list)
    devices: list[DeviceInfo] = field(default_factory=list)
    engines: list[EngineStatus] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status,
            "python_version": self.python_version,
            "unpack_version": self.unpack_version,
            "checks": [c.to_dict() for c in self.checks],
            "devices": [d.to_dict() for d in self.devices],
            "engines": [e.to_dict() for e in self.engines],
        }


def _pkg_version(dist_name: str, import_name: str | None = None) -> tuple[bool, str]:
    try:
        ver = importlib.metadata.version(dist_name)
        return True, ver
    except importlib.metadata.PackageNotFoundError:
        pass
    mod = import_name or dist_name.replace("-", "_")
    try:
        imported = __import__(mod)
        return True, str(getattr(imported, "__version__", "installed"))
    except Exception:
        return False, ""


def _probe_tool(binary: str, version_args: list[str], timeout: float) -> tuple[bool, str, str]:
    path = shutil.which(binary)
    if not path:
        return False, "", ""
    try:
        proc = subprocess.run(
            [path, *version_args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw = (proc.stdout or proc.stderr or "").strip()
        first_line = raw.splitlines()[0].strip() if raw else ""
        return True, path, first_line[:80]
    except Exception:
        return True, path, ""


def _safe_adb_shell(serial: str, cmd: str, timeout: float, root: bool = False) -> str:
    from unpack.utils.adb import adb_shell

    try:
        return adb_shell(serial, cmd, timeout=int(max(1, round(timeout))), root=root)
    except Exception:
        return ""


def _probe_devices(device_serial: str | None, timeout: float) -> list[DeviceInfo]:
    from unpack.utils.adb import list_devices

    raw_devices = list_devices()
    if device_serial:
        raw_devices = [d for d in raw_devices if d.serial == device_serial]

    infos: list[DeviceInfo] = []
    for d in raw_devices:
        info = DeviceInfo(serial=d.serial, state=d.state, model=d.model or "")
        if d.state == "device":
            info.android_version = _safe_adb_shell(
                d.serial, "getprop ro.build.version.release", timeout
            )
            info.api_level = _safe_adb_shell(
                d.serial, "getprop ro.build.version.sdk", timeout
            )
            info.abi = _safe_adb_shell(
                d.serial, "getprop ro.product.cpu.abi", timeout
            )
            uid_out = _safe_adb_shell(d.serial, "id", timeout, root=True)
            info.rooted = "uid=0" in uid_out
            if info.rooted:
                bpf_out = _safe_adb_shell(
                    d.serial,
                    "for p in /data/local/tmp/bpftrace /system/bin/bpftrace /sbin/bpftrace; "
                    "do [ -x $p ] && echo FOUND; done",
                    timeout,
                    root=True,
                )
                info.has_bpftrace = "FOUND" in bpf_out
                ps_out = _safe_adb_shell(
                    d.serial, "pgrep -f frida-server || true", timeout, root=True
                )
                info.frida_server_running = bool(ps_out.strip())
        infos.append(info)
    return infos


def run_doctor(
    check_devices: bool = True,
    device_serial: str | None = None,
    timeout: float = 3.0,
) -> DoctorReport:
    """Run full environment, tool, device, and engine diagnostics."""
    py_ver = platform.python_version()
    checks: list[DiagnosticCheck] = []

    # 1. Runtime
    py_ok = tuple(int(p) for p in py_ver.split(".")[:2]) >= (3, 10)
    checks.append(
        DiagnosticCheck(
            id="python_runtime",
            category="runtime",
            name="Python Runtime",
            status="pass" if py_ok else "fail",
            summary=f"Python {py_ver} ({platform.machine()})",
            version=py_ver,
            detail=f"{platform.system()} {platform.release()}",
            remediation="" if py_ok else "Upgrade to Python >= 3.10.",
        )
    )

    # 2. Python dependencies
    dep_specs = [
        ("typer", "typer", True, "", "CLI framework"),
        ("rich", "rich", True, "", "Terminal rendering"),
        ("flask", "flask", False, "web", "Unpack Studio Web UI"),
        ("androguard", "androguard", False, "analysis", "Full AndroidManifest & APK parsing"),
        ("cryptography", "cryptography", False, "analysis", "APK v1 X.509 certificate inspection"),
        ("lief", "lief", False, "analysis", "Extended ELF symbol enrichment (builtin ELF fallback active)"),
        ("frida", "frida", False, "frida", "Frida DBI & active invocation engine"),
    ]
    dep_installed: dict[str, bool] = {}
    for dist_name, import_name, required, extra, desc in dep_specs:
        ok, ver = _pkg_version(dist_name, import_name)
        dep_installed[dist_name] = ok
        status = "pass" if ok else ("fail" if required else "warn")
        rem = "" if ok else (
            f"pip install -e '.[{extra}]'" if extra else f"pip install {dist_name}"
        )
        checks.append(
            DiagnosticCheck(
                id=f"dep_{dist_name}",
                category="dependency",
                name=dist_name,
                status=status,
                summary=f"{dist_name} {ver}" if ok else f"{dist_name} not installed",
                version=ver,
                detail=desc,
                remediation=rem,
            )
        )

    # 3. External RE tools
    tool_specs = [
        ("adb", ["version"], "Android Debug Bridge (required for dynamic dump/rescan)", "Install Android platform-tools and add adb to PATH."),
        ("jadx", ["--version"], "DEX-to-Java decompiler (recommended post-unpack)", "brew install jadx"),
        ("apktool", ["--version"], "APK resource decoder/rebuilder", "brew install apktool"),
        ("zipalign", [], "APK alignment tool (optional for repacking)", "Install Android SDK build-tools."),
        ("apksigner", ["version"], "APK v2/v3 signing tool (optional for repacking)", "Install Android SDK build-tools."),
        ("keytool", ["-help"], "Java keystore/certificate utility", "Install OpenJDK."),
    ]
    tool_found: dict[str, bool] = {}
    for binary, args, desc, rem in tool_specs:
        ok, path, ver_line = _probe_tool(binary, args, timeout)
        tool_found[binary] = ok
        checks.append(
            DiagnosticCheck(
                id=f"tool_{binary}",
                category="tool",
                name=binary,
                status="pass" if ok else "warn",
                summary=f"{binary} found ({path})" if ok else f"{binary} not found on PATH",
                version=ver_line if ok else "",
                detail=desc,
                remediation="" if ok else rem,
            )
        )

    # 4. Connected ADB devices
    devices: list[DeviceInfo] = []
    if check_devices and tool_found.get("adb", False):
        devices = _probe_devices(device_serial=device_serial, timeout=timeout)
        online = [d for d in devices if d.state == "device"]
        if online:
            summary = f"{len(online)} online device(s): " + ", ".join(
                f"{d.serial} (Android {d.android_version or '?'}, {'root' if d.rooted else 'non-root'})"
                for d in online
            )
            checks.append(
                DiagnosticCheck(
                    id="adb_devices",
                    category="device",
                    name="ADB Devices",
                    status="pass",
                    summary=summary,
                    detail=f"Total listed: {len(devices)}",
                )
            )
        else:
            checks.append(
                DiagnosticCheck(
                    id="adb_devices",
                    category="device",
                    name="ADB Devices",
                    status="warn",
                    summary="No online ADB device connected (offline analysis works without a device)",
                    remediation="Connect an Android device with USB debugging enabled for dynamic dump/rescan.",
                )
            )
    else:
        checks.append(
            DiagnosticCheck(
                id="adb_devices",
                category="device",
                name="ADB Devices",
                status="warn",
                summary="Device probe skipped" if not check_devices else "adb not installed — cannot probe devices",
                remediation="" if not check_devices else "Install Android platform-tools.",
            )
        )

    # 5. Dump engine readiness
    online_devices = [d for d in devices if d.state == "device"]
    primary = online_devices[0] if online_devices else None

    engines: list[EngineStatus] = []

    # Memory engine
    mem_avail = bool(primary and primary.rooted)
    mem_reason = (
        "" if mem_avail else (
            "No online ADB device connected"
            if not primary else "Connected device is not rooted (requires uid=0 for /proc/<pid>/mem)"
        )
    )
    engines.append(
        EngineStatus(
            name="memory",
            available=mem_avail,
            recommended=True,
            reason=mem_reason,
            remediation="" if mem_avail else "Connect a rooted device (Magisk/KernelSU/eng build).",
        )
    )

    # Frida engine
    frida_pkg = dep_installed.get("frida", False)
    frida_avail = bool(frida_pkg and primary and primary.frida_server_running)
    if not frida_pkg:
        frida_reason = "frida Python package not installed"
        frida_rem = "pip install -e '.[frida]'"
    elif not primary:
        frida_reason = "No online ADB device connected"
        frida_rem = "Connect an Android device running frida-server."
    elif not primary.frida_server_running:
        frida_reason = "frida-server process not detected on device"
        frida_rem = "Push and start frida-server on the Android device as root."
    else:
        frida_reason = ""
        frida_rem = ""
    engines.append(
        EngineStatus(
            name="frida",
            available=frida_avail,
            recommended=False,
            reason=frida_reason,
            remediation=frida_rem,
        )
    )

    # eBPF engine
    ebpf_avail = bool(primary and primary.rooted and primary.has_bpftrace)
    if not primary:
        ebpf_reason = "No online ADB device connected"
        ebpf_rem = "Connect a rooted Android device (kernel >= 5.4) with bpftrace."
    elif not primary.rooted:
        ebpf_reason = "Connected device is not rooted"
        ebpf_rem = "Root device and push static bpftrace to /data/local/tmp/bpftrace."
    elif not primary.has_bpftrace:
        ebpf_reason = "bpftrace binary not found on device"
        ebpf_rem = "Push static ARM64 bpftrace to /data/local/tmp/bpftrace."
    else:
        ebpf_reason = ""
        ebpf_rem = ""
    engines.append(
        EngineStatus(
            name="ebpf",
            available=ebpf_avail,
            recommended=False,
            reason=ebpf_reason,
            remediation=ebpf_rem,
        )
    )

    for eng in engines:
        checks.append(
            DiagnosticCheck(
                id=f"engine_{eng.name}",
                category="engine",
                name=f"Engine: {eng.name}",
                status="pass" if eng.available else "warn",
                summary="ready" if eng.available else eng.reason,
                remediation=eng.remediation,
            )
        )

    has_fail = any(c.status == "fail" for c in checks)
    has_warn = any(c.status == "warn" for c in checks)
    overall = "unhealthy" if has_fail else ("degraded" if has_warn else "healthy")

    return DoctorReport(
        overall_status=overall,
        python_version=py_ver,
        unpack_version=UNPACK_VERSION,
        checks=checks,
        devices=devices,
        engines=engines,
    )
