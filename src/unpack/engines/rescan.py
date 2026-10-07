from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from unpack.utils.apk import validate_package_name

# Suffix -> component type. Order doesn't matter since suffixes are
# mutually exclusive in practice (a class name ends with at most one
# of these).
_COMPONENT_TYPE_SUFFIXES: list[tuple[str, str]] = [
    ("Activity", "activity"),
    ("Service", "service"),
    ("Receiver", "receiver"),
    ("Provider", "provider"),
]

# Fully-qualified (or relative, leading-dot) Java class name.
_CLASS_NAME_RE = re.compile(r"^\.?[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+$")


@dataclass
class RescanPlan:
    dex_targets: list[str] = field(default_factory=list)
    nop_count: int = 0
    components: list[dict] = field(default_factory=list)


@dataclass
class RescanResult:
    success: bool = False
    rounds: int = 0
    methods_recovered: int = 0
    methods_still_nop: int = 0
    error: str | None = None


class ComponentExtractor:
    """Classifies Android component class names (Activity / Service /
    Receiver / Provider) by suffix, and can pull candidate names out of
    an APK's AndroidManifest.xml."""

    def classify_components(self, strings: list[str]) -> list[dict]:
        """Classify a flat list of (possibly noisy) strings into app
        components. Non-class-name strings and unrecognized suffixes
        are dropped. Duplicates are collapsed."""
        seen: set[str] = set()
        components: list[dict] = []

        for raw in strings:
            name = (raw or "").strip()
            if not name or name in seen:
                continue
            if not _CLASS_NAME_RE.match(name):
                continue

            comp_type = self._classify_one(name)
            if comp_type is None:
                continue

            seen.add(name)
            components.append({"name": name, "type": comp_type})

        return components

    def _classify_one(self, name: str) -> str | None:
        for suffix, comp_type in _COMPONENT_TYPE_SUFFIXES:
            if name.endswith(suffix):
                return comp_type
        return None

    def extract_manifest_strings(self, apk_path: Path) -> list[str]:
        """Best-effort extraction of component class names from an APK.

        Prefers androguard (which parses AndroidManifest.xml properly
        and returns exactly the declared activities/services/receivers/
        providers). Falls back to a raw scan of the binary XML string
        pool when androguard isn't installed or fails to parse.
        """
        names = self._extract_via_androguard(apk_path)
        if names:
            return names
        return self._extract_manifest_strings_fallback(apk_path)

    def _extract_via_androguard(self, apk_path: Path) -> list[str]:
        try:
            import os as _os
            _os.environ.setdefault("LOGURU_LEVEL", "ERROR")
            try:
                from loguru import logger as _lg
                _lg.disable("androguard")
            except ImportError:
                pass
            from androguard.core.apk import APK
        except ImportError:
            return []

        try:
            a = APK(str(apk_path))
        except Exception:
            return []

        names: list[str] = []
        for getter in ("get_activities", "get_services", "get_receivers", "get_providers"):
            try:
                names.extend(getattr(a, getter)())
            except Exception:
                continue
        return names

    def _extract_manifest_strings_fallback(self, apk_path: Path) -> list[str]:
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                data = zf.read("AndroidManifest.xml")
        except (KeyError, zipfile.BadZipFile, FileNotFoundError, OSError):
            return []

        from unpack.utils.apk import _parse_string_pool

        return _parse_string_pool(data)


class RescanPlanner:
    """Reads a previous dump's report.json and decides which DEX files
    are worth re-scanning (those with NOP-only methods)."""

    def plan(self, report_path: Path) -> RescanPlan:
        plan = RescanPlan()

        if not report_path.exists():
            return plan

        try:
            data = json.loads(report_path.read_text())
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            return plan

        for entry in data.get("per_dex", []):
            nop = entry.get("nop_methods", 0) or 0
            if nop <= 0:
                continue
            file_name = entry.get("file")
            if file_name:
                plan.dex_targets.append(file_name)
            plan.nop_count += nop

        return plan


class IncrementalRescanner:
    """Triggers app components via `am` to force class/method loading
    (and thus packer decryption), then re-scans the still-running
    process's memory for newly-decrypted DEX -- without force-stopping
    or relaunching the app, which would discard any progress."""

    def __init__(
        self,
        rounds: int = 3,
        trigger_delay: float = 1.0,
        settle_delay: float = 2.0,
    ):
        self._rounds = rounds
        self._trigger_delay = trigger_delay
        self._settle_delay = settle_delay

    def rescan(
        self,
        serial: str,
        package_name: str,
        plan: RescanPlan,
        output_dir: Path,
    ) -> RescanResult:
        result = RescanResult()

        if not plan.components:
            result.error = "no components to trigger"
            return result

        try:
            # package_name originates from untrusted APK metadata and is
            # interpolated into `am start/startservice/broadcast -n ...`
            # and `pidof ...` shell commands below -- validate up front so
            # neither helper ever builds a command from an unsafe value.
            validate_package_name(package_name)

            from unpack.core.reporter import Reporter

            reporter = Reporter()
            baseline_nop = plan.nop_count
            result.methods_still_nop = baseline_nop

            for round_num in range(self._rounds):
                for component in plan.components:
                    self._trigger_component(serial, package_name, component)
                    time.sleep(self._trigger_delay)

                result.rounds += 1
                time.sleep(self._settle_delay)

                self._rescan_pid_memory(serial, package_name, output_dir, round_num)

                report = reporter.evaluate(output_dir)
                if report.nop_methods < result.methods_still_nop:
                    result.methods_still_nop = report.nop_methods
                if report.nop_methods <= 0:
                    break

            result.methods_recovered = max(0, baseline_nop - result.methods_still_nop)
            result.success = result.methods_recovered > 0
            if not result.success and not result.error:
                result.error = (
                    f"no additional methods decrypted after triggering "
                    f"{len(plan.components)} component(s) over {result.rounds} round(s)"
                )
        except Exception as exc:
            result.error = str(exc)

        return result

    def _trigger_component(self, serial: str, package_name: str, component: dict):
        comp_type = component.get("type")
        name = component.get("name")
        if not name:
            return

        target = f"{shlex.quote(package_name)}/{name}"

        try:
            if comp_type == "activity":
                subprocess.run(
                    ["adb", "-s", serial, "shell", "am", "start", "-n", target],
                    timeout=10, capture_output=True,
                )
            elif comp_type == "service":
                subprocess.run(
                    ["adb", "-s", serial, "shell", "am", "startservice", "-n", target],
                    timeout=10, capture_output=True,
                )
            elif comp_type == "receiver":
                subprocess.run(
                    ["adb", "-s", serial, "shell", "am", "broadcast", "-n", target],
                    timeout=10, capture_output=True,
                )
            elif comp_type == "provider":
                subprocess.run(
                    ["adb", "-s", serial, "shell", "content", "query",
                     "--uri", f"content://{name}"],
                    timeout=10, capture_output=True,
                )
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, OSError):
            pass

    def _rescan_pid_memory(
        self, serial: str, package_name: str, output_dir: Path, round_num: int,
    ):
        try:
            # `adb shell <args...>` joins its arguments into a single
            # command line executed by a shell on the DEVICE side, so this
            # list-form subprocess call is just as exploitable as an
            # f-string built shell command -- quote defensively.
            pid_out = subprocess.check_output(
                ["adb", "-s", serial, "shell", "pidof", shlex.quote(package_name)],
                text=True, timeout=5,
            ).strip()
            pid = pid_out.split()[0]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, IndexError, OSError):
            return

        try:
            maps_text = subprocess.check_output(
                ["adb", "-s", serial, "shell", "su", "-c", f"cat /proc/{pid}/maps"],
                text=True, timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            return

        output_dir.mkdir(parents=True, exist_ok=True)
        idx = 0
        for line in maps_text.splitlines():
            parts = line.split()
            if not parts:
                continue
            path = parts[-1] if len(parts) > 5 else ""
            if "[anon:dalvik-" not in line and not any(
                k in path for k in (".vdex", ".apk", ".dex")
            ):
                continue
            if any(k in path for k in ("/system/", "/apex/", "/vendor/", "/product/")):
                continue

            addr_range = parts[0]
            try:
                start_hex, end_hex = addr_range.split("-")
                start = int(start_hex, 16)
                end = int(end_hex, 16)
            except ValueError:
                continue

            size = end - start
            if size < 256 or size > 256 * 1024 * 1024:
                continue

            data = self._read_region(serial, pid, start, min(size, 50 * 1024 * 1024))
            if len(data) < 112 or data[:4] not in (b"dex\n", b"cdex"):
                continue

            out_path = output_dir / f"rescan_r{round_num:02d}_{idx:03d}.dex"
            out_path.write_bytes(data)
            idx += 1

    def _read_region(self, serial: str, pid: str, addr: int, size: int) -> bytes:
        bs = 4096
        skip_blocks = addr // bs
        offset = addr % bs
        blocks = (size + offset + bs - 1) // bs
        try:
            raw = subprocess.check_output(
                ["adb", "-s", serial, "shell", "su", "-c",
                 f"dd if=/proc/{pid}/mem bs={bs} skip={skip_blocks} count={blocks} 2>/dev/null"],
                timeout=30,
            )
            return raw[offset:offset + size]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            return b""
