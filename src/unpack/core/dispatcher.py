from __future__ import annotations

import re
import struct
import zipfile
from pathlib import Path

from rich.console import Console

from unpack.core.scanner import ProtectionLevel, ScanResult
from unpack.engines.base import BaseEngine, DumpResult, EngineType
from unpack.engines.ebpf_engine import EbpfEngine
from unpack.engines.frida_engine import FridaEngine
from unpack.engines.memory_engine import MemoryEngine

console = Console()

_ENGINE_PRIORITY: dict[ProtectionLevel, list[EngineType]] = {
    ProtectionLevel.NONE: [EngineType.FRIDA, EngineType.EBPF, EngineType.MEMORY],
    ProtectionLevel.DEX_ENCRYPTION: [EngineType.EBPF, EngineType.FRIDA, EngineType.MEMORY],
    ProtectionLevel.FUNCTION_EXTRACTION: [EngineType.EBPF, EngineType.FRIDA, EngineType.MEMORY],
    ProtectionLevel.VMP: [EngineType.EBPF, EngineType.FRIDA],
    ProtectionLevel.DEX2C: [EngineType.EBPF, EngineType.FRIDA],
}


def _extract_package_name(apk_path: Path) -> str | None:
    """Extract the package name from an APK's binary AndroidManifest.xml."""
    try:
        from androguard.core.apk import APK

        return APK(str(apk_path)).get_package()
    except Exception:
        pass

    # Fallback: parse the binary XML for the 'package' attribute.
    # In AXML the package string sits right after the manifest element tag and
    # is preceded by a UTF-16LE length-prefixed string.  A practical heuristic
    # is to search for the UTF-16LE encoded "package" attribute name and grab
    # the string value that follows it.
    try:
        with zipfile.ZipFile(apk_path) as zf:
            data = zf.read("AndroidManifest.xml")

        # The AXML string pool stores UTF-16LE strings.  We scan for the raw
        # bytes of typical package names (com.xxx.yyy) which appear as ASCII
        # within the pool (each char followed by 0x00).
        text = data.decode("latin-1")
        # Look for patterns like "com.something.something"
        matches = re.findall(
            r"((?:com|cn|net|org|io)\.[a-z0-9_]+(?:\.[a-z0-9_]+)+)", text
        )
        if matches:
            return matches[0]

        # Even rougher: try stripping null bytes and matching
        stripped = data.replace(b"\x00", b"").decode("latin-1", errors="replace")
        matches = re.findall(
            r"((?:com|cn|net|org|io)\.[a-z0-9_]+(?:\.[a-z0-9_]+)+)", stripped
        )
        if matches:
            return matches[0]
    except Exception:
        pass

    return None


class Dispatcher:
    def __init__(self):
        self._engines: dict[EngineType, BaseEngine] = {
            EngineType.EBPF: EbpfEngine(),
            EngineType.FRIDA: FridaEngine(),
            EngineType.MEMORY: MemoryEngine(),
        }

    def dispatch(
        self,
        apk: Path,
        scan_result: ScanResult,
        output_dir: Path,
        device_serial: str | None = None,
        force_engine: str | None = None,
        timeout: int | None = None,
        anti_detect: bool = True,
    ) -> DumpResult:
        package_name = _extract_package_name(apk)
        if not package_name:
            return DumpResult(
                engine=EngineType.FRIDA,
                error="Could not extract package name from APK",
            )

        console.print(f"  Package: [cyan]{package_name}[/]")

        if scan_result.protection_level in (ProtectionLevel.VMP, ProtectionLevel.DEX2C):
            console.print(
                f"  [yellow]Warning:[/] {scan_result.protection_level.value} protection "
                "detected — full automatic unpack is unlikely. Attempting partial dump."
            )

        if timeout:
            for eng in self._engines.values():
                if hasattr(eng, "_wait_seconds"):
                    eng._wait_seconds = timeout

        if not anti_detect:
            for eng in self._engines.values():
                if hasattr(eng, "_anti_detect"):
                    eng._anti_detect = False

        if force_engine:
            try:
                engine_type = EngineType(force_engine.lower())
            except ValueError:
                return DumpResult(
                    engine=EngineType.FRIDA,
                    error=f"Unknown engine: {force_engine}",
                )
            return self._run_engine(engine_type, package_name, output_dir, device_serial)

        priority = _ENGINE_PRIORITY.get(
            scan_result.protection_level,
            [EngineType.FRIDA],
        )

        for engine_type in priority:
            engine = self._engines.get(engine_type)
            if engine and engine.is_available():
                console.print(f"  Engine: [green]{engine_type.value}[/]")
                return engine.dump(package_name, output_dir, device_serial)

        return DumpResult(
            engine=EngineType.FRIDA,
            error="No available engine — install frida and connect a device",
        )

    def _run_engine(
        self,
        engine_type: EngineType,
        package_name: str,
        output_dir: Path,
        device_serial: str | None,
    ) -> DumpResult:
        engine = self._engines.get(engine_type)
        if not engine:
            return DumpResult(
                engine=engine_type,
                error=f"Engine {engine_type.value} is not registered",
            )
        if not engine.is_available():
            return DumpResult(
                engine=engine_type,
                error=f"Engine {engine_type.value} is not available",
            )
        console.print(f"  Engine: [green]{engine_type.value}[/] (forced)")
        return engine.dump(package_name, output_dir, device_serial)
