from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

from unpack.core.scanner import ProtectionLevel, ScanResult
from unpack.engines.base import BaseEngine, DumpOptions, DumpResult, EngineType
from unpack.engines.ebpf_engine import EbpfEngine
from unpack.engines.frida_engine import FridaEngine
from unpack.engines.memory_engine import MemoryEngine
from unpack.logging_config import get_logger
from unpack.utils.apk import get_package_name, validate_package_name

log = get_logger(__name__)

_ENGINE_PRIORITY: dict[ProtectionLevel, list[EngineType]] = {
    ProtectionLevel.NONE: [EngineType.FRIDA, EngineType.EBPF, EngineType.MEMORY],
    ProtectionLevel.DEX_ENCRYPTION: [EngineType.EBPF, EngineType.FRIDA, EngineType.MEMORY],
    ProtectionLevel.FUNCTION_EXTRACTION: [EngineType.EBPF, EngineType.FRIDA, EngineType.MEMORY],
    ProtectionLevel.VMP: [EngineType.EBPF, EngineType.FRIDA],
    ProtectionLevel.DEX2C: [EngineType.EBPF, EngineType.FRIDA],
}


class Dispatcher:
    def __init__(
        self,
        quiet: bool = False,
        on_event: Callable[[str, str], None] | None = None,
    ):
        self._quiet = quiet
        self._on_event = on_event
        self._engines: dict[EngineType, BaseEngine] = {
            EngineType.EBPF: EbpfEngine(),
            EngineType.FRIDA: FridaEngine(),
            EngineType.MEMORY: MemoryEngine(),
        }

    def _emit(self, level: str, plain: str, rich_msg: str | None = None) -> None:
        if level == "warn":
            log.warning("%s", plain)
        else:
            log.info("%s", plain)
        if self._on_event is not None:
            self._on_event(level, plain)
        elif not self._quiet:
            sys.stdout.write(f"  {plain}\n")
            sys.stdout.flush()

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
        package_name = get_package_name(apk)
        if not package_name:
            return DumpResult(
                engine=EngineType.FRIDA,
                error="Could not extract package name from APK",
            )

        # package_name comes straight from an untrusted APK's manifest. This
        # is the single chokepoint every engine.dump() call flows through, so
        # validating here protects all engines even if a malicious APK's
        # package name contains shell metacharacters (e.g. "com.evil;reboot").
        try:
            validate_package_name(package_name)
        except ValueError as exc:
            return DumpResult(
                engine=EngineType.FRIDA,
                error=f"Refusing to dispatch: {exc}",
            )

        self._emit("info", f"Package: {package_name}", f"  Package: [cyan]{package_name}[/]")

        if scan_result.protection_level in (ProtectionLevel.VMP, ProtectionLevel.DEX2C):
            warn_plain = (
                f"{scan_result.protection_level.value} protection detected — "
                "full automatic unpack is unlikely. Attempting partial dump."
            )
            self._emit(
                "warn",
                warn_plain,
                f"  [yellow]Warning:[/] {warn_plain}",
            )

        options = DumpOptions(timeout=timeout, anti_detect=anti_detect)
        for eng in self._engines.values():
            if hasattr(eng, "configure"):
                eng.configure(options)

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

        last_failure: DumpResult | None = None
        tried: set[EngineType] = set()
        skipped_reasons: list[str] = []

        # Try engines in priority order; if all fail/unavailable, allow Memory as last-resort partial fallback
        candidate_order = list(priority)
        if EngineType.MEMORY not in candidate_order:
            candidate_order.append(EngineType.MEMORY)

        for idx, engine_type in enumerate(candidate_order):
            is_last_resort = idx >= len(priority)
            engine = self._engines.get(engine_type)
            if not engine:
                continue
            if not engine.is_available():
                reason = getattr(engine, "unavailable_reason", None) or "unavailable"
                skipped_reasons.append(f"{engine_type.value}: {reason}")
                self._emit(
                    "warn",
                    f"Engine {engine_type.value} skipped ({reason})",
                    f"  [dim]Skip {engine_type.value}: {reason}[/]",
                )
                continue

            tried.add(engine_type)
            if is_last_resort:
                self._emit(
                    "warn",
                    f"All primary engines failed/unavailable; falling back to {engine_type.value} (root /proc/pid/mem scan)...",
                    f"  [yellow]Fallback:[/] using [green]{engine_type.value}[/] for partial memory dump",
                )
            else:
                self._emit("info", f"Engine: {engine_type.value}", f"  Engine: [green]{engine_type.value}[/]")

            res = engine.dump(package_name, output_dir, device_serial)
            if res.success or res.dex_files:
                return res
            last_failure = res
            self._emit(
                "warn",
                f"Engine {engine_type.value} failed ({res.error or 'no DEX captured'}); trying next available engine...",
                f"  [yellow]Fallback:[/] {engine_type.value} failed, trying next engine...",
            )

        if last_failure is not None:
            return last_failure

        detail = "; ".join(skipped_reasons) if skipped_reasons else "install frida and connect a rooted device"
        return DumpResult(
            engine=EngineType.FRIDA,
            error=f"No available engine — {detail}",
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
            reason = getattr(engine, "unavailable_reason", None)
            msg = f"Engine {engine_type.value} is not available"
            if reason:
                msg = f"{msg}: {reason}"
            return DumpResult(
                engine=engine_type,
                error=msg,
            )
        self._emit(
            "info",
            f"Engine: {engine_type.value} (forced)",
            f"  Engine: [green]{engine_type.value}[/] (forced)",
        )
        return engine.dump(package_name, output_dir, device_serial)
