from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class EngineType(Enum):
    FRIDA = "frida"
    MEMORY = "memory"
    EBPF = "ebpf"


@dataclass
class DumpOptions:
    """Typed runtime configuration passed from Dispatcher to dump engines."""

    timeout: int | None = None
    anti_detect: bool = True


@dataclass
class DumpResult:
    engine: EngineType
    dex_files: list[Path] = field(default_factory=list)
    so_files: list[Path] = field(default_factory=list)
    success: bool = False
    error: str | None = None
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "engine": self.engine.value,
            "dex_files": [str(p) for p in self.dex_files],
            "so_files": [str(p) for p in self.so_files],
            "success": self.success,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


class BaseEngine(ABC):
    engine_type: EngineType
    _unavailable_reason: str | None = None

    @property
    def unavailable_reason(self) -> str | None:
        """Human-readable explanation when :meth:`is_available` returns ``False``."""
        return self._unavailable_reason

    def configure(self, options: DumpOptions) -> None:
        """Apply runtime dump options without mutating private attributes externally."""
        if options.timeout is not None and options.timeout > 0 and hasattr(self, "_wait_seconds"):
            self._wait_seconds = options.timeout
        if hasattr(self, "_anti_detect"):
            self._anti_detect = options.anti_detect

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @abstractmethod
    def dump(
        self,
        package_name: str,
        output_dir: Path,
        device_serial: str | None = None,
    ) -> DumpResult:
        ...
