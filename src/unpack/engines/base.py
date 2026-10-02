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
class DumpResult:
    engine: EngineType
    dex_files: list[Path] = field(default_factory=list)
    so_files: list[Path] = field(default_factory=list)
    success: bool = False
    error: str | None = None
    duration_ms: int = 0


class BaseEngine(ABC):
    engine_type: EngineType

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
