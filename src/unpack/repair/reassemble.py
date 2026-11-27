from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from unpack.logging_config import get_logger
from unpack.repair.dex_parser import DexFile

log = get_logger(__name__)

# Matches classes.dex, classes2.dex, classes10.dex, ... at the root of the APK zip.
_DEX_NAME_RE = re.compile(r"^classes\d*\.dex$")


class DexClassLister:
    """Extracts the list of class descriptors defined in a DEX file.

    Class descriptors look like ``Lcom/example/MyClass;`` (JVM/DEX type
    descriptor syntax).
    """

    def list_classes(self, dex_data: bytes) -> list[str]:
        """Parse raw DEX bytes and return the class descriptors it defines."""
        dex = DexFile.parse(dex_data)
        names: list[str] = []
        for cdef in dex.class_defs:
            name = dex.get_type_name(cdef.class_idx)
            if name:
                names.append(name)
        return names

    def list_from_file(self, dex_path: Path) -> list[str]:
        """Parse a DEX file on disk and return its class descriptors."""
        return self.list_classes(dex_path.read_bytes())

    def list_from_apk(self, apk_path: Path) -> dict[str, list[str]]:
        """Read every top-level ``classes*.dex`` entry from an APK.

        Returns a mapping of DEX entry name (e.g. ``classes.dex``,
        ``classes2.dex``) to the list of class descriptors it defines.
        DEX entries that fail to parse are kept with an empty class list
        rather than raising, so a single corrupt DEX doesn't abort the
        whole listing.
        """
        result: dict[str, list[str]] = {}
        with zipfile.ZipFile(apk_path) as zf:
            dex_names = sorted(n for n in zf.namelist() if _DEX_NAME_RE.match(n))
            for name in dex_names:
                data = zf.read(name)
                try:
                    result[name] = self.list_classes(data)
                except Exception as exc:
                    log.debug("DexClassLister skipping corrupt entry %s: %s", name, exc)
                    result[name] = []
        return result


class ClassMapper:
    """Maps classes found in dumped DEX files back to the original DEX
    file (within the original APK) that defined them.
    """

    def build_index(self, original: dict[str, list[str]]) -> dict[str, str]:
        """Build a reverse index: class descriptor -> original DEX name.

        If (unexpectedly) the same class descriptor appears in more than
        one original DEX file, the first DEX encountered (in dict
        iteration order) wins.
        """
        index: dict[str, str] = {}
        for dex_name, classes in original.items():
            for cls in classes:
                index.setdefault(cls, dex_name)
        return index

    def map_classes(
        self,
        original: dict[str, list[str]],
        dumped: dict[str, list[str]],
    ) -> dict[str, str | None]:
        """Map every class seen in the dumped DEX files to its original DEX.

        Returns a dict of class descriptor -> original DEX name, or
        ``None`` if the class wasn't present in the original APK (e.g. a
        dynamically generated or newly loaded class).
        """
        index = self.build_index(original)
        mapping: dict[str, str | None] = {}
        for classes in dumped.values():
            for cls in classes:
                mapping[cls] = index.get(cls)
        return mapping


@dataclass
class ReassembleResult:
    success: bool = False
    classes_mapped: int = 0
    classes_unmapped: int = 0
    output_files: list[str] = field(default_factory=list)
    error: str | None = None
