from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from unpack.logging_config import get_logger
from unpack.utils.fs import file_sha256

log = get_logger(__name__)

_SIGNATURE_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC")


def _is_signature_entry(filename: str) -> bool:
    if not filename.startswith("META-INF/"):
        return False
    upper = filename.upper()
    return upper == "META-INF/MANIFEST.MF" or upper.endswith(_SIGNATURE_SUFFIXES)


@dataclass
class RepackResult:
    success: bool = False
    output_path: Path | None = None
    dex_count: int = 0
    resources_preserved: int = 0
    signatures_stripped: int = 0
    output_size_bytes: int = 0
    output_sha256: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output_path": str(self.output_path) if self.output_path else None,
            "dex_count": self.dex_count,
            "resources_preserved": self.resources_preserved,
            "signatures_stripped": self.signatures_stripped,
            "output_size_bytes": self.output_size_bytes,
            "output_sha256": self.output_sha256,
            "error": self.error,
        }


class Repacker:
    """Combines an original APK with dumped/repaired DEX files into a new APK.

    No device needed: this is purely a zip-level operation that strips the
    original (encrypted/packed) classes*.dex entries (and optionally stale
    META-INF v1 signature files) and substitutes the dumped DEX files, while
    preserving every other resource unchanged.
    """

    def repack(
        self,
        original_apk: Path,
        dex_dir: Path,
        output_dir: Path,
        strip_signatures: bool = True,
    ) -> RepackResult:
        result = RepackResult()

        if not original_apk.exists():
            result.error = f"APK not found: {original_apk}"
            return result

        dex_files = sorted(dex_dir.glob("*.dex"))
        if not dex_files:
            result.error = f"No DEX files in {dex_dir}"
            return result

        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{original_apk.stem}_unpacked.apk"

        try:
            with zipfile.ZipFile(original_apk, "r") as src, \
                 zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as dst:
                for item in src.infolist():
                    if item.filename.startswith("classes") and item.filename.endswith(".dex"):
                        continue
                    if strip_signatures and _is_signature_entry(item.filename):
                        result.signatures_stripped += 1
                        continue
                    dst.writestr(item, src.read(item.filename))
                    result.resources_preserved += 1

                for i, dex_path in enumerate(dex_files):
                    name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
                    dst.writestr(name, dex_path.read_bytes())
                    result.dex_count += 1
        except (zipfile.BadZipFile, OSError) as e:
            result.error = str(e)
            return result

        result.success = True
        result.output_path = output_path
        try:
            result.output_size_bytes = output_path.stat().st_size
            result.output_sha256 = file_sha256(output_path)
        except OSError as exc:
            log.debug("Failed computing output stats for %s: %s", output_path, exc)
        return result
