from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RepackResult:
    success: bool = False
    output_path: Path | None = None
    dex_count: int = 0
    resources_preserved: int = 0
    error: str | None = None


class Repacker:
    """Combines an original APK with dumped/repaired DEX files into a new APK.

    No device needed: this is purely a zip-level operation that strips the
    original (encrypted/packed) classes*.dex entries and substitutes the
    dumped DEX files, while preserving every other resource unchanged.
    """

    def repack(self, original_apk: Path, dex_dir: Path, output_dir: Path) -> RepackResult:
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
        return result
