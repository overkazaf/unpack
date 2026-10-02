from __future__ import annotations

import re
import struct
import zipfile
from pathlib import Path


def get_package_name(apk_path: Path) -> str | None:
    try:
        from androguard.core.apk import APK
        a = APK(str(apk_path))
        return a.get_package()
    except ImportError:
        pass

    return _parse_package_from_binary_manifest(apk_path)


def _parse_package_from_binary_manifest(apk_path: Path) -> str | None:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            data = zf.read("AndroidManifest.xml")
    except (KeyError, zipfile.BadZipFile):
        return None

    return _extract_package_from_axml(data)


def _extract_package_from_axml(data: bytes) -> str | None:
    if len(data) < 8:
        return None

    strings = _parse_string_pool(data)
    if not strings:
        return None

    pkg_attr_name = "package"
    for i, s in enumerate(strings):
        if s == pkg_attr_name:
            for j in range(i + 1, min(i + 10, len(strings))):
                candidate = strings[j]
                if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", candidate):
                    return candidate
            break

    for s in strings:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*){2,}$", s):
            return s

    return None


def _parse_string_pool(data: bytes) -> list[str]:
    if len(data) < 28:
        return []

    magic = struct.unpack_from("<H", data, 0)[0]
    if magic != 0x0003:
        off = data.find(b"\x01\x00\x1c\x00")
        if off < 0:
            return []
        data = data[off:]

    if len(data) < 28:
        return []

    str_count = struct.unpack_from("<I", data, 8)[0]
    flags = struct.unpack_from("<I", data, 16)[0]
    str_start = struct.unpack_from("<I", data, 20)[0]

    if str_count > 100000 or str_count == 0:
        return []

    is_utf8 = (flags & (1 << 8)) != 0
    offsets_start = 28
    strings = []

    for i in range(min(str_count, 10000)):
        off_pos = offsets_start + i * 4
        if off_pos + 4 > len(data):
            break
        str_off = struct.unpack_from("<I", data, off_pos)[0]
        abs_off = str_start + str_off

        if abs_off >= len(data):
            break

        try:
            if is_utf8:
                pos = abs_off
                b = data[pos]
                pos += 2 if b & 0x80 else 1
                char_len = data[pos]
                pos += 2 if char_len & 0x80 else 1
                end = data.index(0, pos)
                strings.append(data[pos:end].decode("utf-8", errors="replace"))
            else:
                char_count = struct.unpack_from("<H", data, abs_off)[0]
                if char_count & 0x8000:
                    char_count = ((char_count & 0x7FFF) << 16) | struct.unpack_from("<H", data, abs_off + 2)[0]
                    start = abs_off + 4
                else:
                    start = abs_off + 2
                raw = data[start:start + char_count * 2]
                strings.append(raw.decode("utf-16-le", errors="replace"))
        except (IndexError, ValueError, UnicodeDecodeError):
            strings.append("")

    return strings


def list_apk_files(apk_path: Path, prefix: str = "") -> list[str]:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            return [n for n in zf.namelist() if n.startswith(prefix)]
    except zipfile.BadZipFile:
        return []


def pull_all_splits(
    package_name: str,
    device_serial: str | None,
    output_dir: Path,
) -> list[Path]:
    import subprocess

    cmd_base = ["adb"]
    if device_serial:
        cmd_base += ["-s", device_serial]

    try:
        out = subprocess.check_output(
            cmd_base + ["shell", "pm", "path", package_name],
            text=True, timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return []

    pulled: list[Path] = []
    for line in out.strip().splitlines():
        device_path = line.strip().removeprefix("package:")
        if not device_path:
            continue
        name = Path(device_path).name
        local_path = output_dir / name
        try:
            subprocess.check_call(
                cmd_base + ["pull", device_path, str(local_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120,
            )
            if local_path.exists():
                pulled.append(local_path)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue

    return pulled


def find_sibling_splits(apk_path: Path) -> list[Path]:
    parent = apk_path.parent
    splits = sorted(parent.glob("split_*.apk"))
    return [s for s in splits if s != apk_path]


def merge_apk_entries(apk_paths: list[Path]) -> dict[str, Path]:
    merged: dict[str, Path] = {}
    for apk in apk_paths:
        try:
            with zipfile.ZipFile(apk, "r") as zf:
                for name in zf.namelist():
                    if name not in merged:
                        merged[name] = apk
        except zipfile.BadZipFile:
            continue
    return merged
