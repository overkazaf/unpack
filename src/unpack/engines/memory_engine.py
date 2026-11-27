from __future__ import annotations

import base64
import shlex
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from unpack.engines.base import BaseEngine, DumpResult, EngineType
from unpack.logging_config import get_logger
from unpack.utils.adb import (
    adb_cmd,
    adb_shell,
    check_root,
    get_device_serial,
    parse_dex_map_regions,
    read_proc_mem,
    validate_pid,
)
from unpack.utils.apk import validate_package_name

log = get_logger(__name__)

DEVICE_DUMP_DIR = "/data/local/tmp/unpack_memscan"
DEVICE_SCRIPT_PATH = "/data/local/tmp/unpack_memscan.sh"


def _find_child_pids(serial: str, parent_pid: str) -> list[str]:
    """Find child PIDs of parent_pid via pgrep -P (for multi-process packers)."""
    try:
        safe_pid = validate_pid(parent_pid)
        out = adb_shell(serial, f"pgrep -P {safe_pid}", root=True, timeout=5)
        return [p.strip() for p in out.splitlines() if p.strip().isdigit()]
    except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        log.debug("Failed to list child PIDs for %s: %s", parent_pid, exc)
        return []


def _sliding_dex_scan(data: bytes, max_scan: int = 1024 * 1024) -> list[int]:
    """Search for DEX magic ("dex\\n") at any offset within the first
    max_scan bytes of data, validating the DEX header at each match.

    Used to find DEX files embedded at arbitrary offsets within anonymous
    memory regions (DEX-in-DEX), as done by some packers.
    """
    offsets = []
    search_len = min(len(data), max_scan)
    pos = 0
    while pos < search_len - 44:
        idx = data.find(b"dex\n", pos, search_len)
        if idx < 0:
            break
        if idx + 44 <= len(data):
            try:
                fsize = struct.unpack_from("<I", data, idx + 32)[0]
                hsize = struct.unpack_from("<I", data, idx + 36)[0]
                endian = struct.unpack_from("<I", data, idx + 40)[0]
                if (hsize == 0x70 and fsize >= 112 and fsize <= 100 * 1024 * 1024
                    and endian in (0x12345678, 0x78563412)):
                    offsets.append(idx)
            except struct.error:
                pass
        pos = idx + 4
    return offsets


class MemoryEngine(BaseEngine):
    engine_type = EngineType.MEMORY

    def __init__(self, wait_seconds: int = 8):
        self._wait_seconds = wait_seconds
        self._serial: str | None = None
        self._unavailable_reason: str | None = None

    def is_available(self) -> bool:
        serial = get_device_serial()
        if not serial:
            self._unavailable_reason = "no ADB device connected"
            return False
        self._serial = serial

        if not check_root(serial):
            self._unavailable_reason = (
                "device is not rooted -- memory engine requires root "
                "for /proc/pid/mem access (adb shell su -c id must return uid=0)"
            )
            return False

        return True

    @property
    def unavailable_reason(self) -> str | None:
        return self._unavailable_reason

    def dump(
        self,
        package_name: str,
        output_dir: Path,
        device_serial: str | None = None,
    ) -> DumpResult:
        result = DumpResult(engine=self.engine_type)
        t0 = time.monotonic_ns()
        serial = device_serial or self._serial or get_device_serial()

        if not serial:
            result.error = "no ADB device connected"
            result.duration_ms = int((time.monotonic_ns() - t0) / 1_000_000)
            return result

        try:
            result = self._do_dump(serial, package_name, output_dir, result)
        except Exception as exc:
            result.error = str(exc)
        finally:
            self._cleanup(serial)
            result.duration_ms = int((time.monotonic_ns() - t0) / 1_000_000)

        return result

    def _do_dump(
        self,
        serial: str,
        package_name: str,
        output_dir: Path,
        result: DumpResult,
    ) -> DumpResult:
        # package_name originates from untrusted APK metadata (see
        # dispatcher.dispatch) and is interpolated into shell commands below
        # -- validate before it ever touches a command string.
        validate_package_name(package_name)
        safe_pkg = shlex.quote(package_name)

        try:
            adb_shell(serial, f"am force-stop {safe_pkg}", root=False, timeout=5)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

        time.sleep(1)

        try:
            adb_shell(
                serial,
                f"monkey -p {safe_pkg} -c android.intent.category.LAUNCHER 1",
                root=False, timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            result.error = f"failed to launch {package_name}"
            return result

        time.sleep(2)  # brief grace period for process to spawn

        try:
            pid_out = adb_shell(serial, f"pidof {safe_pkg}", root=False, timeout=5)
            pid = validate_pid(pid_out.strip().split()[0])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, IndexError, ValueError):
            result.error = f"process not found for {package_name}"
            return result

        from unpack.utils.wait import SmartWaiter
        waiter = SmartWaiter(
            max_wait=max(float(self._wait_seconds), 15.0),
            min_wait=max(3.0, float(self._wait_seconds) / 3),
        )
        waiter.wait(serial, pid)

        all_pids = [pid]
        child_pids = _find_child_pids(serial, pid)
        all_pids.extend(child_pids)

        output_dir.mkdir(parents=True, exist_ok=True)
        seen_hashes: set[str] = set()
        total_targets = 0

        for raw_pid in all_pids:
            try:
                scan_pid = validate_pid(raw_pid)
                maps_text = adb_shell(
                    serial, f"cat /proc/{scan_pid}/maps", root=True, timeout=10
                )
            except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                log.debug("Failed reading /proc/%s/maps: %s", raw_pid, exc)
                continue

            regions = parse_dex_map_regions(maps_text)
            targets = [(r.start, r.size, r.path, r.perms) for r in regions]

            total_targets += len(targets)
            if not targets:
                continue

            dump_cmds: list[tuple[int, int, str]] = []

            # Batch-read all region headers in one script
            probe_script = "#!/system/bin/sh\n"
            for region_start, region_size, _, _ in targets:
                probe_script += (
                    f"dd if=/proc/{scan_pid}/mem bs=1 skip={region_start} count=256 "
                    "2>/dev/null | base64\necho '---PROBE_SEP---'\n"
                )

            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                f.write(probe_script)
                probe_path = f.name
            try:
                adb_cmd(serial, "push", probe_path, "/data/local/tmp/_probe.sh", timeout=10)
                probe_out = adb_shell(
                    serial, "sh /data/local/tmp/_probe.sh", root=True, timeout=60
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                probe_out = ""
            finally:
                Path(probe_path).unlink(missing_ok=True)
                try:
                    adb_shell(serial, "rm -f /data/local/tmp/_probe.sh", root=True, timeout=5)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass

            probe_chunks = probe_out.split("---PROBE_SEP---")

            for i, (region_start, region_size, region_path, region_perms) in enumerate(targets):
                if i >= len(probe_chunks):
                    break
                try:
                    header = base64.b64decode(probe_chunks[i].strip())
                except Exception:
                    continue
                if len(header) < 40:
                    continue

                first_dex_off = -1
                if header[:4] == b"dex\n":
                    first_dex_off = 0
                elif header[:4] == b"cdex":
                    first_dex_off = 0
                elif header[:4] == b"vdex":
                    for voff in range(40, min(len(header) - 4, 200)):
                        if header[voff : voff + 4] == b"dex\n":
                            first_dex_off = voff
                            break
                elif header[:4] == b"oat\n":
                    for oat_off in range(28, min(len(header) - 4, 200)):
                        if header[oat_off : oat_off + 4] == b"dex\n":
                            first_dex_off = oat_off
                            break

                if first_dex_off < 0 and region_size >= 4096:
                    is_anon_rw = "rw" in region_perms
                    path_info = region_path
                    if is_anon_rw and (not path_info or path_info.startswith("[anon:")):
                        scan_size = min(region_size, 65536)
                        if scan_size > len(header):
                            extended = self._read_mem(serial, scan_pid, region_start, scan_size)
                        else:
                            extended = header
                        dex_offsets = _sliding_dex_scan(extended, max_scan=scan_size)
                        if dex_offsets:
                            first_dex_off = dex_offsets[0]

                if first_dex_off < 0:
                    continue

                pos = first_dex_off
                while pos < region_size - 112:
                    dex_addr = region_start + pos
                    if pos < len(header) - 40:
                        hdr = header[pos : pos + 40]
                    else:
                        hdr = self._read_mem(serial, scan_pid, dex_addr, 40)
                    if len(hdr) < 40 or hdr[:4] != b"dex\n":
                        break
                    fsize = struct.unpack_from("<I", hdr, 32)[0]
                    hsize = struct.unpack_from("<I", hdr, 36)[0]
                    if hsize != 0x70 or fsize < 112 or fsize > 100 * 1024 * 1024:
                        break

                    dk = f"{fsize}_{hdr[:32].hex()}"
                    if dk in seen_hashes:
                        pos += fsize
                        pos = (pos + 3) & ~3
                        continue
                    seen_hashes.add(dk)

                    dump_cmds.append((dex_addr, fsize, scan_pid))

                    pos += fsize
                    pos = (pos + 3) & ~3

            for dex_addr, fsize, dump_pid in dump_cmds:
                local_path = output_dir / f"classes_{len(result.dex_files):03d}.dex"
                self._dump_mem_to_file(serial, dump_pid, dex_addr, fsize, local_path)
                if local_path.exists() and local_path.stat().st_size > 112:
                    data = local_path.read_bytes()
                    if data[:4] == b"dex\n" or data[:4] == b"cdex":
                        result.dex_files.append(local_path)
                    else:
                        local_path.unlink(missing_ok=True)

        result.success = len(result.dex_files) > 0
        if not result.success and not result.error:
            result.error = (
                f"no DEX files found in {total_targets} memory regions across "
                f"{len(all_pids)} process(es) -- "
                "app may not be packed, or packer clears DEX after loading"
            )
        return result

    def _read_mem(self, serial: str, pid: str, addr: int, size: int) -> bytes:
        try:
            return read_proc_mem(serial, pid, addr, size, block_size=1, timeout=10)
        except ValueError as exc:
            log.debug("_read_mem rejected invalid pid %r: %s", pid, exc)
            return b""

    def _dump_mem_to_file(
        self, serial: str, pid: str, addr: int, size: int, local_path: Path,
    ):
        try:
            data = read_proc_mem(serial, pid, addr, size, block_size=4096, timeout=60)
            if len(data) > 112:
                local_path.write_bytes(data)
        except (ValueError, OSError) as exc:
            log.debug("_dump_mem_to_file failed for pid=%s addr=%#x: %s", pid, addr, exc)

    def _cleanup(self, serial: str):
        for path in (DEVICE_SCRIPT_PATH, DEVICE_DUMP_DIR):
            try:
                adb_shell(serial, f"rm -rf {shlex.quote(path)}", root=True, timeout=5)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                log.debug("MemoryEngine cleanup ignored for %s: %s", path, exc)
