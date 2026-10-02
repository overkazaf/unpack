from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from unpack.engines.base import BaseEngine, DumpResult, EngineType
from unpack.utils.adb import get_device_serial

DEVICE_DUMP_DIR = "/data/local/tmp/unpack_memscan"
DEVICE_SCRIPT_PATH = "/data/local/tmp/unpack_memscan.sh"

_MEMSCAN_SCRIPT = r"""#!/system/bin/sh
# UNPACK memory-scan DEX/SO dumper (optimised)
# Usage: sh unpack_memscan.sh <package> <outdir> [wait_secs] [scan_timeout]
PKG="$1"; OUTDIR="$2"; WAIT="${3:-8}"; SCAN_TIMEOUT="${4:-60}"

[ -z "$PKG" ] || [ -z "$OUTDIR" ] && { echo "MEMSCAN_ERR: usage: $0 <pkg> <outdir> [wait] [timeout]"; exit 1; }

mkdir -p "$OUTDIR" "$OUTDIR/so"

am force-stop "$PKG" 2>/dev/null; sleep 1
monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
echo "MEMSCAN: launched $PKG, waiting ${WAIT}s..."
sleep "$WAIT"

PID=$(pidof "$PKG" 2>/dev/null | awk '{print $1}')
[ -z "$PID" ] && { echo "MEMSCAN_ERR: process not found"; exit 1; }
echo "MEMSCAN: pid=$PID"

MAPS="/proc/$PID/maps"
MEM="/proc/$PID/mem"
IDX=0; SO_IDX=0
SEEN=""
START_TS=$(date +%s)

hex2dec() {
    # Convert hex string to decimal, handling 64-bit values on Android
    # toybox printf can't handle %lu, use bc instead
    HEX=$(echo "$1" | tr 'a-f' 'A-F')
    echo "ibase=16; $HEX" | bc 2>/dev/null || echo 0
}

read_le32_at() {
    # Read LE uint32 at given decimal offset from /proc/pid/mem
    RAW=$(dd if="$MEM" bs=1 skip="$1" count=4 2>/dev/null | od -A n -t x1 2>/dev/null | tr -d ' \n')
    [ ${#RAW} -lt 8 ] && echo 0 && return
    HEX="${RAW:6:2}${RAW:4:2}${RAW:2:2}${RAW:0:2}"
    HEX_UPPER=$(echo "$HEX" | tr 'a-f' 'A-F')
    echo "ibase=16; $HEX_UPPER" | bc 2>/dev/null || echo 0
}

check_timeout() {
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TS))
    [ "$ELAPSED" -gt "$SCAN_TIMEOUT" ] && { echo "MEMSCAN: timeout after ${ELAPSED}s"; exit 0; }
}

# ── Phase 1: DEX dump ──
# Only scan regions likely to contain unpacked DEX:
#   - *.vdex / *.apk mapped files (not under /system/ /apex/ /vendor/)
#   - [anon:dalvik-* anonymous mappings (runtime allocations)
#   - anonymous rw regions (packers often mmap DEX into anonymous pages)
grep -E '\.vdex|\.apk|\[anon:dalvik|\[anon:\.bss|r..p 00000000 00:00 0' "$MAPS" | \
grep -v '/system/\|/apex/\|/vendor/\|/product/\|jit-\|boot\.\|dalvik-main space\|dalvik-free list\|dalvik-large\|dalvik-Sentinel\|dalvik-Card\|dalvik-Mark\|dalvik-Region\|dalvik-live stack\|dalvik-allocspace\|LinearAlloc' | \
while IFS= read -r LINE; do
    check_timeout

    RANGE=$(echo "$LINE" | awk '{print $1}')
    START_HEX=${RANGE%%-*}
    END_HEX=${RANGE##*-}
    START_DEC=$(hex2dec "$START_HEX") || continue
    END_DEC=$(hex2dec "$END_HEX") || continue
    [ "$START_DEC" = "0" ] && continue
    [ "$END_DEC" = "0" ] && continue
    REGION_SIZE=$((END_DEC - START_DEC))

    [ "$REGION_SIZE" -lt 256 ] && continue
    [ "$REGION_SIZE" -gt 268435456 ] && continue

    # Check for DEX magic at region start
    MAGIC=$(dd if="$MEM" bs=1 skip="$START_DEC" count=4 2>/dev/null | od -A n -t x1 2>/dev/null | tr -d ' \n')
    case "$MAGIC" in
        6465780a) ;;
        *)
            # For VDEX files: DEX is embedded after a header.
            # VDEX magic is "vdex" (76 64 65 78). Try to find DEX inside.
            case "$MAGIC" in
                7664657[08])
                    # Scan at known VDEX header offsets (varies by version)
                    for VOFF in 28 32 36 40 64; do
                        INNER=$(dd if="$MEM" bs=1 skip=$((START_DEC + VOFF)) count=4 2>/dev/null | od -A n -t x1 2>/dev/null | tr -d ' \n')
                        case "$INNER" in
                            6465780a)
                                START_DEC=$((START_DEC + VOFF))
                                REGION_SIZE=$((REGION_SIZE - VOFF))
                                MAGIC="6465780a"
                                break
                                ;;
                        esac
                    done
                    [ "$MAGIC" != "6465780a" ] && continue
                    ;;
                *) continue ;;
            esac
            ;;
    esac

    FILE_SIZE=$(read_le32_at $((START_DEC + 32)))
    [ "$FILE_SIZE" -lt 112 ] && continue
    [ "$FILE_SIZE" -gt 104857600 ] && continue
    [ "$FILE_SIZE" -gt "$REGION_SIZE" ] && FILE_SIZE="$REGION_SIZE"

    # Validate header_size (offset 36) should be 0x70 = 112
    HDR_SIZE=$(read_le32_at $((START_DEC + 36)))
    [ "$HDR_SIZE" -ne 112 ] && continue

    # Dedup by file_size + first 32 bytes
    DEDUP=$(dd if="$MEM" bs=1 skip="$START_DEC" count=32 2>/dev/null | od -A n -t x1 2>/dev/null | tr -d ' \n')
    DKEY="${FILE_SIZE}_${DEDUP}"
    case "$SEEN" in *"$DKEY"*) continue ;; esac
    SEEN="$SEEN|$DKEY"

    OUTFILE="$OUTDIR/mem_$(printf '%03d' $IDX).dex"
    dd if="$MEM" bs=4096 skip=$((START_DEC / 4096)) count=$(( (FILE_SIZE + 4095) / 4096 )) 2>/dev/null | \
        dd bs=1 skip=$((START_DEC % 4096)) count="$FILE_SIZE" of="$OUTFILE" 2>/dev/null

    if [ -s "$OUTFILE" ]; then
        FMAGIC=$(od -A n -t x1 -N 4 "$OUTFILE" 2>/dev/null | tr -d ' \n')
        if [ "$FMAGIC" = "6465780a" ]; then
            echo "MEMSCAN_DEX: $OUTFILE size=$FILE_SIZE base=0x$START_HEX"
            IDX=$((IDX + 1))
        else
            rm -f "$OUTFILE"
        fi
    else
        rm -f "$OUTFILE"
    fi
done

echo "MEMSCAN_DONE: dumped $IDX DEX file(s)"

# ── Phase 2: SO dump (decrypted native libs) ──
check_timeout
SO_SEEN=""
grep 'r-xp' "$MAPS" | \
grep -v '/system/\|/apex/\|/vendor/\|/product/\|libc\.so\|libc++\|libm\.so\|libdl\.so\|liblog\.so\|libz\.so\|linker' | \
grep '/data/' | \
while IFS= read -r LINE; do
    check_timeout

    PATHNAME=$(echo "$LINE" | awk '{print $6}')
    [ -z "$PATHNAME" ] && continue
    case "$SO_SEEN" in *"$PATHNAME"*) continue ;; esac
    SO_SEEN="$SO_SEEN|$PATHNAME"

    RANGE=$(echo "$LINE" | awk '{print $1}')
    START_HEX=${RANGE%%-*}; END_HEX=${RANGE##*-}
    START_DEC=$(printf '%d' "0x$START_HEX" 2>/dev/null) || continue
    END_DEC=$(printf '%d' "0x$END_HEX" 2>/dev/null) || continue
    SIZE=$((END_DEC - START_DEC))

    [ "$SIZE" -lt 64 ] && continue
    [ "$SIZE" -gt 209715200 ] && continue

    HEADER=$(dd if="$MEM" bs=1 skip="$START_DEC" count=4 2>/dev/null | od -A n -t x1 2>/dev/null | tr -d ' \n')
    [ "$HEADER" != "7f454c46" ] && continue

    SO_NAME=$(basename "$PATHNAME")
    SO_FILE="$OUTDIR/so/$SO_NAME"
    dd if="$MEM" bs=4096 skip=$((START_DEC / 4096)) count=$(( (SIZE + 4095) / 4096 )) 2>/dev/null | \
        dd bs=1 skip=$((START_DEC % 4096)) count="$SIZE" of="$SO_FILE" 2>/dev/null

    [ -s "$SO_FILE" ] && { echo "MEMSCAN_SO: $SO_FILE size=$SIZE path=$PATHNAME"; SO_IDX=$((SO_IDX + 1)); } || rm -f "$SO_FILE"
done

echo "MEMSCAN_SO_DONE: dumped $SO_IDX SO file(s)"
"""


def _adb(serial: str, *args: str, timeout: int = 15) -> str:
    cmd = ["adb", "-s", serial, *args]
    return subprocess.check_output(
        cmd, text=True, timeout=timeout, stderr=subprocess.STDOUT
    ).strip()


def _adb_shell(serial: str, cmd: str, timeout: int = 30, root: bool = False) -> str:
    if root:
        cmd = f"su -c '{cmd}'"
    return _adb(serial, "shell", cmd, timeout=timeout)


def _check_root(serial: str) -> bool:
    try:
        out = _adb_shell(serial, "id", root=True)
        return "uid=0" in out
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


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

        if not _check_root(serial):
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
        import struct

        try:
            _adb_shell(serial, f"am force-stop {package_name}", root=False, timeout=5)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

        time.sleep(1)

        try:
            _adb_shell(
                serial,
                f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1",
                root=False, timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            result.error = f"failed to launch {package_name}"
            return result

        time.sleep(self._wait_seconds)

        try:
            pid_out = _adb_shell(serial, f"pidof {package_name}", root=False, timeout=5)
            pid = pid_out.strip().split()[0]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, IndexError):
            result.error = f"process not found for {package_name}"
            return result

        maps_text = _adb_shell(serial, f"cat /proc/{pid}/maps", root=True, timeout=10)

        targets = []
        for line in maps_text.splitlines():
            parts = line.split()
            if len(parts) < 1:
                continue
            path = parts[-1] if len(parts) > 5 else ""
            if not any(k in path for k in [".vdex", ".apk", ".dex"]):
                if "[anon:dalvik-" not in line:
                    continue
            if any(k in path for k in ["/system/", "/apex/", "/vendor/", "/product/"]):
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
            targets.append((start, size, path))

        output_dir.mkdir(parents=True, exist_ok=True)
        seen_hashes: set[str] = set()
        dump_cmds: list[tuple[int, int, str]] = []

        # Batch-read all region headers in one script
        probe_script = "#!/system/bin/sh\n"
        for region_start, region_size, _ in targets:
            probe_script += f"dd if=/proc/{pid}/mem bs=1 skip={region_start} count=256 2>/dev/null | base64\necho '---PROBE_SEP---'\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write(probe_script)
            probe_path = f.name
        try:
            _adb(serial, "push", probe_path, "/data/local/tmp/_probe.sh", timeout=10)
            probe_out = _adb_shell(serial, "sh /data/local/tmp/_probe.sh", root=True, timeout=60)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            probe_out = ""
        finally:
            Path(probe_path).unlink(missing_ok=True)
            try:
                _adb_shell(serial, "rm -f /data/local/tmp/_probe.sh", root=True, timeout=5)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass

        import base64
        probe_chunks = probe_out.split("---PROBE_SEP---")

        for i, (region_start, region_size, _) in enumerate(targets):
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
            elif header[:4] == b"vdex":
                for voff in range(40, min(len(header) - 4, 200)):
                    if header[voff : voff + 4] == b"dex\n":
                        first_dex_off = voff
                        break

            if first_dex_off < 0:
                continue

            # Walk consecutive DEX files using the initial header where possible
            pos = first_dex_off
            while pos < region_size - 112:
                dex_addr = region_start + pos
                if pos < len(header) - 40:
                    hdr = header[pos : pos + 40]
                else:
                    hdr = self._read_mem(serial, pid, dex_addr, 40)
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

                device_path = f"{DEVICE_DUMP_DIR}/classes_{len(dump_cmds):03d}.dex"
                dump_cmds.append((dex_addr, fsize, device_path))

                pos += fsize
                pos = (pos + 3) & ~3

        for dex_addr, fsize, _ in dump_cmds:
            local_path = output_dir / f"classes_{len(result.dex_files):03d}.dex"
            self._dump_mem_to_file(serial, pid, dex_addr, fsize, local_path)
            if local_path.exists() and local_path.stat().st_size > 112:
                data = local_path.read_bytes()
                if data[:4] == b"dex\n":
                    result.dex_files.append(local_path)
                else:
                    local_path.unlink(missing_ok=True)

        result.success = len(result.dex_files) > 0
        if not result.success and not result.error:
            result.error = (
                f"no DEX files found in {len(targets)} memory regions -- "
                "app may not be packed, or packer clears DEX after loading"
            )
        return result

    def _read_mem(self, serial: str, pid: str, addr: int, size: int) -> bytes:
        try:
            raw = subprocess.check_output(
                ["adb", "-s", serial, "shell", "su", "-c",
                 f"dd if=/proc/{pid}/mem bs=1 skip={addr} count={size} 2>/dev/null"],
                timeout=10,
            )
            return raw
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return b""

    def _dump_mem_to_file(
        self, serial: str, pid: str, addr: int, size: int, local_path: Path,
    ):
        bs = 4096
        skip_blocks = addr // bs
        offset = addr % bs
        blocks = (size + offset + bs - 1) // bs
        try:
            raw = subprocess.check_output(
                ["adb", "-s", serial, "shell", "su", "-c",
                 f"dd if=/proc/{pid}/mem bs={bs} skip={skip_blocks} count={blocks} 2>/dev/null"],
                timeout=60,
            )
            data = raw[offset : offset + size]
            if len(data) > 112:
                local_path.write_bytes(data)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    def _cleanup(self, serial: str):
        for path in (DEVICE_SCRIPT_PATH, DEVICE_DUMP_DIR):
            try:
                _adb_shell(serial, f"rm -rf {path}", root=True, timeout=5)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
