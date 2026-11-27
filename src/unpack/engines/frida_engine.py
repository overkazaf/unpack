from __future__ import annotations

import time
from pathlib import Path

from unpack.engines.base import BaseEngine, DumpResult, EngineType
from unpack.engines.frida_scripts import (
    FRIDA_ANTI_DETECT_JS,
    check_frida_usb_available,
    format_frida_error,
)
from unpack.logging_config import get_logger
from unpack.utils.apk import validate_package_name
from unpack.utils.fs import sanitize_filename

log = get_logger(__name__)

_FRIDA_DUMP_BODY = r"""
// ════════════════════════════════════════════════
// DEX dump engine
// ════════════════════════════════════════════════

var collected = {};
var dexIndex = 0;
var soIndex = 0;
var collectedSo = {};

// Full 8-byte magic patterns
var dexMagicPatterns = [
    '64 65 78 0a 30 33 35 00',  // dex\n035\0
    '64 65 78 0a 30 33 37 00',  // dex\n037\0
    '64 65 78 0a 30 33 38 00',  // dex\n038\0
    '64 65 78 0a 30 33 39 00',  // dex\n039\0
    '64 65 78 0a 30 34 31 00',  // dex\n041\0
];

function isDexMagic(ptr) {
    try {
        var b = ptr.readByteArray(4);
        if (!b) return false;
        var a = new Uint8Array(b);
        return a[0] === 0x64 && a[1] === 0x65 && a[2] === 0x78 && a[3] === 0x0a;
    } catch (e) {}
    return false;
}

function validateDexHeader(addr) {
    try {
        var fileSize = addr.add(32).readU32();
        if (fileSize < 112 || fileSize > 100 * 1024 * 1024) return 0;
        var headerSize = addr.add(36).readU32();
        if (headerSize !== 0x70) return 0;
        var endianTag = addr.add(40).readU32();
        if (endianTag !== 0x12345678 && endianTag !== 0x78563412) return 0;
        // Sanity: string_ids_off should be within file
        var stringIdsOff = addr.add(60).readU32();
        if (stringIdsOff > fileSize) return 0;
        return fileSize;
    } catch (e) {
        return 0;
    }
}

function saveDex(base, size, tag) {
    var key = base.toString() + ':' + size;
    if (collected[key]) return;
    collected[key] = true;
    try {
        var buf = base.readByteArray(size);
        dexIndex++;
        send({ type: 'dex', index: dexIndex, size: size, tag: tag }, buf);
    } catch (e) {
        send({ type: 'error', message: 'Failed to read DEX at ' + base + ': ' + e });
    }
}

// ── Strategy 1: Memory scan ──

function scanMemory() {
    var found = 0;
    Process.enumerateRanges('r--').forEach(function (range) {
        if (range.size < 112) return;
        // Skip system regions
        if (range.file && range.file.path) {
            var p = range.file.path;
            if (p.indexOf('/system/') === 0 ||
                p.indexOf('/apex/') === 0 ||
                p.indexOf('/vendor/') === 0) return;
        }
        for (var m = 0; m < dexMagicPatterns.length; m++) {
            try {
                Memory.scan(range.base, range.size, dexMagicPatterns[m], {
                    onMatch: function (addr, sz) {
                        var fileSize = validateDexHeader(addr);
                        if (fileSize > 0) {
                            saveDex(addr, fileSize, 'memory_scan');
                            found++;
                        }
                    },
                    onError: function () {},
                    onComplete: function () {}
                });
            } catch (e) {}
        }
    });
    return found;
}

// ── Strategy 2: Hook DexFile loading ──

function hookDexFileOpen() {
    var libart = Process.findModuleByName('libart.so');
    if (!libart) return;

    var hooked = 0;
    var symbols = libart.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var sym = symbols[i];
        if (sym.name.indexOf('OpenCommon') !== -1 ||
            sym.name.indexOf('OpenMemory') !== -1 ||
            (sym.name.indexOf('DexFile') !== -1 &&
             sym.name.indexOf('Open') !== -1 &&
             sym.name.indexOf('OpenDex') === -1)) {
            try {
                (function (symName) {
                    Interceptor.attach(sym.address, {
                        onEnter: function (args) {
                            for (var a = 0; a < 5; a++) {
                                try {
                                    if (isDexMagic(args[a])) {
                                        var fileSize = validateDexHeader(args[a]);
                                        if (fileSize > 0) {
                                            saveDex(args[a], fileSize, 'dexfile_open:' + symName);
                                        }
                                        break;
                                    }
                                } catch (e) {}
                            }
                        }
                    });
                    hooked++;
                })(sym.name);
            } catch (e) {}
        }
    }
    return hooked;
}

// ── Strategy 5: ClassLinker::DefineClass hook (FART-style) ──

function hookClassLinkerDefineClass() {
    var libart = Process.findModuleByName('libart.so');
    if (!libart) return 0;

    var hooked = 0;
    var symbols = libart.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
        var sym = symbols[i];
        if (sym.name.indexOf('DefineClass') !== -1 &&
            sym.name.indexOf('ClassLinker') !== -1 &&
            sym.name.indexOf('__cfi_') === -1) {
            try {
                (function(symName) {
                    Interceptor.attach(sym.address, {
                        onEnter: function(args) {
                            // ClassLinker::DefineClass has DexFile as one of its args.
                            // The DexFile object's begin_ field points to the DEX data.
                            // Try multiple arg positions to find it.
                            for (var a = 0; a < 8; a++) {
                                try {
                                    var candidate = args[a];
                                    if (candidate.isNull()) continue;
                                    // Try direct: arg might be DEX base pointer
                                    if (isDexMagic(candidate)) {
                                        var fileSize = validateDexHeader(candidate);
                                        if (fileSize > 0) {
                                            saveDex(candidate, fileSize, 'define_class:' + symName);
                                        }
                                        break;
                                    }
                                    // Try indirect: arg might be DexFile*, with begin_ as first field
                                    var beginPtr = candidate.readPointer();
                                    if (!beginPtr.isNull() && isDexMagic(beginPtr)) {
                                        var fileSize = validateDexHeader(beginPtr);
                                        if (fileSize > 0) {
                                            saveDex(beginPtr, fileSize, 'define_class:' + symName);
                                        }
                                        break;
                                    }
                                } catch (e) {}
                            }
                        }
                    });
                    hooked++;
                })(sym.name);
            } catch (e) {}
            break;  // Only hook the first match to avoid duplicate captures
        }
    }
    return hooked;
}

// ── Strategy 3: ClassLoader enumeration ──

function dumpClassLoaders() {
    var found = 0;
    try {
        Java.perform(function () {
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        var pathList = loader.pathList;
                        if (!pathList) return;
                        var value = pathList.value;
                        var dexElements = value.dexElements.value;
                        for (var i = 0; i < dexElements.length; i++) {
                            var element = dexElements[i];
                            var dexFile = element.dexFile.value;
                            if (!dexFile) continue;
                            var cookie = dexFile.mCookie.value;
                            if (!cookie) continue;
                            var arr = Java.array('long', cookie);
                            for (var j = 0; j < arr.length; j++) {
                                var addr = ptr(arr[j]);
                                if (isDexMagic(addr)) {
                                    var fileSize = validateDexHeader(addr);
                                    if (fileSize > 0) {
                                        saveDex(addr, fileSize, 'classloader');
                                        found++;
                                    }
                                }
                            }
                        }
                    } catch (e) {}
                },
                onComplete: function () {}
            });

            // Also try: Java-level hideFridaClasses (deferred from antiDetect)
            if (antiDetect.enabled) {
                try {
                    var CL = Java.use('java.lang.ClassLoader');
                    CL.loadClass.overload('java.lang.String').implementation = function (name) {
                        if (name && (name.indexOf('frida') !== -1 ||
                                     name.indexOf('xposed') !== -1 ||
                                     name.indexOf('de.robv.') !== -1)) {
                            throw Java.use('java.lang.ClassNotFoundException').$new(name);
                        }
                        return this.loadClass(name);
                    };
                } catch (e) {}
            }
        });
    } catch (e) {}
    return found;
}

// ── Strategy 4: SO dump via dlopen hook ──

function hookDlopen() {
    var targets = ['dlopen', 'android_dlopen_ext'];
    targets.forEach(function (fname) {
        var addr = Module.findExportByName(null, fname);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter: function (args) {
                try { this._soPath = args[0].readUtf8String(); }
                catch (e) { this._soPath = null; }
            },
            onLeave: function (retval) {
                if (!this._soPath || retval.isNull()) return;
                var p = this._soPath;
                if (p.indexOf('/system/') === 0 ||
                    p.indexOf('/apex/') === 0 ||
                    p.indexOf('/vendor/') === 0 ||
                    p.indexOf('libc.so') !== -1 ||
                    p.indexOf('libc++') !== -1 ||
                    p.indexOf('libm.so') !== -1 ||
                    p.indexOf('libdl.so') !== -1 ||
                    p.indexOf('liblog.so') !== -1 ||
                    p.indexOf('libandroid') !== -1) return;
                if (collectedSo[p]) return;
                collectedSo[p] = true;
                try {
                    var mod = Process.findModuleByName(p.split('/').pop());
                    if (!mod) return;
                    var size = mod.size;
                    if (size < 64 || size > 200 * 1024 * 1024) return;
                    var buf = mod.base.readByteArray(size);
                    soIndex++;
                    send({ type: 'so', index: soIndex, size: size, name: mod.name, path: p }, buf);
                } catch (e) {}
            }
        });
    });
}


// ════════════════════════════════════════════════
// Orchestration — polling approach
//
// 1. Arm hooks IMMEDIATELY (before resume)
// 2. On resume, poll memory every 2s
// 3. After WAIT_SECONDS, final sweep + done
// ════════════════════════════════════════════════

var WAIT_SECONDS = UNPACK_WAIT_PLACEHOLDER;
var scanRound = 0;

// Arm all hooks right now (process is still suspended)
send({ type: 'status', message: 'Arming hooks (process still paused)...' });
var hookedSymbols = hookDexFileOpen();
var classLinkerHooks = hookClassLinkerDefineClass();
hookDlopen();
send({ type: 'status', message: 'Hooks armed: ' + hookedSymbols + ' DexFile + ' + classLinkerHooks + ' ClassLinker + dlopen' });

// Polling loop: runs after the process is resumed
function pollScan() {
    scanRound++;
    var found = scanMemory();
    send({ type: 'status', message: 'Scan round ' + scanRound + ': ' + found + ' new DEX (total ' + dexIndex + ')' });

    if (scanRound * 2 < WAIT_SECONDS) {
        setTimeout(pollScan, 2000);
    } else {
        // Final round: ClassLoader enum + last memory scan
        send({ type: 'status', message: 'Final sweep: ClassLoader enum...' });
        var clFound = dumpClassLoaders();
        var memFound = scanMemory();
        send({ type: 'status', message: 'Final sweep: +' + clFound + ' classloader, +' + memFound + ' memory' });
        send({ type: 'done', dexTotal: dexIndex, soTotal: soIndex });
    }
}

// Start polling 1s after resume to let the packer begin unpacking
setTimeout(pollScan, 1000);
"""

_FRIDA_SCRIPT = "'use strict';\n" + FRIDA_ANTI_DETECT_JS + "\nantiDetect.apply();\n" + _FRIDA_DUMP_BODY


class FridaEngine(BaseEngine):
    engine_type = EngineType.FRIDA

    def __init__(self, anti_detect: bool = True, wait_seconds: int = 15):
        self._anti_detect = anti_detect
        self._wait_seconds = wait_seconds
        self._frida = None
        self._unavailable_reason: str | None = None

    def is_available(self) -> bool:
        available, frida_mod, reason = check_frida_usb_available(timeout=3.0)
        self._frida = frida_mod
        self._unavailable_reason = reason
        return available

    def dump(
        self,
        package_name: str,
        output_dir: Path,
        device_serial: str | None = None,
    ) -> DumpResult:
        result = DumpResult(engine=self.engine_type)
        t0 = time.monotonic_ns()

        try:
            # package_name originates from untrusted APK metadata. frida's
            # device.spawn() takes argv as a list (not shell-interpreted) so
            # this isn't a shell-injection vector today, but we validate
            # anyway for defense-in-depth and to fail fast with a clear error
            # instead of an opaque Frida spawn failure on a malformed name.
            validate_package_name(package_name)

            frida = self._frida
            if frida is None:
                import frida as _frida
                frida = _frida

            if device_serial:
                device = frida.get_device(device_serial, timeout=5)
            else:
                device = frida.get_usb_device(timeout=5)

            pid = device.spawn([package_name])
            session = device.attach(pid)

            script_src = _FRIDA_SCRIPT.replace(
                "UNPACK_WAIT_PLACEHOLDER", str(self._wait_seconds)
            )
            if not self._anti_detect:
                script_src = script_src.replace(
                    "antiDetect.apply();", "// antiDetect disabled"
                )

            output_dir.mkdir(parents=True, exist_ok=True)
            dex_files: list[Path] = []
            so_files: list[Path] = []
            process_alive = True

            def on_message(message, data):
                nonlocal process_alive
                if message["type"] == "send":
                    payload = message["payload"]
                    if payload.get("type") == "dex" and data:
                        idx = int(payload.get("index", len(dex_files) + 1))
                        raw_tag = str(payload.get("tag", "unknown"))
                        safe_tag = sanitize_filename(raw_tag, fallback="unknown", max_length=64)
                        out = output_dir / f"classes_{idx:03d}_{safe_tag}.dex"
                        out.write_bytes(data)
                        dex_files.append(out)
                    elif payload.get("type") == "so" and data:
                        so_dir = output_dir / "so"
                        so_dir.mkdir(parents=True, exist_ok=True)
                        idx = int(payload.get("index", len(so_files) + 1))
                        raw_name = str(payload.get("name", f"lib_{idx:03d}.so"))
                        safe_name = sanitize_filename(raw_name, fallback=f"lib_{idx:03d}.so")
                        out = so_dir / safe_name
                        out.write_bytes(data)
                        so_files.append(out)
                elif message["type"] == "error":
                    process_alive = False
                    log.debug("Frida script error message: %s", message.get("description", ""))

            script = session.create_script(script_src)
            script.on("message", on_message)
            script.load()

            # Resume AFTER hooks are armed
            device.resume(pid)

            from unpack.utils.adb import get_device_serial as _get_serial
            from unpack.utils.wait import SmartWaiter

            _serial = device_serial or _get_serial()
            if _serial:
                waiter = SmartWaiter(
                    max_wait=max(float(self._wait_seconds), 15.0) + 2,
                    min_wait=max(3.0, float(self._wait_seconds) / 3),
                )
                waiter.wait(_serial, str(pid))
            else:
                time.sleep(self._wait_seconds + 2)

            try:
                script.unload()
            except Exception as exc:
                log.debug("Frida script unload ignored: %s", exc)
            try:
                device.kill(pid)
            except Exception as exc:
                log.debug("Frida process kill ignored for pid=%s: %s", pid, exc)

            result.dex_files = dex_files
            result.so_files = so_files
            result.success = len(dex_files) > 0
            if not dex_files:
                if not process_alive:
                    result.error = (
                        "Target process died during dump — packer likely detected "
                        "Frida despite anti-detection. Try --engine memory or --engine ebpf"
                    )
                else:
                    result.error = "No DEX files captured — packer may have blocked injection"

        except Exception as exc:
            result.error = format_frida_error(exc)
            log.debug("FridaEngine.dump failed for %s: %s", package_name, exc)

        result.duration_ms = int((time.monotonic_ns() - t0) / 1_000_000)
        return result
