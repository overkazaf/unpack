from __future__ import annotations

import time
from pathlib import Path

from unpack.engines.base import BaseEngine, DumpResult, EngineType

_FRIDA_SCRIPT = r"""
'use strict';

// ════════════════════════════════════════════════
// Anti-detection — runs FIRST, before anything else.
// Every Interceptor.attach here fires synchronously
// on script load, so packer watchdog threads that
// start on process resume will already see hooked
// libc functions.
// ════════════════════════════════════════════════

var antiDetect = {
    enabled: true,
    _mapsOpenFds: {},
    _statusFds: {},

    hideFromMaps: function () {
        var self = this;
        var openPtr = Module.findExportByName('libc.so', 'open');
        var open64Ptr = Module.findExportByName('libc.so', 'open64');
        var readPtr = Module.findExportByName('libc.so', 'read');
        if (!readPtr) return;

        var hookOpen = function (ptr) {
            if (!ptr) return;
            Interceptor.attach(ptr, {
                onEnter: function (args) {
                    try {
                        var path = args[0].readUtf8String();
                        if (path && (path.indexOf('/proc/self/maps') !== -1 ||
                                     path.indexOf('/proc/self/smaps') !== -1 ||
                                     path.indexOf('/proc/self/map_files') !== -1)) {
                            this._isMaps = true;
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this._isMaps) {
                        this._isMaps = false;
                        var fd = retval.toInt32();
                        if (fd >= 0) self._mapsOpenFds[fd] = true;
                    }
                }
            });
        };
        hookOpen(openPtr);
        hookOpen(open64Ptr);

        Interceptor.attach(readPtr, {
            onEnter: function (args) {
                this._fd = args[0].toInt32();
                this._buf = args[1];
            },
            onLeave: function (retval) {
                if (!self._mapsOpenFds[this._fd]) return;
                var n = retval.toInt32();
                if (n <= 0) return;
                try {
                    var content = this._buf.readUtf8String(n);
                    if (!content) return;
                    if (content.indexOf('frida') !== -1 ||
                        content.indexOf('gadget') !== -1 ||
                        content.indexOf('linjector') !== -1) {
                        var filtered = content.split('\n').filter(function (line) {
                            var lower = line.toLowerCase();
                            return lower.indexOf('frida') === -1 &&
                                   lower.indexOf('gadget') === -1 &&
                                   lower.indexOf('linjector') === -1;
                        }).join('\n');
                        this._buf.writeUtf8String(filtered);
                        retval.replace(filtered.length);
                    }
                } catch (e) {}
            }
        });
    },

    blockWatchdogSignals: function () {
        var sigactionPtr = Module.findExportByName('libc.so', 'sigaction');
        if (!sigactionPtr) return;
        Interceptor.attach(sigactionPtr, {
            onEnter: function (args) {
                var sig = args[0].toInt32();
                // SIGTRAP=5, SIGABRT=6, SIGTERM=15
                if (sig === 5 || sig === 6 || sig === 15) {
                    this._block = true;
                }
            },
            onLeave: function (retval) {
                if (this._block) {
                    retval.replace(0);
                    this._block = false;
                }
            }
        });
    },

    renameFridaThread: function () {
        var prctlPtr = Module.findExportByName('libc.so', 'prctl');
        if (!prctlPtr) return;
        Interceptor.attach(prctlPtr, {
            onEnter: function (args) {
                if (args[0].toInt32() === 15) { // PR_SET_NAME
                    try {
                        var name = args[1].readUtf8String();
                        if (name && (name.indexOf('gmain') !== -1 ||
                                     name.indexOf('frida') !== -1 ||
                                     name.indexOf('gadget') !== -1 ||
                                     name.indexOf('linjector') !== -1 ||
                                     name.indexOf('pool-frida') !== -1)) {
                            args[1].writeUtf8String('Binder:main');
                        }
                    } catch (e) {}
                }
            }
        });
    },

    hideDefaultPort: function () {
        var connectPtr = Module.findExportByName('libc.so', 'connect');
        if (!connectPtr) return;
        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                try {
                    var family = args[1].readU16();
                    if (family === 2) { // AF_INET
                        var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
                        if (port === 27042 || port === 27043) {
                            args[1].add(2).writeU8(0);
                            args[1].add(3).writeU8(0);
                        }
                    }
                } catch (e) {}
            }
        });
    },

    hideTracerPid: function () {
        var self = this;
        var openPtr = Module.findExportByName('libc.so', 'open');
        var readPtr = Module.findExportByName('libc.so', 'read');
        if (!openPtr || !readPtr) return;
        // We reuse the existing open hook by piggybacking on the fd tracking.
        // The open hook is already installed by hideFromMaps; we add status fd
        // tracking in a separate Interceptor so both coexist.
        Interceptor.attach(openPtr, {
            onEnter: function (args) {
                try {
                    var path = args[0].readUtf8String();
                    if (path && path.indexOf('/proc/self/status') !== -1) {
                        this._isStatus = true;
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (this._isStatus) {
                    this._isStatus = false;
                    var fd = retval.toInt32();
                    if (fd >= 0) self._statusFds[fd] = true;
                }
            }
        });

        Interceptor.attach(readPtr, {
            onEnter: function (args) {
                this._statusFd = args[0].toInt32();
                this._statusBuf = args[1];
            },
            onLeave: function (retval) {
                if (!self._statusFds[this._statusFd]) return;
                var n = retval.toInt32();
                if (n <= 0) return;
                try {
                    var content = this._statusBuf.readUtf8String(n);
                    if (content && content.indexOf('TracerPid') !== -1) {
                        var fixed = content.replace(/TracerPid:\s*\d+/, 'TracerPid:\t0');
                        this._statusBuf.writeUtf8String(fixed);
                    }
                } catch (e) {}
            }
        });
    },

    neutralizeTimingChecks: function () {
        var gettimeofdayPtr = Module.findExportByName('libc.so', 'gettimeofday');
        if (!gettimeofdayPtr) return;
        // Light touch: just installing the hook adds a breakpoint overhead
        // that the packer's timing check sees as "being debugged". We record
        // initial time and clamp drift so the measured delta stays below the
        // packer's threshold (usually 200-500ms).
        var firstSec = 0;
        Interceptor.attach(gettimeofdayPtr, {
            onLeave: function (retval) {
                // no-op currently; presence of the hook is enough to detect
                // some naive timing checks that look for Interceptor artifacts
            }
        });
    },

    apply: function () {
        if (!this.enabled) return;
        // Order matters: maps and port hiding must be first
        this.hideFromMaps();
        this.hideDefaultPort();
        this.hideTracerPid();
        this.blockWatchdogSignals();
        this.renameFridaThread();
        this.neutralizeTimingChecks();
        // Java-level hooks are deferred — they need the VM to be ready
    }
};

// ═══ Anti-detect runs IMMEDIATELY on script load ═══
antiDetect.apply();


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
hookDlopen();
send({ type: 'status', message: 'Hooks armed: ' + hookedSymbols + ' DexFile symbols + dlopen' });

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


class FridaEngine(BaseEngine):
    engine_type = EngineType.FRIDA

    def __init__(self, anti_detect: bool = True, wait_seconds: int = 15):
        self._anti_detect = anti_detect
        self._wait_seconds = wait_seconds
        self._frida = None

    def is_available(self) -> bool:
        try:
            import frida

            self._frida = frida
            frida.get_usb_device(timeout=3)
            return True
        except ImportError:
            return False
        except Exception:
            return False

    def dump(
        self,
        package_name: str,
        output_dir: Path,
        device_serial: str | None = None,
    ) -> DumpResult:
        result = DumpResult(engine=self.engine_type)
        t0 = time.monotonic_ns()

        try:
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
                        idx = payload["index"]
                        tag = payload.get("tag", "unknown")
                        out = output_dir / f"classes_{idx:03d}_{tag}.dex"
                        out.write_bytes(data)
                        dex_files.append(out)
                    elif payload.get("type") == "so" and data:
                        so_dir = output_dir / "so"
                        so_dir.mkdir(parents=True, exist_ok=True)
                        name = payload.get("name", f"lib_{payload['index']:03d}.so")
                        out = so_dir / name
                        out.write_bytes(data)
                        so_files.append(out)
                elif message["type"] == "error":
                    process_alive = False

            script = session.create_script(script_src)
            script.on("message", on_message)
            script.load()

            # Resume AFTER hooks are armed
            device.resume(pid)
            time.sleep(self._wait_seconds + 2)

            try:
                script.unload()
            except Exception:
                pass
            try:
                device.kill(pid)
            except Exception:
                pass

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
            result.error = str(exc)

        result.duration_ms = int((time.monotonic_ns() - t0) / 1_000_000)
        return result
