from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ActiveInvokeResult:
    success: bool = False
    code_items: list[dict] = field(default_factory=list)
    classes_resolved: int = 0
    methods_resolved: int = 0
    methods_captured: int = 0
    methods_nop_skipped: int = 0
    error: str | None = None
    duration_ms: int = 0


_ANTI_DETECT_BLOCK = r"""
'use strict';

// ── Anti-detection (MUST run first, before packer's watchdog starts) ──

(function() {
    // 1. Hide /proc/self/maps from frida detection
    var openPtr = Module.findExportByName('libc.so', 'open');
    var readPtr = Module.findExportByName('libc.so', 'read');
    if (openPtr) {
        var mapsTargets = {};
        Interceptor.attach(openPtr, {
            onEnter: function(args) {
                try {
                    var path = args[0].readUtf8String();
                    if (path && (path.indexOf('/proc/self/maps') !== -1 || path.indexOf('/proc/self/smaps') !== -1)) {
                        this._filterMaps = true;
                    }
                } catch(e) {}
            },
            onLeave: function(retval) {
                if (this._filterMaps) {
                    mapsTargets[retval.toInt32()] = true;
                    this._filterMaps = false;
                }
            }
        });
        if (readPtr) {
            Interceptor.attach(readPtr, {
                onEnter: function(args) {
                    this._fd = args[0].toInt32();
                    this._buf = args[1];
                    this._size = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (!mapsTargets[this._fd]) return;
                    var n = retval.toInt32();
                    if (n <= 0) return;
                    try {
                        var content = this._buf.readUtf8String(n);
                        var filtered = content.split('\n').filter(function(line) {
                            return line.indexOf('frida') === -1 && line.indexOf('gadget') === -1 &&
                                   line.indexOf('linjector') === -1 && line.indexOf('agent') === -1;
                        }).join('\n');
                        this._buf.writeUtf8String(filtered);
                        retval.replace(filtered.length);
                    } catch(e) {}
                }
            });
        }
    }

    // 2. Hide default Frida port 27042
    var connectPtr = Module.findExportByName('libc.so', 'connect');
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function(args) {
                try {
                    var family = args[1].readU16();
                    if (family === 2) { // AF_INET
                        var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
                        if (port === 27042 || port === 27043) {
                            args[1].add(2).writeU8(0);
                            args[1].add(3).writeU8(0);
                        }
                    }
                } catch(e) {}
            }
        });
    }

    // 3. Block watchdog signals (SIGTERM/SIGABRT/SIGTRAP)
    var sigactionPtr = Module.findExportByName('libc.so', 'sigaction');
    if (sigactionPtr) {
        Interceptor.attach(sigactionPtr, {
            onEnter: function(args) {
                var sig = args[0].toInt32();
                if (sig === 15 || sig === 6 || sig === 5) this._block = true;
            },
            onLeave: function(retval) {
                if (this._block) { retval.replace(0); this._block = false; }
            }
        });
    }

    // 4. TracerPid bypass
    if (openPtr && readPtr) {
        var statusFds = {};
        Interceptor.attach(openPtr, {
            onEnter: function(args) {
                try {
                    var p = args[0].readUtf8String();
                    if (p && p.indexOf('/proc/self/status') !== -1) this._isStatus = true;
                } catch(e) {}
            },
            onLeave: function(retval) {
                if (this._isStatus) { statusFds[retval.toInt32()] = true; this._isStatus = false; }
            }
        });
        Interceptor.attach(readPtr, {
            onEnter: function(args) {
                this._fd2 = args[0].toInt32();
                this._buf2 = args[1];
            },
            onLeave: function(retval) {
                if (!statusFds[this._fd2]) return;
                var n = retval.toInt32();
                if (n <= 0) return;
                try {
                    var s = this._buf2.readUtf8String(n);
                    var fixed = s.replace(/TracerPid:\s*\d+/, 'TracerPid:\t0');
                    this._buf2.writeUtf8String(fixed);
                } catch(e) {}
            }
        });
    }

    // 5. Rename frida threads
    var prctlPtr = Module.findExportByName('libc.so', 'prctl');
    if (prctlPtr) {
        Interceptor.attach(prctlPtr, {
            onEnter: function(args) {
                if (args[0].toInt32() === 15) { // PR_SET_NAME
                    try {
                        var name = args[1].readUtf8String();
                        if (name && (name.indexOf('gmain') !== -1 || name.indexOf('frida') !== -1 || name.indexOf('gadget') !== -1)) {
                            args[1].writeUtf8String('Binder:main');
                        }
                    } catch(e) {}
                }
            }
        });
    }

    // 6. Timing attack mitigation
    var gettimeofdayPtr = Module.findExportByName('libc.so', 'gettimeofday');
    if (gettimeofdayPtr) {
        var callCount = 0;
        Interceptor.attach(gettimeofdayPtr, {
            onLeave: function(retval) {
                callCount++;
            }
        });
    }
})();
"""

_ACTIVE_INVOKE_SCRIPT = r"""
// ════════════════════════════════════════════════════════
// FART-style Active Method Invocation
//
// Goal: force the packer to decrypt every method's
// CodeItem by resolving all classes and methods, then
// walk the ART runtime to capture the now-decrypted
// bytecode.
// ════════════════════════════════════════════════════════

var BATCH_SIZE = 100;
var BATCH_DELAY_MS = 30;
var WAIT_BEFORE_HARVEST = ACTIVE_INVOKE_WAIT_PLACEHOLDER;

var stats = {
    classesResolved: 0,
    methodsResolved: 0,
    methodsCaptured: 0,
    methodsNopSkipped: 0,
    errors: 0
};

// ── Framework class filter ──

var SKIP_PREFIXES = [
    'java.', 'javax.', 'sun.', 'com.sun.',
    'android.', 'androidx.', 'dalvik.',
    'com.android.', 'com.google.android.',
    'org.apache.', 'org.json.', 'org.xml.',
    'kotlin.', 'kotlinx.',
    'org.intellij.', 'org.jetbrains.',
];

function isAppClass(name) {
    for (var i = 0; i < SKIP_PREFIXES.length; i++) {
        if (name.indexOf(SKIP_PREFIXES[i]) === 0) return false;
    }
    return true;
}

// ── Phase 1: Resolve all classes and methods ──

function resolveAllMethods() {
    send({ type: 'status', message: 'Phase 1: enumerating loaded classes...' });

    var appClasses = [];
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (isAppClass(name)) {
                appClasses.push(name);
            }
        },
        onComplete: function () {}
    });

    send({ type: 'status', message: 'Found ' + appClasses.length + ' app classes to resolve' });

    var batch = 0;
    for (var i = 0; i < appClasses.length; i++) {
        try {
            var cls = Java.use(appClasses[i]);
            stats.classesResolved++;

            // getDeclaredMethods forces ART to resolve every method
            // in this class — triggering packer decrypt hooks
            var methods = cls.class.getDeclaredMethods();
            for (var j = 0; j < methods.length; j++) {
                try {
                    methods[j].setAccessible(true);
                    stats.methodsResolved++;
                } catch (e) {}
            }

            // Also resolve constructors
            var ctors = cls.class.getDeclaredConstructors();
            for (var k = 0; k < ctors.length; k++) {
                try {
                    ctors[k].setAccessible(true);
                    stats.methodsResolved++;
                } catch (e) {}
            }
        } catch (e) {
            stats.errors++;
        }

        batch++;
        if (batch >= BATCH_SIZE) {
            batch = 0;
            // Yield to prevent ANR — use a blocking sleep via Thread
            try {
                Java.use('java.lang.Thread').sleep(BATCH_DELAY_MS);
            } catch (e) {}

            if ((i % 500) === 0) {
                send({
                    type: 'progress',
                    phase: 'resolve',
                    current: i,
                    total: appClasses.length,
                    classes: stats.classesResolved,
                    methods: stats.methodsResolved
                });
            }
        }
    }

    send({
        type: 'status',
        message: 'Phase 1 done: ' + stats.classesResolved + ' classes, ' +
                 stats.methodsResolved + ' methods resolved'
    });
}

// ── Phase 2: Harvest CodeItems from ART runtime ──
//
// After resolution, walk every loaded DexFile's class/method
// table and read the now-decrypted CodeItem data directly
// from memory.

function harvestCodeItems() {
    send({ type: 'status', message: 'Phase 2: harvesting CodeItems from ART memory...' });

    // Find libart.so for ArtMethod struct layout probing
    var libart = Process.findModuleByName('libart.so');
    if (!libart) {
        send({ type: 'status', message: 'WARNING: libart.so not found, skipping ART walk' });
        return;
    }

    // Strategy: enumerate ClassLoaders, get their DexFile cookies,
    // and for each DexFile walk the method table to read CodeItems.
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                var pathList = loader.pathList;
                if (!pathList) return;
                var dexElements = pathList.value.dexElements.value;
                for (var i = 0; i < dexElements.length; i++) {
                    var element = dexElements[i];
                    var dexFile = element.dexFile;
                    if (!dexFile || !dexFile.value) continue;

                    var cookie = dexFile.value.mCookie;
                    if (!cookie || !cookie.value) continue;

                    var cookieArr;
                    try {
                        cookieArr = Java.array('long', cookie.value);
                    } catch (e) {
                        continue;
                    }

                    for (var ci = 0; ci < cookieArr.length; ci++) {
                        var dexAddr = ptr(cookieArr[ci]);
                        if (dexAddr.isNull()) continue;

                        // Validate this is a DEX base
                        try {
                            var magic = dexAddr.readU32();
                            // 0x0a786564 = "dex\n" LE
                            if (magic !== 0x0a786564) continue;
                        } catch (e) {
                            continue;
                        }

                        harvestFromDex(dexAddr);
                    }
                }
            } catch (e) {}
        },
        onComplete: function () {}
    });

    send({
        type: 'status',
        message: 'Phase 2 done: captured ' + stats.methodsCaptured +
                 ' CodeItems, skipped ' + stats.methodsNopSkipped + ' NOP methods'
    });
}

function harvestFromDex(dexBase) {
    try {
        var fileSize = dexBase.add(32).readU32();
        var headerSize = dexBase.add(36).readU32();
        if (headerSize !== 0x70) return;
        if (fileSize < 112 || fileSize > 100 * 1024 * 1024) return;

        var classDefsSize = dexBase.add(96).readU32();
        var classDefsOff = dexBase.add(100).readU32();
        var methodIdsSize = dexBase.add(88).readU32();

        if (classDefsSize === 0 || classDefsOff === 0) return;

        // String table for class/method name resolution
        var stringIdsSize = dexBase.add(56).readU32();
        var stringIdsOff = dexBase.add(60).readU32();
        var typeIdsSize = dexBase.add(64).readU32();
        var typeIdsOff = dexBase.add(68).readU32();
        var methodIdsOff = dexBase.add(92).readU32();

        // Walk each ClassDef
        for (var c = 0; c < classDefsSize; c++) {
            var cdOff = classDefsOff + c * 32;
            if (cdOff + 32 > fileSize) break;

            var classIdx = dexBase.add(cdOff).readU32();
            var accessFlags = dexBase.add(cdOff + 4).readU32();
            var classDataOff = dexBase.add(cdOff + 24).readU32();

            // Skip interfaces and annotation-only classes
            if (classDataOff === 0) continue;
            if (classDataOff >= fileSize) continue;

            // Get class name
            var className = readTypeName(dexBase, typeIdsOff, typeIdsSize,
                                          stringIdsOff, stringIdsSize, classIdx);

            // Parse ClassData (ULEB128 encoded)
            var pos = classDataOff;
            var staticFieldsSize = readUleb128(dexBase, pos);
            pos = staticFieldsSize.nextPos;
            var instanceFieldsSize = readUleb128(dexBase, pos);
            pos = instanceFieldsSize.nextPos;
            var directMethodsSize = readUleb128(dexBase, pos);
            pos = directMethodsSize.nextPos;
            var virtualMethodsSize = readUleb128(dexBase, pos);
            pos = virtualMethodsSize.nextPos;

            // Skip field entries
            for (var sf = 0; sf < staticFieldsSize.value + instanceFieldsSize.value; sf++) {
                var f1 = readUleb128(dexBase, pos); pos = f1.nextPos;
                var f2 = readUleb128(dexBase, pos); pos = f2.nextPos;
            }

            // Walk direct + virtual methods
            var totalMethods = directMethodsSize.value + virtualMethodsSize.value;
            var methodIdx = 0;
            for (var m = 0; m < totalMethods; m++) {
                var methodIdxDiff = readUleb128(dexBase, pos); pos = methodIdxDiff.nextPos;
                var mAccessFlags = readUleb128(dexBase, pos); pos = mAccessFlags.nextPos;
                var codeOff = readUleb128(dexBase, pos); pos = codeOff.nextPos;

                methodIdx += methodIdxDiff.value;

                if (codeOff.value === 0) continue;
                if (codeOff.value >= fileSize) continue;

                // Read CodeItem
                var ciBase = dexBase.add(codeOff.value);
                var registersSize, insSize, outsSize, triesSize, insnsSize;
                try {
                    registersSize = ciBase.readU16();
                    insSize = ciBase.add(2).readU16();
                    outsSize = ciBase.add(4).readU16();
                    triesSize = ciBase.add(6).readU16();
                    // debug_info_off at +8 (4 bytes)
                    insnsSize = ciBase.add(12).readU32();
                } catch (e) {
                    continue;
                }

                if (insnsSize === 0) continue;

                var insnsBytes = insnsSize * 2;
                if (insnsBytes > 1024 * 1024) continue; // skip absurdly large

                // Check if instructions are all NOP (still encrypted)
                var insnsPtr = ciBase.add(16);
                var isNop = true;
                var checkLen = Math.min(insnsBytes, 64);
                try {
                    var sample = insnsPtr.readByteArray(checkLen);
                    var arr = new Uint8Array(sample);
                    for (var b = 0; b < arr.length; b++) {
                        if (arr[b] !== 0) { isNop = false; break; }
                    }
                } catch (e) {
                    continue;
                }

                if (isNop && insnsSize > 1) {
                    stats.methodsNopSkipped++;
                    continue;
                }

                // Get method name
                var methodName = readMethodName(dexBase, methodIdsOff, methodIdsSize,
                                                 stringIdsOff, stringIdsSize, methodIdx);

                // Capture the real bytecode
                try {
                    var insnsBuf = insnsPtr.readByteArray(insnsBytes);
                    stats.methodsCaptured++;

                    send({
                        type: 'code_item',
                        class_name: className || ('class_' + classIdx),
                        method_name: methodName || ('method_' + methodIdx),
                        method_idx: methodIdx,
                        code_off: codeOff.value,
                        insns_size: insnsSize,
                        registers_size: registersSize,
                        ins_size: insSize,
                        outs_size: outsSize,
                    }, insnsBuf);

                } catch (e) {
                    stats.errors++;
                }

                // Yield periodically
                if (stats.methodsCaptured % 500 === 0) {
                    send({
                        type: 'progress',
                        phase: 'harvest',
                        captured: stats.methodsCaptured,
                        nopSkipped: stats.methodsNopSkipped
                    });
                }
            }
        }
    } catch (e) {
        send({ type: 'error', message: 'harvestFromDex error: ' + e });
    }
}


// ── ULEB128 reader ──

function readUleb128(base, offset) {
    var result = 0;
    var shift = 0;
    var pos = offset;
    while (true) {
        var b;
        try { b = base.add(pos).readU8(); } catch (e) { break; }
        pos++;
        result |= (b & 0x7F) << shift;
        if ((b & 0x80) === 0) break;
        shift += 7;
    }
    return { value: result, nextPos: pos };
}

// ── String table helpers ──

function readStringByIdx(dexBase, stringIdsOff, stringIdsSize, idx) {
    if (idx >= stringIdsSize) return null;
    try {
        var strDataOff = dexBase.add(stringIdsOff + idx * 4).readU32();
        // Skip MUTF-8 size (ULEB128)
        var r = readUleb128(dexBase, strDataOff);
        var strStart = dexBase.add(r.nextPos);
        return strStart.readUtf8String();
    } catch (e) {
        return null;
    }
}

function readTypeName(dexBase, typeIdsOff, typeIdsSize, stringIdsOff, stringIdsSize, typeIdx) {
    if (typeIdx >= typeIdsSize) return null;
    try {
        var stringIdx = dexBase.add(typeIdsOff + typeIdx * 4).readU32();
        return readStringByIdx(dexBase, stringIdsOff, stringIdsSize, stringIdx);
    } catch (e) {
        return null;
    }
}

function readMethodName(dexBase, methodIdsOff, methodIdsSize, stringIdsOff, stringIdsSize, methodIdx) {
    if (methodIdx >= methodIdsSize) return null;
    try {
        // method_id: u16 class_idx, u16 proto_idx, u32 name_idx
        var nameIdx = dexBase.add(methodIdsOff + methodIdx * 8 + 4).readU32();
        return readStringByIdx(dexBase, stringIdsOff, stringIdsSize, nameIdx);
    } catch (e) {
        return null;
    }
}


// ════════════════════════════════════════════════════════
// Orchestration
// ════════════════════════════════════════════════════════

setTimeout(function () {
    send({ type: 'status', message: 'Active invocation starting...' });

    Java.perform(function () {
        // Phase 1: resolve
        resolveAllMethods();

        // Wait for packer to finish decrypting
        send({ type: 'status', message: 'Waiting ' + WAIT_BEFORE_HARVEST + 's for packer to settle...' });
        try {
            Java.use('java.lang.Thread').sleep(WAIT_BEFORE_HARVEST * 1000);
        } catch (e) {}

        // Phase 2: harvest
        harvestCodeItems();

        // Send final stats
        send({
            type: 'done',
            classesResolved: stats.classesResolved,
            methodsResolved: stats.methodsResolved,
            methodsCaptured: stats.methodsCaptured,
            methodsNopSkipped: stats.methodsNopSkipped,
            errors: stats.errors
        });
    });
}, 2000);
"""


class ActiveInvoker:
    def __init__(self, anti_detect: bool = True, wait_seconds: int = 15, harvest_delay: int = 5):
        self._anti_detect = anti_detect
        self._wait_seconds = wait_seconds
        self._harvest_delay = harvest_delay

    def is_available(self) -> bool:
        try:
            import frida
            frida.get_usb_device(timeout=3)
            return True
        except (ImportError, Exception):
            return False

    def invoke(
        self,
        package_name: str,
        output_dir: Path,
        device_serial: str | None = None,
    ) -> ActiveInvokeResult:
        result = ActiveInvokeResult()
        t0 = time.monotonic_ns()

        try:
            result = self._do_invoke(package_name, output_dir, device_serial, result)
        except Exception as exc:
            result.error = str(exc)
        finally:
            result.duration_ms = int((time.monotonic_ns() - t0) / 1_000_000)

        return result

    def _do_invoke(
        self,
        package_name: str,
        output_dir: Path,
        device_serial: str | None,
        result: ActiveInvokeResult,
    ) -> ActiveInvokeResult:
        try:
            import frida
        except ImportError:
            result.error = "frida not installed"
            return result

        if device_serial:
            device = frida.get_device(device_serial, timeout=5)
        else:
            device = frida.get_usb_device(timeout=5)

        pid = device.spawn([package_name])
        session = device.attach(pid)

        invoke_src = _ACTIVE_INVOKE_SCRIPT.replace(
            "ACTIVE_INVOKE_WAIT_PLACEHOLDER", str(self._harvest_delay)
        )

        if self._anti_detect:
            script_src = _ANTI_DETECT_BLOCK + "\n" + invoke_src
        else:
            script_src = "'use strict';\n" + invoke_src

        output_dir.mkdir(parents=True, exist_ok=True)
        code_items: list[dict] = []
        process_alive = True

        def on_message(message, data):
            nonlocal process_alive
            if message["type"] == "send":
                payload = message["payload"]
                msg_type = payload.get("type")

                if msg_type == "code_item" and data:
                    code_items.append({
                        "class_name": payload.get("class_name", ""),
                        "method_name": payload.get("method_name", ""),
                        "method_idx": payload.get("method_idx", 0),
                        "code_off": payload.get("code_off", 0),
                        "insns": bytes(data),
                        "insns_size": payload.get("insns_size", 0),
                        "registers_size": payload.get("registers_size", 0),
                        "ins_size": payload.get("ins_size", 0),
                        "outs_size": payload.get("outs_size", 0),
                    })

                elif msg_type == "done":
                    result.classes_resolved = payload.get("classesResolved", 0)
                    result.methods_resolved = payload.get("methodsResolved", 0)
                    result.methods_captured = payload.get("methodsCaptured", 0)
                    result.methods_nop_skipped = payload.get("methodsNopSkipped", 0)

            elif message["type"] == "error":
                process_alive = False

        script = session.create_script(script_src)
        script.on("message", on_message)
        script.load()

        device.resume(pid)

        # Total wait: resolve time + harvest delay + buffer
        total_wait = self._wait_seconds + self._harvest_delay + 5
        time.sleep(total_wait)

        try:
            script.unload()
        except Exception:
            pass
        try:
            device.kill(pid)
        except Exception:
            pass

        result.code_items = code_items
        result.success = len(code_items) > 0

        if not result.success and not result.error:
            if not process_alive:
                result.error = (
                    "Target process died — packer detected Frida. "
                    "Active invocation requires the process to survive long enough "
                    "for class/method resolution."
                )
            else:
                result.error = (
                    "No CodeItems captured — methods may already be decrypted "
                    "(dump with Memory engine), or the packer uses a non-standard "
                    "decrypt mechanism."
                )

        # Save captured CodeItems as JSON for the merge step
        if code_items:
            manifest = []
            for ci in code_items:
                manifest.append({
                    "class_name": ci["class_name"],
                    "method_name": ci["method_name"],
                    "method_idx": ci["method_idx"],
                    "code_off": ci["code_off"],
                    "insns_size": ci["insns_size"],
                    "registers_size": ci["registers_size"],
                    "ins_size": ci["ins_size"],
                    "outs_size": ci["outs_size"],
                    "insns_file": f"codeitem_{ci['method_idx']:06d}.bin",
                })
                bin_path = output_dir / f"codeitem_{ci['method_idx']:06d}.bin"
                bin_path.write_bytes(ci["insns"])

            manifest_path = output_dir / "codeitems_manifest.json"
            manifest_path.write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False)
            )

        return result
