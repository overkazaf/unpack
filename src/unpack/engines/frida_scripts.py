"""Shared Frida JavaScript payloads and device/error helpers.

Centralizes the anti-detection JS block and USB/jailed-device verification so
:mod:`unpack.engines.frida_engine` and :mod:`unpack.engines.active_invoke`
never drift out of sync.
"""

from __future__ import annotations

from typing import Any

from unpack.logging_config import get_logger

log = get_logger(__name__)

# Single source of truth for Frida anti-detection hooks.
# Runs synchronously on script load before target process resume.
FRIDA_ANTI_DETECT_JS = r"""
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
        Interceptor.attach(gettimeofdayPtr, {
            onLeave: function () {}
        });
    },

    apply: function () {
        if (!this.enabled) return;
        this.hideFromMaps();
        this.hideDefaultPort();
        this.hideTracerPid();
        this.blockWatchdogSignals();
        this.renameFridaThread();
        this.neutralizeTimingChecks();
    }
};
"""


def check_frida_usb_available(timeout: float = 3.0) -> tuple[bool, Any | None, str | None]:
    """Verify Frida is installed, a USB device is attached, and ``frida-server`` is reachable.

    Rejects jailed Gadget-only USB devices so callers can cleanly fall back to
    the root memory engine instead of failing mid-spawn.
    """
    try:
        import frida

        device = frida.get_usb_device(timeout=timeout)
        if hasattr(device, "query_system_parameters"):
            try:
                params = device.query_system_parameters()
                if isinstance(params, dict) and params.get("access") == "jailed":
                    return (
                        False,
                        frida,
                        "frida-server is not running on device (jailed Android mode). "
                        "Start frida-server as root on the device (e.g. "
                        "adb shell su -c '/data/local/tmp/frida-server -D &'), "
                        "or use engine=memory.",
                    )
            except Exception as qexc:
                qmsg = str(qexc).lower()
                if any(tok in qmsg for tok in ("gadget", "jailed", "frida-server", "connection")):
                    return (
                        False,
                        frida,
                        f"frida-server not reachable on device ({qexc}). "
                        "Start frida-server as root on the device or use engine=memory.",
                    )
                log.debug("Frida query_system_parameters probe ignored: %s", qexc)
        return True, frida, None
    except ImportError:
        return False, None, "frida not installed (pip install -e '.[frida]')"
    except Exception as exc:
        return False, None, f"no USB Frida device reachable ({exc})"


def format_frida_error(exc: Exception) -> str:
    """Return a clear, actionable English error message for Frida runtime failures."""
    msg = str(exc)
    lower = msg.lower()
    if any(
        tok in lower
        for tok in ("need gadget", "jailed android", "unable to connect to remote frida-server")
    ):
        return (
            "frida-server is not running on the device (Frida fell back to jailed Gadget mode). "
            "Start frida-server as root on the device "
            "(e.g. `adb shell su -c '/data/local/tmp/frida-server -D &'`), "
            "or switch to `--engine memory` (root-only, no frida-server required). "
            f"[cause: {msg}]"
        )
    return msg


__all__ = [
    "FRIDA_ANTI_DETECT_JS",
    "check_frida_usb_available",
    "format_frida_error",
]
