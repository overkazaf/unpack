"""Regression tests for eBPF uprobe symbol discovery, verification, and Dispatcher fallback."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from unpack.core.dispatcher import Dispatcher
from unpack.core.scanner import ProtectionLevel, ScanResult
from unpack.engines.base import DumpResult, EngineType
from unpack.engines.ebpf_engine import (
    _SymbolInfo,
    _generate_bpftrace_script,
    _get_probe_target,
    _parse_readelf_symbols,
    _verify_symbols_probeable,
)


def test_parse_readelf_skips_undefined_imports_and_non_func():
    readelf_out = """
Symbol table '.dynsym' contains 5 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _ZN3art13DexFileLoader4OpenERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEbbbPNS_22DexFileLoaderErrorCodeE
     2: 0000000000041230   128 FUNC    GLOBAL DEFAULT   14 _ZN3art7DexFileC2EPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEj@@LIBDEXFILE_1
     3: 000000000018a000    64 OBJECT  GLOBAL DEFAULT   18 _ZN3art11ClassLinker11DefineClassE_notfunc
     4: 000000000024bc10   320 FUNC    GLOBAL DEFAULT   14 _ZN3art11ClassLinker15RegisterDexFileERKNS_7DexFileE
"""
    parsed = _parse_readelf_symbols(readelf_out, "/apex/com.android.art/lib64/libart.so")
    assert "dexfile_open" not in parsed  # UND with 0x0 must be skipped
    assert "define_class" not in parsed  # OBJECT must be skipped
    assert parsed["dexfile_ctor"].offset == "0x41230"
    assert parsed["dexfile_ctor"].name.endswith("allocatorIcEEEEj")  # version suffix stripped
    assert parsed["dexfile_ctor"].library == "/apex/com.android.art/lib64/libart.so"
    assert parsed["register_dexfile"].offset == "0x24bc10"


def test_verify_symbols_probeable_uses_offset_when_name_fails_and_omits_unprobeable():
    syms = {
        "dexfile_ctor": _SymbolInfo(
            name="_ZN3art7DexFileC2E",
            offset="0x41230",
            library="/apex/com.android.art/lib64/libdexfile.so",
        ),
        "dexfile_open": _SymbolInfo(
            name="_ZN3art13DexFileLoader4OpenE",
            offset="0x55000",
            library="/apex/com.android.art/lib64/libdexfile.so",
        ),
    }

    def fake_shell(serial, cmd, root=True, timeout=10):
        if "_ZN3art7DexFileC2E" in cmd:
            return "ERROR: No matches for uprobe /apex/com.android.art/lib64/libdexfile.so:_ZN3art7DexFileC2E"
        if "0x41230" in cmd:
            return "uprobe:/apex/com.android.art/lib64/libdexfile.so:0x41230\n"
        return "ERROR: No matches for uprobe\n"

    with patch("unpack.engines.ebpf_engine.adb_shell", side_effect=fake_shell):
        verified = _verify_symbols_probeable("SER", "/apex/com.android.art/lib64/libart.so", syms, "/data/local/tmp/bpftrace")

    assert verified["dexfile_ctor"].probeable is True
    assert _get_probe_target(verified["dexfile_ctor"]) == "0x41230"
    assert verified["dexfile_open"].probeable is False

    script = _generate_bpftrace_script("/apex/com.android.art/lib64/libart.so", verified)
    assert "uprobe:/apex/com.android.art/lib64/libdexfile.so:0x41230" in script
    assert "_ZN3art7DexFileC2E" not in script
    assert "DexFileLoader" not in script


def test_dispatcher_auto_falls_back_when_ebpf_fails(tmp_path):
    d = Dispatcher(quiet=True)
    ebpf = MagicMock()
    ebpf.is_available.return_value = True
    ebpf.dump.return_value = DumpResult(engine=EngineType.EBPF, success=False, error="bpftrace failed")

    frida = MagicMock()
    frida.is_available.return_value = True
    dex_out = tmp_path / "classes.dex"
    dex_out.write_bytes(b"dex\n035\x00" + b"\x00" * 120)
    frida.dump.return_value = DumpResult(engine=EngineType.FRIDA, success=True, dex_files=[dex_out])

    d._engines[EngineType.EBPF] = ebpf
    d._engines[EngineType.FRIDA] = frida

    scan = ScanResult(protection_level=ProtectionLevel.VMP)
    with patch("unpack.core.dispatcher.get_package_name", return_value="com.demo.app"):
        res = d.dispatch(tmp_path / "demo.apk", scan, tmp_path)

    assert res.success is True
    assert res.engine == EngineType.FRIDA
    assert ebpf.dump.called
    assert frida.dump.called


def test_frida_engine_rejects_jailed_device_without_frida_server():
    from unpack.engines.frida_engine import FridaEngine

    fake_dev = MagicMock()
    fake_dev.query_system_parameters.return_value = {"access": "jailed", "os": {"id": "android"}}
    fake_frida = MagicMock()
    fake_frida.get_usb_device.return_value = fake_dev

    eng = FridaEngine()
    with patch.dict("sys.modules", {"frida": fake_frida}):
        assert eng.is_available() is False
    assert eng.unavailable_reason and "frida-server" in eng.unavailable_reason


def test_dispatcher_vmp_falls_back_to_memory_when_ebpf_fails_and_frida_unavailable(tmp_path):
    d = Dispatcher(quiet=True)
    ebpf = MagicMock()
    ebpf.is_available.return_value = True
    ebpf.dump.return_value = DumpResult(engine=EngineType.EBPF, success=False, error="bpftrace failed")

    frida = MagicMock()
    frida.is_available.return_value = False
    frida.unavailable_reason = "frida-server is not running on device"

    mem = MagicMock()
    mem.is_available.return_value = True
    dex_out = tmp_path / "classes.dex"
    dex_out.write_bytes(b"dex\n035\x00" + b"\x00" * 120)
    mem.dump.return_value = DumpResult(engine=EngineType.MEMORY, success=True, dex_files=[dex_out])

    d._engines[EngineType.EBPF] = ebpf
    d._engines[EngineType.FRIDA] = frida
    d._engines[EngineType.MEMORY] = mem

    scan = ScanResult(protection_level=ProtectionLevel.VMP)
    with patch("unpack.core.dispatcher.get_package_name", return_value="com.demo.vmp"):
        res = d.dispatch(tmp_path / "demo.apk", scan, tmp_path)

    assert res.success is True
    assert res.engine == EngineType.MEMORY
    assert not frida.dump.called
    assert mem.dump.called

