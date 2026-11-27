"""Unit tests for W1 foundation contracts, security hardening, and engine/ADB refactors."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from unpack.analysis.disasm import FULL_OPCODE_TABLE, OPCODE_TABLE
from unpack.analysis.ioc import categorize_string
from unpack.analysis.vmp import VmpDetector
from unpack.core.dispatcher import Dispatcher
from unpack.core.fingerprint import PackerFingerprint
from unpack.core.scanner import ProtectionLevel, ScanResult
from unpack.engines.active_invoke import ActiveInvoker, MemoryActiveInvoker
from unpack.engines.base import DumpOptions, DumpResult, EngineType
from unpack.engines.ebpf_engine import EbpfEngine, _parse_dump_entries, _push_file
from unpack.engines.frida_engine import FridaEngine
from unpack.engines.frida_scripts import format_frida_error
from unpack.engines.rescan import IncrementalRescanner
from unpack.logging_config import configure_logging, get_logger
from unpack.utils.adb import parse_dex_map_regions, read_proc_mem, validate_pid
from unpack.utils.fs import (
    atomic_write_json,
    file_sha256,
    resolve_unpack_home,
    sanitize_filename,
    utc_now_iso,
)
from unpack.utils.wait import SmartWaiter


class TestLoggingConfig:
    def test_configure_logging_streams_and_levels(self):
        buf = io.StringIO()
        logger = configure_logging("DEBUG", stream=buf, force=True)
        assert logger.level == logging.DEBUG
        sub = get_logger("unpack.test_sub")
        sub.debug("hello-debug-entry")
        assert "hello-debug-entry" in buf.getvalue()

        # Reset back to WARNING on stderr cleanly
        configure_logging("WARNING", force=True)

    def test_configure_logging_invalid_level_raises(self):
        with pytest.raises(ValueError, match="Invalid log level"):
            configure_logging("NOT_A_LEVEL")


class TestFsHelpers:
    def test_utc_now_iso_format(self):
        ts = utc_now_iso()
        assert ts.endswith("Z")
        assert "T" in ts

    def test_resolve_unpack_home_precedence(self, tmp_path, monkeypatch):
        explicit = tmp_path / "custom"
        assert resolve_unpack_home(explicit) == explicit

        env_dir = tmp_path / "env_home"
        monkeypatch.setenv("UNPACK_HOME", str(env_dir))
        assert resolve_unpack_home() == env_dir

        monkeypatch.delenv("UNPACK_HOME", raising=False)
        assert resolve_unpack_home() == Path.home() / ".unpack"

    def test_atomic_write_json_and_mode(self, tmp_path):
        target = tmp_path / "nested" / "secret.json"
        atomic_write_json(target, {"k": "v"}, mode=0o600)
        assert json.loads(target.read_text(encoding="utf-8")) == {"k": "v"}
        if os.name == "posix":
            assert (target.stat().st_mode & 0o777) == 0o600

    def test_file_sha256_streaming(self, tmp_path):
        payload = b"ABCD" * 50_000
        p = tmp_path / "blob.bin"
        p.write_bytes(payload)
        assert file_sha256(p, chunk_size=4096) == hashlib.sha256(payload).hexdigest()

    @pytest.mark.parametrize(
        ("raw", "expected_safe"),
        [
            ("../../etc/passwd", "passwd"),
            (r"..\..\..\windows\evil.so", "evil.so"),
            ("dexfile_open:_ZN3art7DexFileE", "dexfile_open_ZN3art7DexFileE"),
            ("..", "fallback"),
            (".", "fallback"),
            ("", "fallback"),
            ("a/b/c\x00.dex", "c.dex"),
        ],
    )
    def test_sanitize_filename_blocks_traversal(self, raw, expected_safe):
        out = sanitize_filename(raw, fallback="fallback")
        assert "/" not in out
        assert "\\" not in out
        assert ".." not in out
        assert "\x00" not in out
        assert ":" not in out
        assert out == expected_safe

    def test_sanitize_filename_preserves_extension_on_truncation(self):
        long_name = "a" * 200 + ".dex"
        out = sanitize_filename(long_name, max_length=32)
        assert len(out) <= 32
        assert out.endswith(".dex")


class TestAdbAndPidHardening:
    def test_validate_pid(self):
        assert validate_pid("1234") == "1234"
        assert validate_pid(42) == "42"
        for bad in ("", "0", "-5", "123;id", "123$(reboot)", "abc"):
            with pytest.raises(ValueError):
                validate_pid(bad)

    def test_read_proc_mem_rejects_bad_pid_without_subprocess(self):
        with patch("unpack.utils.adb.subprocess.check_output") as mock_co:
            with pytest.raises(ValueError):
                read_proc_mem("SER", "123;rm -rf /", 0, 16)
        mock_co.assert_not_called()

    def test_parse_dex_map_regions_filters_system(self):
        maps = (
            "1000-2000 r--p 00000000 00:00 0 /data/app/base.apk\n"
            "2000-3000 r--p 00000000 00:00 0 /system/framework/boot.vdex\n"
            "3000-4000 rw-p 00000000 00:00 0 [anon:dalvik-classes.dex]\n"
        )
        regions = parse_dex_map_regions(maps)
        assert len(regions) == 2
        assert regions[0].path == "/data/app/base.apk"
        assert regions[1].path == "[anon:dalvik-classes.dex]"

    def test_fingerprint_rejects_bad_pid_and_uses_root(self):
        fp = PackerFingerprint()
        with pytest.raises(ValueError):
            fp.probe("SER", "123;id")

        seen_roots: list[bool] = []

        def fake_shell(serial, cmd, timeout=30, root=False):
            seen_roots.append(root)
            return ""

        with patch("unpack.core.fingerprint.adb_shell", side_effect=fake_shell):
            fp.probe("SER", "12345")
        assert seen_roots and all(seen_roots)

    def test_smart_waiter_rejects_bad_pid(self):
        waiter = SmartWaiter(poll_interval=0.01, max_wait=1.0)
        with pytest.raises(ValueError):
            waiter.wait("SER", "999;reboot")


class TestEngineContractsAndHardening:
    def test_dispatcher_configures_engines_via_dump_options(self, tmp_path):
        d = Dispatcher(quiet=True)
        options_seen: list[DumpOptions] = []

        fake_eng = MagicMock()
        fake_eng.is_available.return_value = True
        fake_eng.configure.side_effect = lambda opt: options_seen.append(opt)
        dex_out = tmp_path / "classes.dex"
        dex_out.write_bytes(b"dex\n035\x00" + b"\x00" * 120)
        fake_eng.dump.return_value = DumpResult(
            engine=EngineType.MEMORY, success=True, dex_files=[dex_out]
        )
        d._engines[EngineType.MEMORY] = fake_eng

        scan = ScanResult(protection_level=ProtectionLevel.NONE)
        with patch("unpack.core.dispatcher.get_package_name", return_value="com.demo.app"):
            res = d.dispatch(
                tmp_path / "demo.apk",
                scan,
                tmp_path,
                force_engine="memory",
                timeout=42,
                anti_detect=False,
            )

        assert res.success is True
        assert options_seen == [DumpOptions(timeout=42, anti_detect=False)]

    def test_active_invoker_rejects_jailed_device(self):
        fake_dev = MagicMock()
        fake_dev.query_system_parameters.return_value = {"access": "jailed"}
        fake_frida = MagicMock()
        fake_frida.get_usb_device.return_value = fake_dev

        inv = ActiveInvoker()
        with patch.dict("sys.modules", {"frida": fake_frida}):
            assert inv.is_available() is False
        assert inv.unavailable_reason and "frida-server" in inv.unavailable_reason

    def test_format_frida_error_is_english_and_actionable(self):
        msg = format_frida_error(RuntimeError("need Gadget to attach on jailed Android"))
        assert "frida-server" in msg
        assert "--engine memory" in msg
        assert all(ord(ch) < 128 for ch in msg)

    def test_frida_dump_sanitizes_untrusted_payload_paths(self, tmp_path):
        fake_script = MagicMock()
        callbacks: dict[str, object] = {}
        fake_script.on.side_effect = lambda evt, fn: callbacks.__setitem__(evt, fn)

        def trigger_messages():
            cb = callbacks["message"]
            cb(
                {"type": "send", "payload": {"type": "dex", "index": 1, "tag": "dexfile_open:../../evil:sym"}},
                b"dex\n035\x00" + b"\x00" * 120,
            )
            cb(
                {"type": "send", "payload": {"type": "so", "index": 1, "name": "../../../tmp/pwn.so"}},
                b"\x7fELF" + b"\x00" * 64,
            )

        fake_script.load.side_effect = trigger_messages
        fake_session = MagicMock()
        fake_session.create_script.return_value = fake_script
        fake_dev = MagicMock()
        fake_dev.spawn.return_value = 1234
        fake_dev.attach.return_value = fake_session
        fake_frida = MagicMock()
        fake_frida.get_usb_device.return_value = fake_dev

        eng = FridaEngine(wait_seconds=1)
        out_dir = tmp_path / "dump"
        with patch.dict("sys.modules", {"frida": fake_frida}), \
             patch("unpack.utils.adb.get_device_serial", return_value=None), \
             patch("unpack.engines.frida_engine.time.sleep"):
            res = eng.dump("com.demo.app", out_dir)

        assert res.success is True
        assert len(res.dex_files) == 1
        assert res.dex_files[0].parent == out_dir
        assert ":" not in res.dex_files[0].name
        assert ".." not in res.dex_files[0].name
        assert len(res.so_files) == 1
        assert res.so_files[0].parent == out_dir / "so"
        assert res.so_files[0].name == "pwn.so"

    def test_memory_active_invoker_rejects_empty_package(self, tmp_path):
        res = MemoryActiveInvoker().invoke("SER", "123", "", tmp_path)
        assert res.success is False
        assert res.error

    def test_ebpf_quoting_and_parse_validation(self):
        cmds: list[str] = []
        with patch("unpack.engines.ebpf_engine.adb_cmd"), \
             patch("unpack.engines.ebpf_engine.adb_shell", side_effect=lambda s, c, **kw: cmds.append(c) or ""):
            _push_file("SER", "/tmp/a.bt", "/data/local/tmp/my script.bt")
        assert cmds and "'/data/local/tmp/my script.bt'" in cmds[0]

        eng = EbpfEngine()
        cleanup_cmds: list[str] = []
        with patch("unpack.engines.ebpf_engine._find_bpftrace_path", return_value="/data/local/tmp/bpf'trace"), \
             patch("unpack.engines.ebpf_engine.adb_shell", side_effect=lambda s, c, **kw: cleanup_cmds.append(c) or ""):
            eng._cleanup("SER")
        assert any("pkill -f" in c and "'\"'\"'" in c for c in cleanup_cmds)

        entries = _parse_dump_entries("EBPF_DUMP: -1 0x1000 500\nEBPF_DUMP: 0 0x1000 500\nEBPF_DUMP: 42 0x1000 500\n")
        assert entries == [(42, 0x1000, 500)]

    def test_rescan_quotes_component_names(self):
        rescanner = IncrementalRescanner()
        called_args: list[tuple] = []
        with patch("unpack.engines.rescan.adb_run", side_effect=lambda *a, **kw: called_args.append(a)):
            rescanner._trigger_component(
                "SER", "com.demo.app", {"type": "activity", "name": "com.evil;rebootActivity"}
            )
            rescanner._trigger_component(
                "SER", "com.demo.app", {"type": "provider", "name": "com.evil$(id)Provider"}
            )
        assert len(called_args) == 2
        assert called_args[0][-1] == "'com.demo.app/com.evil;rebootActivity'"
        assert called_args[1][-1] == "'content://com.evil$(id)Provider'"


class TestAnalysisConsistency:
    def test_disasm_return_void_format_matches_full_table(self):
        assert OPCODE_TABLE[0x0E] == FULL_OPCODE_TABLE[0x0E]

    def test_ioc_categorization(self):
        assert categorize_string("https://api.example.com/v1") == "url"
        assert categorize_string("192.168.1.10") == "ip"
        assert categorize_string("/system/bin/su") == "anti_analysis"
        assert categorize_string("AKIAIOSFODNN7EXAMPLE") == "secret"
        assert categorize_string("hello world") == "plain"

    def test_vmp_public_first_invoke_target(self):
        # invoke-static {v0}, method@0x0007 (format 35c)
        insns = bytes([0x71, 0x10, 0x07, 0x00, 0x00, 0x00])
        assert VmpDetector().first_invoke_target(insns, 3) == 7
