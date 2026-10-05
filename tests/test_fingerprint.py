from __future__ import annotations

from unittest.mock import patch

import pytest

from unpack.core.fingerprint import FingerprintResult, PackerFingerprint


MAPS_CLEAN = """\
12c00000-12c21000 rw-p 00000000 00:00 0                                  [anon:dalvik-main space]
7f1234560000-7f1234580000 r-xp 00000000 fd:00 1234  /system/lib64/libc.so
7f1234580000-7f12345a0000 r--p 00000000 fd:00 1234  /system/lib64/libc.so
"""

MAPS_MANY_DALVIK = "\n".join(
    f"12c{i:05d}-12c{i+1:05d}000 rw-p 00000000 00:00 0  [anon:dalvik-zygote space {i}]"
    for i in range(15)
)

STATUS_NO_TRACER = """\
Name:\tcom.example.app
State:\tS (sleeping)
Tgid:\t12345
TracerPid:\t0
Uid:\t10123\t10123\t10123\t10123
"""

STATUS_TRACED = """\
Name:\tcom.example.app
State:\tt (tracing stop)
Tgid:\t12345
TracerPid:\t12399
Uid:\t10123\t10123\t10123\t10123
"""

BENIGN_COMMS = [
    "main",
    "Binder:main",
    "FinalizerDaemon",
    "FinalizerWatchdogDaemon",
    "ReferenceQueueDaemon",
    "HeapTaskDaemon",
    "Signal Catcher",
    "JDWP",
    "Jit thread pool",
    "perfetto_hprof_listener",
    "ADB-JDWP Connection Control Thread",
]

SUSPICIOUS_COMMS = [
    "pool-1-thread-1",
    "Thread-5",
    "timer-3",
    "antidebug-watchdog",
    "integrity-monitor",
    "root-checker",
]


@pytest.fixture
def fp():
    return PackerFingerprint()


class TestPackerFingerprint:
    def test_result_fields(self):
        r = FingerprintResult()
        assert r.dalvik_anon_regions == 0
        assert r.watchdog_threads == []
        assert r.has_ptrace_protection is False
        assert r.custom_linker_ns is False
        assert r.thread_count == 0

    def test_risk_score_low_for_clean(self):
        r = FingerprintResult(
            dalvik_anon_regions=3,
            watchdog_threads=[],
            has_ptrace_protection=False,
            custom_linker_ns=False,
            thread_count=10,
        )
        assert r.risk_score < 0.3

    def test_risk_score_high_for_protected(self):
        r = FingerprintResult(
            dalvik_anon_regions=15,
            watchdog_threads=["pool-1-thread-1", "watchdog-timer", "monitor-thread"],
            has_ptrace_protection=True,
            custom_linker_ns=True,
            thread_count=40,
        )
        assert r.risk_score > 0.5

    def test_risk_score_capped_at_one(self):
        r = FingerprintResult(
            dalvik_anon_regions=100,
            watchdog_threads=["pool-1-thread-1"] * 10,
            has_ptrace_protection=True,
            custom_linker_ns=True,
            thread_count=200,
        )
        assert r.risk_score <= 1.0

    def test_parse_maps_counts_dalvik(self, fp):
        assert fp._count_dalvik_anon(MAPS_CLEAN) == 1
        assert fp._count_dalvik_anon(MAPS_MANY_DALVIK) == 15
        assert fp._count_dalvik_anon("") == 0

    def test_parse_status_ptrace(self, fp):
        assert fp._has_ptrace(STATUS_TRACED) is True
        assert fp._has_ptrace(STATUS_NO_TRACER) is False
        assert fp._has_ptrace("") is False

    def test_detect_watchdog_threads(self, fp):
        flagged = fp._find_watchdog_threads(BENIGN_COMMS + SUSPICIOUS_COMMS)
        assert set(flagged) == set(SUSPICIOUS_COMMS)
        for benign in BENIGN_COMMS:
            assert benign not in flagged

    def test_detect_watchdog_threads_empty(self, fp):
        assert fp._find_watchdog_threads([]) == []

    def test_detect_watchdog_threads_all_benign(self, fp):
        assert fp._find_watchdog_threads(BENIGN_COMMS) == []

    def test_to_dict(self):
        r = FingerprintResult(
            dalvik_anon_regions=12,
            watchdog_threads=["pool-1-thread-1"],
            has_ptrace_protection=True,
            custom_linker_ns=True,
            thread_count=35,
        )
        d = r.to_dict()
        assert d["dalvik_anon_regions"] == 12
        assert d["watchdog_threads"] == ["pool-1-thread-1"]
        assert d["has_ptrace_protection"] is True
        assert d["custom_linker_ns"] is True
        assert d["thread_count"] == 35
        assert "risk_score" in d
        assert isinstance(d["risk_score"], float)


class TestPackerFingerprintProbe:
    def test_probe_assembles_result(self, fp):
        comms = BENIGN_COMMS + ["pool-1-thread-1", "watchdog-x"]

        def fake_adb_shell(serial, cmd, timeout=30, root=False):
            if "maps" in cmd:
                return MAPS_MANY_DALVIK
            if "status" in cmd:
                return STATUS_TRACED
            if "comm" in cmd or "task" in cmd:
                return "\n".join(comms)
            if "linker" in cmd or "ls " in cmd:
                return ""
            return ""

        with patch("unpack.core.fingerprint._adb_shell", side_effect=fake_adb_shell):
            with patch.object(fp, "_read_thread_comms", return_value=comms):
                result = fp.probe("emulator-5554", "12345")

        assert result.dalvik_anon_regions == 15
        assert result.has_ptrace_protection is True
        assert set(result.watchdog_threads) == {"pool-1-thread-1", "watchdog-x"}
        assert result.thread_count == len(comms)

    def test_probe_handles_adb_errors_gracefully(self, fp):
        with patch(
            "unpack.core.fingerprint._adb_shell",
            side_effect=OSError("adb not found"),
        ):
            with patch.object(fp, "_read_thread_comms", return_value=[]):
                result = fp.probe("emulator-5554", "12345")

        assert isinstance(result, FingerprintResult)
        assert result.dalvik_anon_regions == 0
        assert result.has_ptrace_protection is False
