from __future__ import annotations

import subprocess
from unittest.mock import patch

from unpack.core.doctor import DeviceInfo, DoctorReport, run_doctor
from unpack.utils.adb import list_devices
from unpack.core.errors import (
    ApkValidationError,
    DependencyError,
    DeviceError,
    DexFormatError,
    EngineError,
    ErrorCode,
    UnpackError,
)


class TestDoctorReport:
    def test_run_doctor_offline_fast(self):
        report = run_doctor(check_devices=False, timeout=1.0)
        assert isinstance(report, DoctorReport)
        assert report.overall_status in {"healthy", "degraded", "unhealthy"}
        assert report.python_version != ""
        assert report.unpack_version != ""
        assert len(report.checks) >= 10
        assert len(report.engines) == 3

        d = report.to_dict()
        for key in ("overall_status", "python_version", "unpack_version", "checks", "devices", "engines"):
            assert key in d

    def test_run_doctor_with_mocked_rooted_device(self):
        fake_dev = DeviceInfo(
            serial="emulator-5554",
            state="device",
            model="Pixel_7",
            android_version="14",
            api_level="34",
            abi="arm64-v8a",
            rooted=True,
            has_bpftrace=True,
            frida_server_running=True,
        )
        with patch("unpack.core.doctor._probe_devices", return_value=[fake_dev]), \
             patch("unpack.core.doctor._probe_tool", return_value=(True, "/usr/bin/tool", "1.0")):
            report = run_doctor(check_devices=True, timeout=1.0)

        assert len(report.devices) == 1
        engines = {e.name: e for e in report.engines}
        assert engines["memory"].available is True
        assert engines["ebpf"].available is True

    def test_adb_list_devices_handles_nonzero_exit_and_oserror(self):
        with patch(
            "unpack.utils.adb.subprocess.check_output",
            side_effect=subprocess.CalledProcessError(1, ["adb", "devices", "-l"]),
        ):
            assert list_devices() == []

        with patch(
            "unpack.utils.adb.subprocess.check_output",
            side_effect=OSError("daemon busy"),
        ):
            assert list_devices() == []

    def test_run_doctor_handles_adb_probe_failure_gracefully(self):
        with patch("unpack.core.doctor._probe_tool", return_value=(True, "/usr/bin/adb", "1.0")), \
             patch("unpack.core.doctor._probe_devices", side_effect=RuntimeError("adb crashed")):
            report = run_doctor(check_devices=True, timeout=1.0)
        dev_checks = [c for c in report.checks if c.id == "adb_devices"]
        assert len(dev_checks) == 1
        assert dev_checks[0].status == "warn"
        assert "adb crashed" in dev_checks[0].summary


class TestErrorTaxonomy:
    def test_unpack_error_to_dict(self):
        err = UnpackError(
            "bad apk",
            code=ErrorCode.INVALID_APK,
            hint="Check file",
            exit_code=1,
            details={"path": "a.apk"},
        )
        d = err.to_dict()
        assert d["error"] == "bad apk"
        assert d["code"] == "INVALID_APK"
        assert d["hint"] == "Check file"
        assert d["details"] == {"path": "a.apk"}

    def test_subclasses_codes(self):
        assert ApkValidationError("x").code == ErrorCode.INVALID_APK
        assert DexFormatError("x").code == ErrorCode.INVALID_DEX
        assert DeviceError("x").exit_code == 2
        assert EngineError("x").exit_code == 4
        assert "frida" in DependencyError("missing", package="frida", extra="frida").hint
