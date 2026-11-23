"""Structured error taxonomy for UNPACK core, CLI, and Web APIs."""

from __future__ import annotations

from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    """Machine-readable error codes shared across CLI, Web, and core APIs."""

    INTERNAL_ERROR = "INTERNAL_ERROR"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    INVALID_APK = "INVALID_APK"
    INVALID_DEX = "INVALID_DEX"
    INVALID_PACKAGE_NAME = "INVALID_PACKAGE_NAME"
    DEVICE_NOT_CONNECTED = "DEVICE_NOT_CONNECTED"
    ROOT_REQUIRED = "ROOT_REQUIRED"
    ENGINE_UNAVAILABLE = "ENGINE_UNAVAILABLE"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    DUMP_FAILED = "DUMP_FAILED"
    REPAIR_FAILED = "REPAIR_FAILED"
    REPACK_FAILED = "REPACK_FAILED"
    TIMEOUT = "TIMEOUT"


class UnpackError(Exception):
    """Base structured exception carrying an error code, hint, and exit code."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.INTERNAL_ERROR,
        hint: str = "",
        exit_code: int = 1,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.hint = hint
        self.exit_code = exit_code
        self.details: dict[str, Any] = dict(details) if details else {}

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": self.message,
            "code": self.code.value,
            "exit_code": self.exit_code,
        }
        if self.hint:
            payload["hint"] = self.hint
        if self.details:
            payload["details"] = self.details
        return payload


class ApkValidationError(UnpackError):
    def __init__(self, message: str, hint: str = "", details: dict[str, Any] | None = None):
        super().__init__(
            message=message,
            code=ErrorCode.INVALID_APK,
            hint=hint or "Verify the file is a valid ZIP/APK archive.",
            exit_code=1,
            details=details,
        )


class DexFormatError(UnpackError):
    def __init__(self, message: str, hint: str = "", details: dict[str, Any] | None = None):
        super().__init__(
            message=message,
            code=ErrorCode.INVALID_DEX,
            hint=hint or "Run `unpack repair <file.dex>` to fix corrupted DEX headers.",
            exit_code=1,
            details=details,
        )


class DeviceError(UnpackError):
    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.DEVICE_NOT_CONNECTED,
        hint: str = "",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(
            message=message,
            code=code,
            hint=hint or "Connect an Android device with USB debugging enabled and run `adb devices`.",
            exit_code=2,
            details=details,
        )


class EngineError(UnpackError):
    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.ENGINE_UNAVAILABLE,
        hint: str = "",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(
            message=message,
            code=code,
            hint=hint or "Run `unpack doctor` to inspect engine readiness and device prerequisites.",
            exit_code=4,
            details=details,
        )


class DependencyError(UnpackError):
    def __init__(self, message: str, package: str = "", extra: str = ""):
        hint = f"Install with `pip install -e '.[{extra}]'`" if extra else (
            f"Install missing dependency: `pip install {package}`" if package else ""
        )
        super().__init__(
            message=message,
            code=ErrorCode.DEPENDENCY_MISSING,
            hint=hint,
            exit_code=1,
            details={"package": package} if package else None,
        )
