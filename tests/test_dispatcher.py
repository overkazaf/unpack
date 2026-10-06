from __future__ import annotations

from unittest.mock import patch

from unpack.core.dispatcher import Dispatcher, _ENGINE_PRIORITY
from unpack.core.scanner import ScanResult, ProtectionLevel
from unpack.engines.base import EngineType


class TestEnginePriority:
    def test_dex_encryption_prefers_ebpf(self):
        priority = _ENGINE_PRIORITY[ProtectionLevel.DEX_ENCRYPTION]
        assert priority[0] == EngineType.EBPF

    def test_function_extraction_prefers_ebpf(self):
        priority = _ENGINE_PRIORITY[ProtectionLevel.FUNCTION_EXTRACTION]
        assert priority[0] == EngineType.EBPF

    def test_none_prefers_frida(self):
        priority = _ENGINE_PRIORITY[ProtectionLevel.NONE]
        assert priority[0] == EngineType.FRIDA

    def test_vmp_no_memory(self):
        priority = _ENGINE_PRIORITY[ProtectionLevel.VMP]
        assert EngineType.MEMORY not in priority


class TestDispatcherForceEngine:
    def test_force_unknown_engine_returns_error(self, tmp_path):
        d = Dispatcher()
        scan = ScanResult(protection_level=ProtectionLevel.NONE)
        with patch("unpack.core.dispatcher.get_package_name", return_value="com.test"):
            result = d.dispatch(tmp_path / "fake.apk", scan, tmp_path, force_engine="nonexistent")
        assert result.error and "Unknown engine" in result.error
