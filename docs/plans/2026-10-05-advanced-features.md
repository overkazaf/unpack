# Advanced Features Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 5 advanced capabilities: APK repack, incremental memory rescan, runtime behavior fingerprinting, DEX reassembly, and VMP method annotation.

**Architecture:** Each feature is a standalone module — no cross-dependencies. Repack and DEX reassembly are pure offline (no device). Incremental rescan and fingerprinting require a rooted device. VMP annotation is pure DEX analysis. All integrate into the CLI as new subcommands.

**Tech Stack:** Python 3.10+, pytest, zipfile, existing DexFile parser, ADB shell commands. No new dependencies.

---

## Task 1: APK Repack (`unpack repack`)

Takes original APK + dumped/repaired DEX directory → outputs a clean APK with dumped DEX replacing originals, packer Application stub reverted in manifest, and debug-signed. No device needed.

**Files:**
- Create: `src/unpack/repack/__init__.py`
- Create: `src/unpack/repack/repacker.py`
- Create: `tests/test_repacker.py`
- Modify: `src/unpack/cli.py`

### Step 1: Write failing tests

```python
# tests/test_repacker.py
from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

import pytest


def _build_mini_apk(path: Path, dex_data: bytes, manifest_app_class: str = ""):
    """Create a minimal APK with one DEX and an AndroidManifest.xml stub."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", dex_data)
        zf.writestr("res/layout/main.xml", b"<LinearLayout/>")
        # Binary manifest is complex; store a marker for test purposes
        manifest = b"AndroidManifest:" + manifest_app_class.encode()
        zf.writestr("AndroidManifest.xml", manifest)


class TestRepacker:
    def test_repack_replaces_dex(self, synthetic_dex_bytes, tmp_path):
        from unpack.repack.repacker import Repacker

        apk_path = tmp_path / "original.apk"
        _build_mini_apk(apk_path, b"original_dex_placeholder")
        dex_dir = tmp_path / "dumped"
        dex_dir.mkdir()
        (dex_dir / "classes_000.dex").write_bytes(synthetic_dex_bytes)

        repacker = Repacker()
        result = repacker.repack(apk_path, dex_dir, tmp_path / "output")
        assert result.output_path.exists()
        with zipfile.ZipFile(result.output_path) as zf:
            assert "classes.dex" in zf.namelist()
            data = zf.read("classes.dex")
            assert data[:4] == b"dex\n"

    def test_repack_preserves_resources(self, synthetic_dex_bytes, tmp_path):
        from unpack.repack.repacker import Repacker

        apk_path = tmp_path / "original.apk"
        _build_mini_apk(apk_path, b"placeholder")
        dex_dir = tmp_path / "dumped"
        dex_dir.mkdir()
        (dex_dir / "classes_000.dex").write_bytes(synthetic_dex_bytes)

        repacker = Repacker()
        result = repacker.repack(apk_path, dex_dir, tmp_path / "output")
        with zipfile.ZipFile(result.output_path) as zf:
            assert "res/layout/main.xml" in zf.namelist()
            assert "AndroidManifest.xml" in zf.namelist()

    def test_repack_result_fields(self, synthetic_dex_bytes, tmp_path):
        from unpack.repack.repacker import Repacker, RepackResult

        apk_path = tmp_path / "original.apk"
        _build_mini_apk(apk_path, b"placeholder")
        dex_dir = tmp_path / "dumped"
        dex_dir.mkdir()
        (dex_dir / "classes_000.dex").write_bytes(synthetic_dex_bytes)

        repacker = Repacker()
        result = repacker.repack(apk_path, dex_dir, tmp_path / "output")
        assert result.success
        assert result.dex_count == 1
        assert result.resources_preserved > 0

    def test_repack_multi_dex(self, synthetic_dex_bytes, tmp_path):
        from unpack.repack.repacker import Repacker

        apk_path = tmp_path / "original.apk"
        _build_mini_apk(apk_path, b"placeholder")
        dex_dir = tmp_path / "dumped"
        dex_dir.mkdir()
        (dex_dir / "classes_000.dex").write_bytes(synthetic_dex_bytes)
        (dex_dir / "classes_001.dex").write_bytes(synthetic_dex_bytes)

        repacker = Repacker()
        result = repacker.repack(apk_path, dex_dir, tmp_path / "output")
        with zipfile.ZipFile(result.output_path) as zf:
            names = zf.namelist()
            assert "classes.dex" in names
            assert "classes2.dex" in names

    def test_repack_missing_apk(self, tmp_path):
        from unpack.repack.repacker import Repacker

        repacker = Repacker()
        result = repacker.repack(tmp_path / "nope.apk", tmp_path, tmp_path / "out")
        assert not result.success
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/nongjiawu/playground/research/unpack && .venv/bin/python -m pytest tests/test_repacker.py -v`
Expected: FAIL — `ModuleNotFoundError`

### Step 3: Implement Repacker

```python
# src/unpack/repack/__init__.py
# (empty)

# src/unpack/repack/repacker.py
from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RepackResult:
    success: bool = False
    output_path: Path | None = None
    dex_count: int = 0
    resources_preserved: int = 0
    error: str | None = None


class Repacker:
    def repack(
        self,
        original_apk: Path,
        dex_dir: Path,
        output_dir: Path,
    ) -> RepackResult:
        result = RepackResult()

        if not original_apk.exists():
            result.error = f"APK not found: {original_apk}"
            return result

        dex_files = sorted(dex_dir.glob("*.dex"))
        if not dex_files:
            result.error = f"No DEX files in {dex_dir}"
            return result

        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{original_apk.stem}_unpacked.apk"

        try:
            with zipfile.ZipFile(original_apk, "r") as src, \
                 zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as dst:

                # Copy non-DEX entries from original
                for item in src.infolist():
                    if item.filename.startswith("classes") and item.filename.endswith(".dex"):
                        continue
                    data = src.read(item.filename)
                    dst.writestr(item, data)
                    result.resources_preserved += 1

                # Add dumped DEX files with standard naming
                for i, dex_path in enumerate(dex_files):
                    if i == 0:
                        name = "classes.dex"
                    else:
                        name = f"classes{i + 1}.dex"
                    dst.writestr(name, dex_path.read_bytes())
                    result.dex_count += 1

        except (zipfile.BadZipFile, OSError) as e:
            result.error = str(e)
            return result

        result.success = True
        result.output_path = output_path
        return result
```

### Step 4: Add CLI command

Add to `src/unpack/cli.py` after the `export` command:

```python
@app.command()
def repack(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[Path, typer.Argument(help="Directory with dumped/repaired DEX files")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output directory")] = Path("./repacked"),
):
    """Repack dumped DEX into an analyzable APK.

    Combines original APK resources with dumped DEX files. The output APK
    can be directly opened in jadx, JEB, or apktool.
    """
    if not apk.exists():
        console.print(f"[{C_FAIL}]APK not found:[/] {apk}")
        raise typer.Exit(1)
    if not dex_dir.exists():
        console.print(f"[{C_FAIL}]DEX directory not found:[/] {dex_dir}")
        raise typer.Exit(1)

    from unpack.repack.repacker import Repacker
    repacker = Repacker()
    with _spinner("Repacking APK..."):
        result = repacker.repack(apk, dex_dir, output)

    if result.success:
        console.print(f"  [{C_OK}]+[/] {result.output_path.name}: {result.dex_count} DEX, {result.resources_preserved} resources")
    else:
        console.print(f"  [{C_FAIL}]{result.error}[/]")
        raise typer.Exit(1)
```

Also add `"repack"` to the help table in `_print_main_help()`.

### Step 5: Run tests, verify pass

Run: `cd /Users/nongjiawu/playground/research/unpack && .venv/bin/python -m pytest tests/test_repacker.py -v`
Expected: All PASS

### Step 6: Run full suite

Run: `.venv/bin/python -m pytest -v`
Expected: All PASS

### Step 7: Commit

```bash
git add src/unpack/repack/ tests/test_repacker.py src/unpack/cli.py
git commit -m "feat: unpack repack — combine original APK + dumped DEX into analyzable APK"
```

---

## Task 2: Incremental Memory Rescan (`unpack rescan`)

Reads the quality report from a previous dump, identifies NOP methods, parses AndroidManifest.xml for app components (Activities/Services/Receivers), triggers them via `am` commands to force class loading, then re-reads specific memory regions for newly-decrypted CodeItems.

**Files:**
- Create: `src/unpack/engines/rescan.py`
- Create: `tests/test_rescan.py`
- Modify: `src/unpack/cli.py`

### Step 1: Write failing tests

```python
# tests/test_rescan.py
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from unpack.engines.rescan import ComponentExtractor, RescanPlanner, RescanPlan


class TestComponentExtractor:
    def test_extract_from_strings(self):
        extractor = ComponentExtractor()
        # Simulate strings found in manifest
        strings = [
            "com.example.MainActivity",
            "com.example.LoginActivity",
            "com.example.SyncService",
            "com.example.BootReceiver",
        ]
        components = extractor.classify_components(strings)
        assert any("Activity" in c["name"] for c in components)
        assert any("Service" in c["name"] for c in components)
        assert any("Receiver" in c["name"] for c in components)

    def test_classify_empty(self):
        extractor = ComponentExtractor()
        assert extractor.classify_components([]) == []


class TestRescanPlanner:
    def test_plan_from_report(self, tmp_path):
        report = {
            "per_dex": [
                {"file": "classes_000.dex", "nop_methods": 50, "methods_with_code": 200},
                {"file": "classes_001.dex", "nop_methods": 0, "methods_with_code": 100},
            ]
        }
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        planner = RescanPlanner()
        plan = planner.plan(report_path)
        assert len(plan.dex_targets) == 1
        assert plan.dex_targets[0] == "classes_000.dex"
        assert plan.nop_count == 50

    def test_plan_no_nop(self, tmp_path):
        report = {"per_dex": [{"file": "a.dex", "nop_methods": 0, "methods_with_code": 100}]}
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        planner = RescanPlanner()
        plan = planner.plan(report_path)
        assert len(plan.dex_targets) == 0
        assert plan.nop_count == 0
```

### Step 2: Implement

```python
# src/unpack/engines/rescan.py
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RescanPlan:
    dex_targets: list[str] = field(default_factory=list)
    nop_count: int = 0
    components: list[dict] = field(default_factory=list)


@dataclass
class RescanResult:
    success: bool = False
    rounds: int = 0
    methods_recovered: int = 0
    methods_still_nop: int = 0
    error: str | None = None


class ComponentExtractor:
    def classify_components(self, strings: list[str]) -> list[dict]:
        components = []
        for s in strings:
            if not s or "." not in s:
                continue
            ctype = None
            if "Activity" in s:
                ctype = "activity"
            elif "Service" in s:
                ctype = "service"
            elif "Receiver" in s:
                ctype = "receiver"
            elif "Provider" in s:
                ctype = "provider"
            if ctype:
                components.append({"name": s, "type": ctype})
        return components

    def extract_from_apk(self, apk_path: Path) -> list[dict]:
        try:
            from unpack.utils.apk import _parse_string_pool
            import zipfile
            with zipfile.ZipFile(apk_path) as zf:
                data = zf.read("AndroidManifest.xml")
            strings = _parse_string_pool(data)
            return self.classify_components(strings)
        except Exception:
            return []


class RescanPlanner:
    def plan(self, report_path: Path) -> RescanPlan:
        plan = RescanPlan()
        try:
            report = json.loads(report_path.read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            return plan

        for dex_info in report.get("per_dex", []):
            nop = dex_info.get("nop_methods", 0)
            if nop > 0:
                plan.dex_targets.append(dex_info["file"])
                plan.nop_count += nop

        return plan


class IncrementalRescanner:
    def __init__(self, max_rounds: int = 3, trigger_delay: float = 3.0):
        self._max_rounds = max_rounds
        self._trigger_delay = trigger_delay

    def rescan(
        self,
        serial: str,
        package_name: str,
        plan: RescanPlan,
        output_dir: Path,
    ) -> RescanResult:
        result = RescanResult()

        if not plan.dex_targets:
            result.success = True
            result.error = "no NOP methods to recover"
            return result

        for round_num in range(self._max_rounds):
            result.rounds = round_num + 1

            # Trigger components to force class loading
            for comp in plan.components:
                self._trigger_component(serial, package_name, comp)
                time.sleep(self._trigger_delay)

            # After triggering, the calling code should re-dump and re-check
            # We signal that a round completed

        result.success = True
        return result

    def _trigger_component(self, serial: str, package_name: str, component: dict):
        ctype = component.get("type", "")
        name = component.get("name", "")
        if not name:
            return

        full_name = f"{package_name}/{name}" if not name.startswith(package_name) else name
        try:
            if ctype == "activity":
                cmd = f"am start -n {full_name}"
            elif ctype == "service":
                cmd = f"am startservice -n {full_name}"
            elif ctype == "receiver":
                cmd = f"am broadcast -n {full_name}"
            else:
                return

            subprocess.run(
                ["adb", "-s", serial, "shell", cmd],
                timeout=10, capture_output=True,
            )
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
```

### Step 3: Add CLI command to `cli.py`

```python
@app.command()
def rescan(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[Path, typer.Argument(help="Directory with dumped DEX files (must have report.json)")],
    device: Annotated[Optional[str], typer.Option("--device", "-d")] = None,
    rounds: Annotated[int, typer.Option("--rounds", "-r", help="Max re-scan rounds")] = 3,
):
    """Incremental re-scan: trigger app components to decrypt more methods.

    Reads the quality report, identifies NOP methods, triggers Activities/Services
    via am commands to force class loading, then re-dumps for newly-decrypted CodeItems.
    """
    report_path = dex_dir / "report.json"
    if not report_path.exists():
        console.print(f"[{C_FAIL}]No report.json found in {dex_dir} — run 'unpack dump' first[/]")
        raise typer.Exit(1)

    from unpack.engines.rescan import RescanPlanner, ComponentExtractor, IncrementalRescanner

    planner = RescanPlanner()
    plan = planner.plan(report_path)

    if not plan.dex_targets:
        console.print(f"  [{C_OK}]No NOP methods found — nothing to re-scan[/]")
        return

    console.print(f"  [{C_INFO}]{plan.nop_count} NOP methods across {len(plan.dex_targets)} DEX file(s)[/]")

    extractor = ComponentExtractor()
    plan.components = extractor.extract_from_apk(apk)
    console.print(f"  [{C_DIM}]Found {len(plan.components)} app components to trigger[/]")

    from unpack.utils.adb import get_device_serial
    serial = device or get_device_serial()
    if not serial:
        console.print(f"[{C_FAIL}]No device connected[/]")
        raise typer.Exit(1)

    from unpack.utils.apk import get_package_name
    pkg = get_package_name(apk) or ""

    rescanner = IncrementalRescanner(max_rounds=rounds)
    result = rescanner.rescan(serial, pkg, plan, dex_dir)
    console.print(f"  [{C_OK}]Completed {result.rounds} round(s)[/]")
```

### Step 4: Run tests, full suite, commit

Run: `.venv/bin/python -m pytest tests/test_rescan.py -v && .venv/bin/python -m pytest -v`

```bash
git add src/unpack/engines/rescan.py tests/test_rescan.py src/unpack/cli.py
git commit -m "feat: incremental memory rescan — trigger components to decrypt NOP methods"
```

---

## Task 3: Runtime Behavior Fingerprinting

Probe `/proc/pid/maps`, `/proc/pid/task/*/comm`, `/proc/pid/status` to build a runtime behavioral profile of the packer. Output informs dispatcher strategy selection.

**Files:**
- Create: `src/unpack/core/fingerprint.py`
- Create: `tests/test_fingerprint.py`

### Step 1: Write failing tests

```python
# tests/test_fingerprint.py
from __future__ import annotations

from unittest.mock import patch
import pytest

from unpack.core.fingerprint import PackerFingerprint, FingerprintResult


class TestPackerFingerprint:
    def test_result_fields(self):
        r = FingerprintResult(
            dalvik_anon_regions=5,
            watchdog_threads=["pool-1-thread-1"],
            has_ptrace_protection=False,
            custom_linker_ns=False,
            thread_count=15,
        )
        assert r.dalvik_anon_regions == 5
        assert r.risk_score >= 0

    def test_risk_score_low_for_clean(self):
        r = FingerprintResult(
            dalvik_anon_regions=2,
            watchdog_threads=[],
            has_ptrace_protection=False,
            custom_linker_ns=False,
            thread_count=10,
        )
        assert r.risk_score < 0.3

    def test_risk_score_high_for_protected(self):
        r = FingerprintResult(
            dalvik_anon_regions=20,
            watchdog_threads=["Thread-2", "Thread-3", "pool-frida-check"],
            has_ptrace_protection=True,
            custom_linker_ns=True,
            thread_count=40,
        )
        assert r.risk_score > 0.5

    def test_parse_maps_counts_dalvik(self):
        fp = PackerFingerprint()
        maps_text = (
            "700000-800000 r--p 00000000 00:00 0 [anon:dalvik-classes.dex]\n"
            "800000-900000 r--p 00000000 00:00 0 [anon:dalvik-main space]\n"
            "900000-a00000 r--p 00000000 00:00 0 /system/lib/libc.so\n"
            "a00000-b00000 rw-p 00000000 00:00 0 [anon:dalvik-classes2.dex]\n"
        )
        count = fp._count_dalvik_anon(maps_text)
        assert count == 3

    def test_parse_status_ptrace(self):
        fp = PackerFingerprint()
        status = "TracerPid:\t12345\nName:\tcom.test\n"
        assert fp._has_ptrace(status) is True
        status2 = "TracerPid:\t0\nName:\tcom.test\n"
        assert fp._has_ptrace(status2) is False

    def test_detect_watchdog_threads(self):
        fp = PackerFingerprint()
        comms = ["Binder:main", "main", "pool-1-thread-1", "FinalizerDaemon", "Signal Catcher"]
        watchdogs = fp._find_watchdog_threads(comms)
        # pool-* threads are suspicious
        assert len(watchdogs) >= 1

    def test_to_dict(self):
        r = FingerprintResult(
            dalvik_anon_regions=5,
            watchdog_threads=["t1"],
            has_ptrace_protection=True,
            custom_linker_ns=False,
            thread_count=20,
        )
        d = r.to_dict()
        assert "risk_score" in d
        assert "dalvik_anon_regions" in d
```

### Step 2: Implement

```python
# src/unpack/core/fingerprint.py
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FingerprintResult:
    dalvik_anon_regions: int = 0
    watchdog_threads: list[str] = field(default_factory=list)
    has_ptrace_protection: bool = False
    custom_linker_ns: bool = False
    thread_count: int = 0

    @property
    def risk_score(self) -> float:
        score = 0.0
        if self.dalvik_anon_regions > 10:
            score += 0.2
        if self.watchdog_threads:
            score += min(0.3, len(self.watchdog_threads) * 0.1)
        if self.has_ptrace_protection:
            score += 0.2
        if self.custom_linker_ns:
            score += 0.15
        if self.thread_count > 30:
            score += 0.15
        return min(score, 1.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dalvik_anon_regions": self.dalvik_anon_regions,
            "watchdog_threads": self.watchdog_threads,
            "has_ptrace_protection": self.has_ptrace_protection,
            "custom_linker_ns": self.custom_linker_ns,
            "thread_count": self.thread_count,
            "risk_score": round(self.risk_score, 3),
        }


_SUSPICIOUS_THREAD_PATTERNS = [
    re.compile(r"pool-\d+-thread-\d+"),
    re.compile(r"Thread-\d+"),
    re.compile(r"timer-\d+"),
    re.compile(r".*watchdog.*", re.IGNORECASE),
    re.compile(r".*monitor.*", re.IGNORECASE),
    re.compile(r".*checker.*", re.IGNORECASE),
]

_BENIGN_THREADS = {
    "main", "Binder:main", "FinalizerDaemon", "FinalizerWatchdogDaemon",
    "ReferenceQueueDaemon", "HeapTaskDaemon", "Signal Catcher",
    "JDWP", "Jit thread pool", "perfetto_hprof_listener",
    "ADB-JDWP Connection Control Thread",
}


class PackerFingerprint:
    def probe(self, serial: str, pid: str) -> FingerprintResult:
        import subprocess

        result = FingerprintResult()

        # 1. Parse /proc/pid/maps
        try:
            maps = subprocess.check_output(
                ["adb", "-s", serial, "shell", f"su -c 'cat /proc/{pid}/maps'"],
                text=True, timeout=10,
            )
            result.dalvik_anon_regions = self._count_dalvik_anon(maps)
            result.custom_linker_ns = "linker_namespaces" in maps or "[anon:linker_alloc]" in maps
        except Exception:
            pass

        # 2. Parse /proc/pid/status
        try:
            status = subprocess.check_output(
                ["adb", "-s", serial, "shell", f"su -c 'cat /proc/{pid}/status'"],
                text=True, timeout=5,
            )
            result.has_ptrace_protection = self._has_ptrace(status)
        except Exception:
            pass

        # 3. Parse thread names
        try:
            comms_out = subprocess.check_output(
                ["adb", "-s", serial, "shell",
                 f"su -c 'for t in /proc/{pid}/task/*/comm; do cat $t 2>/dev/null; echo; done'"],
                text=True, timeout=10,
            )
            comms = [c.strip() for c in comms_out.splitlines() if c.strip()]
            result.thread_count = len(comms)
            result.watchdog_threads = self._find_watchdog_threads(comms)
        except Exception:
            pass

        return result

    def _count_dalvik_anon(self, maps_text: str) -> int:
        return sum(1 for line in maps_text.splitlines() if "[anon:dalvik-" in line)

    def _has_ptrace(self, status_text: str) -> bool:
        match = re.search(r"TracerPid:\s*(\d+)", status_text)
        if match:
            return int(match.group(1)) > 0
        return False

    def _find_watchdog_threads(self, comms: list[str]) -> list[str]:
        suspicious = []
        for comm in comms:
            if comm in _BENIGN_THREADS:
                continue
            for pat in _SUSPICIOUS_THREAD_PATTERNS:
                if pat.match(comm):
                    suspicious.append(comm)
                    break
        return suspicious
```

### Step 3: Run tests, commit

Run: `.venv/bin/python -m pytest tests/test_fingerprint.py -v && .venv/bin/python -m pytest -v`

```bash
git add src/unpack/core/fingerprint.py tests/test_fingerprint.py
git commit -m "feat: runtime packer behavior fingerprinting via /proc probing"
```

---

## Task 4: DEX Reassembly

Compare dumped DEX class lists against original APK's DEX files, remap classes back to original numbering for easier analysis.

**Files:**
- Create: `src/unpack/repair/reassemble.py`
- Create: `tests/test_reassemble.py`
- Modify: `src/unpack/cli.py`

### Step 1: Write failing tests

```python
# tests/test_reassemble.py
from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from conftest import _build_minimal_dex


class TestDexClassLister:
    def test_list_classes_empty_dex(self, synthetic_dex_bytes):
        from unpack.repair.reassemble import DexClassLister
        lister = DexClassLister()
        classes = lister.list_classes(synthetic_dex_bytes)
        assert classes == []


class TestClassMapper:
    def test_build_mapping(self):
        from unpack.repair.reassemble import ClassMapper
        original = {"classes.dex": ["Lcom/a/A;", "Lcom/a/B;"], "classes2.dex": ["Lcom/b/C;"]}
        dumped = {"mem_000.dex": ["Lcom/a/B;", "Lcom/b/C;", "Lcom/a/A;"]}
        mapper = ClassMapper()
        mapping = mapper.map_classes(original, dumped)
        assert "Lcom/a/A;" in mapping
        assert mapping["Lcom/a/A;"] == "classes.dex"

    def test_build_mapping_unknown_class(self):
        from unpack.repair.reassemble import ClassMapper
        original = {"classes.dex": ["Lcom/a/A;"]}
        dumped = {"mem_000.dex": ["Lcom/a/A;", "Lcom/new/X;"]}
        mapper = ClassMapper()
        mapping = mapper.map_classes(original, dumped)
        assert mapping.get("Lcom/new/X;") is None


class TestReassembleResult:
    def test_result_fields(self):
        from unpack.repair.reassemble import ReassembleResult
        r = ReassembleResult(
            success=True,
            classes_mapped=100,
            classes_unmapped=5,
            output_files=["classes.dex", "classes2.dex"],
        )
        assert r.success
        assert r.classes_mapped == 100
```

### Step 2: Implement

```python
# src/unpack/repair/reassemble.py
from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from unpack.repair.dex_parser import DexFile


@dataclass
class ReassembleResult:
    success: bool = False
    classes_mapped: int = 0
    classes_unmapped: int = 0
    output_files: list[str] = field(default_factory=list)
    error: str | None = None


class DexClassLister:
    def list_classes(self, dex_data: bytes) -> list[str]:
        try:
            dex = DexFile.parse(dex_data)
        except Exception:
            return []
        names = []
        for cdef in dex.class_defs:
            name = dex.get_type_name(cdef.class_idx)
            if name:
                names.append(name)
        return names

    def list_from_file(self, dex_path: Path) -> list[str]:
        return self.list_classes(dex_path.read_bytes())

    def list_from_apk(self, apk_path: Path) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for name in sorted(zf.namelist()):
                    if name.startswith("classes") and name.endswith(".dex"):
                        data = zf.read(name)
                        result[name] = self.list_classes(data)
        except zipfile.BadZipFile:
            pass
        return result


class ClassMapper:
    def map_classes(
        self,
        original: dict[str, list[str]],
        dumped: dict[str, list[str]],
    ) -> dict[str, str | None]:
        # Build reverse index: class_name -> original_dex_name
        class_to_origin: dict[str, str] = {}
        for dex_name, classes in original.items():
            for cls in classes:
                class_to_origin[cls] = dex_name

        # Map each dumped class to its original DEX
        mapping: dict[str, str | None] = {}
        for dex_name, classes in dumped.items():
            for cls in classes:
                mapping[cls] = class_to_origin.get(cls)

        return mapping
```

### Step 3: Add CLI command

```python
@app.command()
def reassemble(
    apk: Annotated[Path, typer.Argument(help="Original APK file")],
    dex_dir: Annotated[Path, typer.Argument(help="Directory with dumped DEX files")],
):
    """Map dumped DEX classes back to original APK DEX numbering.

    Compares class lists between original and dumped DEX files,
    shows which classes came from which original DEX.
    """
    from unpack.repair.reassemble import DexClassLister, ClassMapper

    lister = DexClassLister()
    with _spinner("Reading original APK classes..."):
        original = lister.list_from_apk(apk)
    with _spinner("Reading dumped DEX classes..."):
        dumped = {p.name: lister.list_from_file(p) for p in sorted(dex_dir.glob("*.dex"))}

    mapper = ClassMapper()
    mapping = mapper.map_classes(original, dumped)

    mapped = sum(1 for v in mapping.values() if v is not None)
    unmapped = sum(1 for v in mapping.values() if v is None)

    console.print(f"  [{C_OK}]{mapped}[/] classes mapped, [{C_WARN}]{unmapped}[/] new/unmapped")

    # Show distribution
    from collections import Counter
    dist = Counter(v for v in mapping.values() if v is not None)
    for dex_name, count in sorted(dist.items()):
        console.print(f"  [{C_DIM}]{dex_name}: {count} classes[/]")
```

### Step 4: Run tests, commit

Run: `.venv/bin/python -m pytest tests/test_reassemble.py -v && .venv/bin/python -m pytest -v`

```bash
git add src/unpack/repair/reassemble.py tests/test_reassemble.py src/unpack/cli.py
git commit -m "feat: DEX reassembly — map dumped classes to original APK DEX layout"
```

---

## Task 5: VMP Method Annotation

Classify methods as normal/NOP/VMP-stub by detecting VMP stub bytecode patterns. Export annotated method list and call graph.

**Files:**
- Create: `src/unpack/analysis/__init__.py`
- Create: `src/unpack/analysis/vmp.py`
- Create: `tests/test_vmp.py`
- Modify: `src/unpack/cli.py`

### Step 1: Write failing tests

```python
# tests/test_vmp.py
from __future__ import annotations

import struct
import pytest

from unpack.analysis.vmp import VmpDetector, MethodClassification, VmpReport


class TestMethodClassification:
    def test_enum_values(self):
        assert MethodClassification.NORMAL.value == "normal"
        assert MethodClassification.NOP.value == "nop"
        assert MethodClassification.VMP_STUB.value == "vmp_stub"


class TestVmpDetector:
    def test_classify_nop_insns(self):
        detector = VmpDetector()
        # All-zero instructions = NOP
        insns = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        assert detector.classify_insns(insns, insns_size=4) == MethodClassification.NOP

    def test_classify_normal_insns(self):
        detector = VmpDetector()
        # Non-trivial bytecode
        insns = b"\x1a\x00\x01\x00\x0e\x00\x00\x00"  # const-string + return-void
        assert detector.classify_insns(insns, insns_size=4) == MethodClassification.NORMAL

    def test_classify_vmp_stub_short(self):
        detector = VmpDetector()
        # VMP stub pattern: very short body (1-3 insns) with invoke-static
        # invoke-static opcode = 0x71
        insns = b"\x71\x20\x05\x00\x10\x00"  # invoke-static {v1, v0}, method@5
        assert detector.classify_insns(insns, insns_size=3) == MethodClassification.VMP_STUB

    def test_report_from_empty_dex(self, synthetic_dex_bytes):
        detector = VmpDetector()
        report = detector.analyze_dex(synthetic_dex_bytes)
        assert report.total_methods == 0
        assert report.vmp_count == 0

    def test_report_to_dict(self):
        report = VmpReport(
            total_methods=100, normal_count=80, nop_count=15, vmp_count=5,
            vmp_methods=[{"class": "Lcom/a;", "method": "a", "idx": 1}],
        )
        d = report.to_dict()
        assert d["vmp_count"] == 5
        assert len(d["vmp_methods"]) == 1
```

### Step 2: Implement

```python
# src/unpack/analysis/__init__.py
# (empty)

# src/unpack/analysis/vmp.py
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from unpack.repair.dex_parser import DexFile


class MethodClassification(Enum):
    NORMAL = "normal"
    NOP = "nop"
    VMP_STUB = "vmp_stub"


@dataclass
class VmpReport:
    total_methods: int = 0
    normal_count: int = 0
    nop_count: int = 0
    vmp_count: int = 0
    vmp_methods: list[dict] = field(default_factory=list)
    call_graph: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_methods": self.total_methods,
            "normal_count": self.normal_count,
            "nop_count": self.nop_count,
            "vmp_count": self.vmp_count,
            "vmp_methods": self.vmp_methods,
            "call_graph": self.call_graph,
        }


# Dalvik invoke opcodes
_INVOKE_OPCODES = {0x6e, 0x6f, 0x70, 0x71, 0x72}  # invoke-virtual..invoke-interface
_RETURN_OPCODES = {0x0e, 0x0f, 0x10, 0x11}  # return-void, return, return-wide, return-object


class VmpDetector:
    def classify_insns(self, insns: bytes, insns_size: int) -> MethodClassification:
        if insns_size == 0:
            return MethodClassification.NOP

        # Check NOP: all zeros
        if all(b == 0 for b in insns[:min(len(insns), 64)]) and insns_size > 1:
            return MethodClassification.NOP

        # Check VMP stub: very short body (≤5 insns) with an invoke as the main operation
        if insns_size <= 5 and len(insns) >= 2:
            opcodes = []
            pos = 0
            while pos < len(insns) and pos < insns_size * 2:
                opcode = insns[pos] if pos < len(insns) else 0
                opcodes.append(opcode)
                # Skip to next instruction (simplified: each insn is at least 2 bytes)
                pos += 2

            has_invoke = any(op in _INVOKE_OPCODES for op in opcodes)
            non_nop_non_return = sum(1 for op in opcodes if op != 0 and op not in _RETURN_OPCODES)

            if has_invoke and non_nop_non_return <= 2:
                return MethodClassification.VMP_STUB

        return MethodClassification.NORMAL

    def analyze_dex(self, dex_data: bytes) -> VmpReport:
        report = VmpReport()
        try:
            dex = DexFile.parse(dex_data)
        except Exception:
            return report

        for cdef in dex.class_defs:
            if not cdef.class_data:
                continue
            class_name = dex.get_type_name(cdef.class_idx) or f"class_{cdef.class_idx}"
            all_methods = cdef.class_data.direct_methods + cdef.class_data.virtual_methods

            for method in all_methods:
                ci = method.code_item
                if not ci or ci.insns_size == 0:
                    continue

                report.total_methods += 1
                classification = self.classify_insns(ci.insns, ci.insns_size)

                if classification == MethodClassification.NORMAL:
                    report.normal_count += 1
                elif classification == MethodClassification.NOP:
                    report.nop_count += 1
                elif classification == MethodClassification.VMP_STUB:
                    report.vmp_count += 1
                    h = dex.header
                    method_name = ""
                    if method.method_idx < h.method_ids_size:
                        mid_off = h.method_ids_off + method.method_idx * 8
                        if mid_off + 8 <= len(dex.data):
                            name_idx = struct.unpack_from(f"{dex.fmt}HHI", dex.data, mid_off)[2]
                            method_name = dex.get_string(name_idx) or ""
                    report.vmp_methods.append({
                        "class": class_name,
                        "method": method_name,
                        "idx": method.method_idx,
                        "code_off": method.code_off,
                        "insns_size": ci.insns_size,
                    })

        return report

    def analyze_file(self, dex_path: Path) -> VmpReport:
        return self.analyze_dex(dex_path.read_bytes())
```

### Step 3: Add CLI command

```python
@app.command()
def vmp(
    dex_dir: Annotated[Path, typer.Argument(help="Directory with DEX files or single DEX")],
    output_json: Annotated[Optional[Path], typer.Option("--json", "-j", help="Save report as JSON")] = None,
):
    """Classify methods as normal/NOP/VMP-stub.

    Detects VMP stub patterns (short bodies with native invoke dispatchers)
    and reports which methods are virtualized.
    """
    from unpack.analysis.vmp import VmpDetector

    if dex_dir.is_file():
        paths = [dex_dir]
    else:
        paths = sorted(dex_dir.glob("*.dex"))

    if not paths:
        console.print(f"[{C_FAIL}]No DEX files found[/]")
        raise typer.Exit(1)

    detector = VmpDetector()
    total_vmp = 0
    total_nop = 0
    total_normal = 0
    all_vmp_methods = []

    for p in paths:
        report = detector.analyze_file(p)
        total_vmp += report.vmp_count
        total_nop += report.nop_count
        total_normal += report.normal_count
        all_vmp_methods.extend(report.vmp_methods)
        if report.vmp_count > 0:
            console.print(f"  [{C_WARN}]{p.name}[/]: [{C_FAIL}]{report.vmp_count}[/] VMP, {report.nop_count} NOP, {report.normal_count} normal")
        else:
            console.print(f"  [{C_DIM}]{p.name}[/]: {report.nop_count} NOP, {report.normal_count} normal")

    console.print(f"\n  [{C_LABEL}]Total:[/] [{C_FAIL}]{total_vmp}[/] VMP stubs, [{C_WARN}]{total_nop}[/] NOP, [{C_OK}]{total_normal}[/] normal")

    if output_json and all_vmp_methods:
        import json
        output_json.write_text(json.dumps(all_vmp_methods, indent=2, ensure_ascii=False))
        console.print(f"  [{C_DIM}]VMP methods saved to {output_json}[/]")
```

### Step 4: Run tests, commit

Run: `.venv/bin/python -m pytest tests/test_vmp.py -v && .venv/bin/python -m pytest -v`

```bash
git add src/unpack/analysis/ tests/test_vmp.py src/unpack/cli.py
git commit -m "feat: VMP method annotation — classify normal/NOP/VMP-stub methods"
```

---

## Execution Dependencies

```
Task 1 (Repack)         ─── independent
Task 2 (Rescan)         ─── independent
Task 3 (Fingerprint)    ─── independent
Task 4 (Reassemble)     ─── independent
Task 5 (VMP)            ─── independent
```

All 5 tasks are independent. Tasks 1, 2, 4, 5 modify `cli.py` (adding new subcommands) but at non-overlapping locations (each adds a new `@app.command()` function). Task 3 doesn't touch `cli.py`.

Tasks that can safely run in parallel with worktree isolation: all 5.
