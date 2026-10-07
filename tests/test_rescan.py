from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from unpack.engines.rescan import (
    ComponentExtractor,
    IncrementalRescanner,
    RescanPlan,
    RescanPlanner,
    RescanResult,
)


class TestComponentExtractor:
    def test_extract_from_strings(self):
        extractor = ComponentExtractor()
        strings = [
            "com.example.MainActivity",
            "com.example.SyncService",
            "com.example.BootReceiver",
        ]
        components = extractor.classify_components(strings)
        types = {c["name"]: c["type"] for c in components}

        assert types["com.example.MainActivity"] == "activity"
        assert types["com.example.SyncService"] == "service"
        assert types["com.example.BootReceiver"] == "receiver"

    def test_extract_provider(self):
        extractor = ComponentExtractor()
        components = extractor.classify_components(["com.example.data.FileProvider"])
        assert components == [{"name": "com.example.data.FileProvider", "type": "provider"}]

    def test_classify_empty(self):
        extractor = ComponentExtractor()
        assert extractor.classify_components([]) == []

    def test_classify_ignores_non_components(self):
        extractor = ComponentExtractor()
        strings = [
            "com.example.Utils",
            "not a class name at all",
            "",
            "   ",
            "single_word",
        ]
        assert extractor.classify_components(strings) == []

    def test_classify_deduplicates(self):
        extractor = ComponentExtractor()
        strings = ["com.example.MainActivity", "com.example.MainActivity"]
        components = extractor.classify_components(strings)
        assert len(components) == 1

    def test_classify_mixed_noise(self):
        extractor = ComponentExtractor()
        strings = [
            "com.example.MainActivity",
            "com.example.Utils",
            "com.example.SyncService",
            "junk$$$",
            "com.example.BootReceiver",
            "com.example.data.FileProvider",
        ]
        components = extractor.classify_components(strings)
        names_by_type = {}
        for c in components:
            names_by_type.setdefault(c["type"], []).append(c["name"])

        assert names_by_type["activity"] == ["com.example.MainActivity"]
        assert names_by_type["service"] == ["com.example.SyncService"]
        assert names_by_type["receiver"] == ["com.example.BootReceiver"]
        assert names_by_type["provider"] == ["com.example.data.FileProvider"]
        assert len(components) == 4  # Utils and junk$$$ dropped


class TestRescanPlanner:
    def _write_report(self, tmp_path: Path, per_dex: list[dict]) -> Path:
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps({"per_dex": per_dex}))
        return report_path

    def test_plan_from_report(self, tmp_path):
        report_path = self._write_report(tmp_path, [
            {"file": "classes_001.dex", "nop_methods": 0},
            {"file": "classes_002.dex", "nop_methods": 50},
        ])

        planner = RescanPlanner()
        plan = planner.plan(report_path)

        assert plan.dex_targets == ["classes_002.dex"]
        assert plan.nop_count == 50
        assert plan.components == []

    def test_plan_no_nop(self, tmp_path):
        report_path = self._write_report(tmp_path, [
            {"file": "classes_001.dex", "nop_methods": 0},
            {"file": "classes_002.dex", "nop_methods": 0},
        ])

        planner = RescanPlanner()
        plan = planner.plan(report_path)

        assert plan.dex_targets == []
        assert plan.nop_count == 0

    def test_plan_sums_multiple_dex(self, tmp_path):
        report_path = self._write_report(tmp_path, [
            {"file": "classes_001.dex", "nop_methods": 10},
            {"file": "classes_002.dex", "nop_methods": 20},
        ])

        planner = RescanPlanner()
        plan = planner.plan(report_path)

        assert sorted(plan.dex_targets) == ["classes_001.dex", "classes_002.dex"]
        assert plan.nop_count == 30

    def test_plan_missing_report_file(self, tmp_path):
        planner = RescanPlanner()
        plan = planner.plan(tmp_path / "does_not_exist.json")

        assert plan.dex_targets == []
        assert plan.nop_count == 0

    def test_plan_malformed_report(self, tmp_path):
        report_path = tmp_path / "report.json"
        report_path.write_text("{not valid json")

        planner = RescanPlanner()
        plan = planner.plan(report_path)

        assert plan.dex_targets == []
        assert plan.nop_count == 0

    def test_plan_missing_per_dex_key(self, tmp_path):
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps({"dex_count": 2}))

        planner = RescanPlanner()
        plan = planner.plan(report_path)

        assert plan.dex_targets == []
        assert plan.nop_count == 0


class TestRescanPlanDataclass:
    def test_defaults(self):
        plan = RescanPlan()
        assert plan.dex_targets == []
        assert plan.nop_count == 0
        assert plan.components == []


class TestRescanResultDataclass:
    def test_defaults(self):
        result = RescanResult()
        assert result.success is False
        assert result.rounds == 0
        assert result.methods_recovered == 0
        assert result.methods_still_nop == 0
        assert result.error is None


class TestIncrementalRescannerNoComponents:
    def test_rescan_with_no_components_errors_without_adb(self, tmp_path):
        rescanner = IncrementalRescanner(rounds=2)
        plan = RescanPlan(dex_targets=["classes_001.dex"], nop_count=10, components=[])

        result = rescanner.rescan("fake-serial", "com.test.app", plan, tmp_path)

        assert result.success is False
        assert result.rounds == 0
        assert result.error == "no components to trigger"


class TestHashExistingDex:
    """_hash_existing_dex seeds dedup with whatever the prior dump already
    wrote to disk, so re-scanning memory doesn't report unchanged content
    as 'newly decrypted'."""

    def test_hashes_existing_dex_files(self, tmp_path, synthetic_dex_bytes):
        (tmp_path / "classes_000.dex").write_bytes(synthetic_dex_bytes)
        rescanner = IncrementalRescanner()

        hashes = rescanner._hash_existing_dex(tmp_path)

        assert len(hashes) == 1

    def test_missing_directory_returns_empty_set(self, tmp_path):
        rescanner = IncrementalRescanner()

        assert rescanner._hash_existing_dex(tmp_path / "does_not_exist") == set()

    def test_empty_directory_returns_empty_set(self, tmp_path):
        rescanner = IncrementalRescanner()

        assert rescanner._hash_existing_dex(tmp_path) == set()


class TestRescanPidMemoryDedup:
    """_rescan_pid_memory re-reads /proc/pid/maps and dd's out DEX-shaped
    regions, but must skip any region whose bytes it has already written
    (this round, a prior round, or the original dump) -- otherwise every
    round re-reports the same unchanged dalvik regions as 'new'."""

    @staticmethod
    def _maps_line(start: int, end: int, tag: str = "dalvik-small") -> str:
        return f"{start:x}-{end:x} rw-p 00000000 00:00 0 [anon:{tag}]\n"

    def test_writes_and_returns_newly_seen_region(self, tmp_path):
        rescanner = IncrementalRescanner()
        maps_text = self._maps_line(0x10000000, 0x10000200)  # 512 bytes
        dex_bytes = b"dex\n" + b"\x00" * 600

        with mock.patch("subprocess.check_output") as co:
            co.side_effect = ["1234\n", maps_text, dex_bytes]
            new_files = rescanner._rescan_pid_memory(
                "serial", "com.test.app", tmp_path, 0, set(),
            )

        assert len(new_files) == 1
        assert new_files[0].exists()
        assert new_files[0].read_bytes()[:4] == b"dex\n"

    def test_rescanning_identical_memory_finds_nothing_new(self, tmp_path):
        rescanner = IncrementalRescanner()
        maps_text = self._maps_line(0x10000000, 0x10000200)
        dex_bytes = b"dex\n" + b"\x00" * 600
        seen_hashes: set[str] = set()

        with mock.patch("subprocess.check_output") as co:
            co.side_effect = ["1234\n", maps_text, dex_bytes]
            first_round = rescanner._rescan_pid_memory(
                "serial", "com.test.app", tmp_path, 0, seen_hashes,
            )
        assert len(first_round) == 1

        with mock.patch("subprocess.check_output") as co:
            co.side_effect = ["1234\n", maps_text, dex_bytes]
            second_round = rescanner._rescan_pid_memory(
                "serial", "com.test.app", tmp_path, 1, seen_hashes,
            )
        assert second_round == []

    def test_region_matching_prior_dump_is_not_new(self, tmp_path, synthetic_dex_bytes):
        # A dalvik region that re-dumps exactly the base classes.dex we
        # already have on disk (always mapped, never changes) must not
        # be reported as newly decrypted.
        (tmp_path / "classes_000.dex").write_bytes(synthetic_dex_bytes)
        rescanner = IncrementalRescanner()
        seen_hashes = rescanner._hash_existing_dex(tmp_path)

        maps_text = self._maps_line(0x10000000, 0x10000100)  # 256 bytes

        with mock.patch("subprocess.check_output") as co:
            co.side_effect = ["1234\n", maps_text, bytes(synthetic_dex_bytes)]
            new_files = rescanner._rescan_pid_memory(
                "serial", "com.test.app", tmp_path, 0, seen_hashes,
            )

        assert new_files == []

    def test_no_pid_returns_empty_without_crashing(self, tmp_path):
        rescanner = IncrementalRescanner()

        with mock.patch("subprocess.check_output", side_effect=OSError("no adb")):
            new_files = rescanner._rescan_pid_memory(
                "serial", "com.test.app", tmp_path, 0, set(),
            )

        assert new_files == []


class TestRescanResultTracksNewDexFiles:
    """The rescan() loop must thread new_dex_files through every round and
    let discovering new DEX drive success, even when the Reporter-based
    NOP count doesn't move (e.g. the newly decrypted code has no NOPs)."""

    def test_new_dex_files_accumulate_and_drive_success(self, tmp_path, monkeypatch):
        rescanner = IncrementalRescanner(rounds=2, trigger_delay=0, settle_delay=0)
        plan = RescanPlan(
            dex_targets=["classes_002.dex"],
            nop_count=10,
            components=[{"name": "com.example.MainActivity", "type": "activity"}],
        )

        monkeypatch.setattr(rescanner, "_trigger_component", lambda *a, **k: None)

        produced = {0: [tmp_path / "rescan_r00_000.dex"], 1: []}

        def fake_rescan_pid_memory(serial, pkg, out_dir, round_num, seen_hashes):
            return produced[round_num]

        monkeypatch.setattr(rescanner, "_rescan_pid_memory", fake_rescan_pid_memory)

        class _FlatReport:
            nop_methods = 10  # never improves -- isolates the new_dex_files signal

        monkeypatch.setattr(
            "unpack.core.reporter.Reporter.evaluate",
            lambda self, output_dir, scan_result=None: _FlatReport(),
        )

        result = rescanner.rescan("serial", "com.example", plan, tmp_path)

        assert result.rounds == 2
        assert result.new_dex_files == [tmp_path / "rescan_r00_000.dex"]
        assert result.methods_recovered == 0  # nop count never moved
        assert result.success is True  # but new content was found, so it still counts
        assert result.error is None
