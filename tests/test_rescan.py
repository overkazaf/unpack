from __future__ import annotations

import json
from pathlib import Path

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
