from __future__ import annotations

from pathlib import Path

import pytest

from unpack.core.reporter import Reporter, QualityReport


@pytest.fixture
def reporter():
    return Reporter()


class TestReporterWithDex:
    def test_counts_dex_files(self, reporter, tmp_dex_dir):
        report = reporter.evaluate(tmp_dex_dir)
        assert report.dex_count == 2

    def test_score_for_minimal_dex(self, reporter, tmp_dex_dir):
        report = reporter.evaluate(tmp_dex_dir)
        assert report.total_classes == 0
        assert report.total_methods == 0
        assert report.score == 0.5  # dex_count > 0 but no methods

    def test_to_dict(self, reporter, tmp_dex_dir):
        report = reporter.evaluate(tmp_dex_dir)
        d = report.to_dict()
        assert "dex_count" in d
        assert "code_coverage" in d
        assert "score" in d
        assert isinstance(d["per_dex"], list)
        assert len(d["per_dex"]) == 2


class TestReporterEmpty:
    def test_empty_dir(self, reporter, tmp_path):
        d = tmp_path / "empty"
        d.mkdir()
        report = reporter.evaluate(d)
        assert report.dex_count == 0
        assert report.total_classes == 0
        assert report.score == 0.0

    def test_non_dex_files_ignored(self, reporter, tmp_path):
        d = tmp_path / "nondex"
        d.mkdir()
        (d / "readme.txt").write_text("not a dex")
        (d / "data.bin").write_bytes(b"\x00" * 100)
        report = reporter.evaluate(d)
        assert report.dex_count == 0
