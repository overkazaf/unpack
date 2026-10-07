from __future__ import annotations

from unpack.core.dedup import dedup_dex_files


class TestDedupDexFiles:
    def test_no_duplicates(self, synthetic_dex_bytes, tmp_path):
        (tmp_path / "a.dex").write_bytes(synthetic_dex_bytes)
        result = dedup_dex_files(tmp_path)
        assert len(result) == 1

    def test_removes_duplicates(self, synthetic_dex_bytes, tmp_path):
        (tmp_path / "a.dex").write_bytes(synthetic_dex_bytes)
        (tmp_path / "b.dex").write_bytes(synthetic_dex_bytes)
        result = dedup_dex_files(tmp_path)
        assert len(result) == 1

    def test_keeps_different_files(self, synthetic_dex_bytes, tmp_path):
        (tmp_path / "a.dex").write_bytes(synthetic_dex_bytes)
        (tmp_path / "b.dex").write_bytes(synthetic_dex_bytes + b"\x00")
        result = dedup_dex_files(tmp_path)
        assert len(result) == 2

    def test_empty_dir(self, tmp_path):
        result = dedup_dex_files(tmp_path)
        assert result == []
