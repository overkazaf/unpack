from __future__ import annotations

import zipfile

import pytest

from unpack.repair.reassemble import ClassMapper, DexClassLister, ReassembleResult


class TestDexClassLister:
    def test_list_classes_empty_dex(self, synthetic_dex_bytes):
        lister = DexClassLister()
        assert lister.list_classes(synthetic_dex_bytes) == []

    def test_list_from_file(self, tmp_dex):
        lister = DexClassLister()
        assert lister.list_from_file(tmp_dex) == []

    def test_list_from_apk(self, tmp_path, synthetic_dex_bytes):
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("classes.dex", synthetic_dex_bytes)
            zf.writestr("classes2.dex", synthetic_dex_bytes)
            zf.writestr("AndroidManifest.xml", b"")

        lister = DexClassLister()
        result = lister.list_from_apk(apk_path)

        assert set(result.keys()) == {"classes.dex", "classes2.dex"}
        assert result["classes.dex"] == []
        assert result["classes2.dex"] == []

    def test_list_from_apk_no_dex(self, tmp_path):
        apk_path = tmp_path / "empty.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"")

        lister = DexClassLister()
        assert lister.list_from_apk(apk_path) == {}

    def test_list_from_apk_ignores_nested_dex(self, tmp_path, synthetic_dex_bytes):
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("classes.dex", synthetic_dex_bytes)
            zf.writestr("assets/some/classes.dex", synthetic_dex_bytes)

        lister = DexClassLister()
        result = lister.list_from_apk(apk_path)
        assert set(result.keys()) == {"classes.dex"}


class TestClassMapper:
    def test_build_mapping(self):
        original = {
            "classes.dex": ["Lcom/a/A;", "Lcom/a/B;"],
            "classes2.dex": ["Lcom/b/C;"],
        }
        dumped = {"mem_000.dex": ["Lcom/a/B;", "Lcom/b/C;", "Lcom/a/A;"]}

        mapper = ClassMapper()
        mapping = mapper.map_classes(original, dumped)

        assert mapping["Lcom/a/A;"] == "classes.dex"
        assert mapping["Lcom/a/B;"] == "classes.dex"
        assert mapping["Lcom/b/C;"] == "classes2.dex"

    def test_build_mapping_unknown_class(self):
        original = {"classes.dex": ["Lcom/a/A;"]}
        dumped = {"mem_000.dex": ["Lcom/a/A;", "Lcom/new/New;"]}

        mapper = ClassMapper()
        mapping = mapper.map_classes(original, dumped)

        assert mapping["Lcom/a/A;"] == "classes.dex"
        assert mapping["Lcom/new/New;"] is None

    def test_build_mapping_multiple_dumped_files(self):
        original = {
            "classes.dex": ["Lcom/a/A;"],
            "classes2.dex": ["Lcom/b/B;"],
        }
        dumped = {
            "mem_000.dex": ["Lcom/a/A;"],
            "mem_001.dex": ["Lcom/b/B;", "Lcom/c/C;"],
        }

        mapper = ClassMapper()
        mapping = mapper.map_classes(original, dumped)

        assert mapping["Lcom/a/A;"] == "classes.dex"
        assert mapping["Lcom/b/B;"] == "classes2.dex"
        assert mapping["Lcom/c/C;"] is None

    def test_build_mapping_empty_original(self):
        mapper = ClassMapper()
        mapping = mapper.map_classes({}, {"mem_000.dex": ["Lcom/a/A;"]})
        assert mapping["Lcom/a/A;"] is None

    def test_build_mapping_empty_dumped(self):
        mapper = ClassMapper()
        mapping = mapper.map_classes({"classes.dex": ["Lcom/a/A;"]}, {})
        assert mapping == {}

    def test_build_index(self):
        original = {
            "classes.dex": ["Lcom/a/A;", "Lcom/a/B;"],
            "classes2.dex": ["Lcom/b/C;"],
        }
        mapper = ClassMapper()
        index = mapper.build_index(original)
        assert index == {
            "Lcom/a/A;": "classes.dex",
            "Lcom/a/B;": "classes.dex",
            "Lcom/b/C;": "classes2.dex",
        }


class TestReassembleResult:
    def test_result_fields(self):
        result = ReassembleResult()
        assert result.success is False
        assert result.classes_mapped == 0
        assert result.classes_unmapped == 0
        assert result.output_files == []
        assert result.error is None

    def test_result_custom_values(self):
        result = ReassembleResult(
            success=True,
            classes_mapped=10,
            classes_unmapped=2,
            output_files=["classes.dex", "classes2.dex"],
            error=None,
        )
        assert result.success is True
        assert result.classes_mapped == 10
        assert result.classes_unmapped == 2
        assert result.output_files == ["classes.dex", "classes2.dex"]
        assert result.error is None

    def test_result_independent_default_lists(self):
        a = ReassembleResult()
        b = ReassembleResult()
        a.output_files.append("x.dex")
        assert b.output_files == []
