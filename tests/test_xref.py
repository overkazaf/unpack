from __future__ import annotations

import hashlib
import json
import struct
import zlib

import pytest
from typer.testing import CliRunner

from unpack.analysis.xref import REFLECTION_SIGNATURES, XrefBuilder, XrefReport
from unpack.cli import app
from unpack.repair.dex_parser import DexFile

runner = CliRunner()


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


class _DexBuilder:
    """Minimal hand-rolled DEX builder for xref tests.

    Lays out string/type/field/method tables plus one class with one
    direct method whose code_item holds caller-supplied bytecode. Table
    offsets are explicit (not real-DEX-layout order), which is fine since
    DexFile only ever follows the header's *_off fields.
    """

    HEADER_SIZE = 0x70

    def __init__(self):
        self.strings: list[str] = []
        self.types: list[int] = []  # string idx per type
        self.fields: list[tuple[int, int, int]] = []  # (class_idx, type_idx, name_idx)
        self.methods: list[tuple[int, int, int]] = []  # (class_idx, proto_idx, name_idx)

    def add_string(self, s: str) -> int:
        self.strings.append(s)
        return len(self.strings) - 1

    def add_type(self, string_idx: int) -> int:
        self.types.append(string_idx)
        return len(self.types) - 1

    def add_field(self, class_idx: int, type_idx: int, name_idx: int) -> int:
        self.fields.append((class_idx, type_idx, name_idx))
        return len(self.fields) - 1

    def add_method(self, class_idx: int, proto_idx: int, name_idx: int) -> int:
        self.methods.append((class_idx, proto_idx, name_idx))
        return len(self.methods) - 1

    def build(
        self,
        class_idx: int,
        direct_methods: list[tuple[int, int, bytes, int, int]],
    ) -> bytes:
        """direct_methods: list of (method_idx, access_flags, insns, insns_size, registers_size)."""
        buf = bytearray(self.HEADER_SIZE)

        string_data_offs = []
        for s in self.strings:
            string_data_offs.append(len(buf))
            buf += _uleb128(len(s))
            buf += s.encode("utf-8")
            buf += b"\x00"

        string_ids_off = len(buf)
        for off in string_data_offs:
            buf += struct.pack("<I", off)

        type_ids_off = len(buf)
        for sidx in self.types:
            buf += struct.pack("<I", sidx)

        field_ids_off = len(buf)
        for (c, t, n) in self.fields:
            buf += struct.pack("<HHI", c, t, n)

        method_ids_off = len(buf)
        for (c, p, n) in self.methods:
            buf += struct.pack("<HHI", c, p, n)

        code_offs = []
        for (_midx, _access, insns, insns_size, regs) in direct_methods:
            while len(buf) % 4 != 0:
                buf += b"\x00"
            code_offs.append(len(buf))
            buf += struct.pack("<4H2I", regs, 0, 1, 0, 0, insns_size)
            buf += insns

        class_data_off = len(buf)
        buf += _uleb128(0)  # static_fields_size
        buf += _uleb128(0)  # instance_fields_size
        buf += _uleb128(len(direct_methods))
        buf += _uleb128(0)  # virtual_methods_size

        prev_idx = 0
        for (midx, access, _insns, _insns_size, _regs), code_off in zip(direct_methods, code_offs):
            buf += _uleb128(midx - prev_idx)
            prev_idx = midx
            buf += _uleb128(access)
            buf += _uleb128(code_off)

        class_defs_off = len(buf)
        no_index = 0xFFFFFFFF
        buf += struct.pack(
            "<8I",
            class_idx, 0x1, no_index, 0, no_index, 0, class_data_off, 0,
        )

        data_off = self.HEADER_SIZE
        data_size = len(buf) - data_off
        file_size = len(buf)

        buf[0:8] = b"dex\n035\x00"
        struct.pack_into("<I", buf, 32, file_size)
        struct.pack_into("<I", buf, 36, self.HEADER_SIZE)
        struct.pack_into("<I", buf, 40, 0x12345678)
        struct.pack_into("<I", buf, 44, 0)
        struct.pack_into("<I", buf, 48, 0)
        struct.pack_into("<I", buf, 52, 0)
        struct.pack_into("<I", buf, 56, len(self.strings))
        struct.pack_into("<I", buf, 60, string_ids_off)
        struct.pack_into("<I", buf, 64, len(self.types))
        struct.pack_into("<I", buf, 68, type_ids_off)
        struct.pack_into("<I", buf, 72, 0)
        struct.pack_into("<I", buf, 76, 0)
        struct.pack_into("<I", buf, 80, len(self.fields))
        struct.pack_into("<I", buf, 84, field_ids_off)
        struct.pack_into("<I", buf, 88, len(self.methods))
        struct.pack_into("<I", buf, 92, method_ids_off)
        struct.pack_into("<I", buf, 96, 1)
        struct.pack_into("<I", buf, 100, class_defs_off)
        struct.pack_into("<I", buf, 104, data_size)
        struct.pack_into("<I", buf, 108, data_off)

        sig = hashlib.sha1(bytes(buf[32:])).digest()
        buf[12:32] = sig
        checksum = zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF
        struct.pack_into("<I", buf, 8, checksum)

        return bytes(buf)


def _build_xref_dex() -> bytes:
    """One class (LMain;) with one method (main) whose body:

    - const-strings "secret"
    - invoke-static Ljava/lang/Class;->forName   (reflection sink)
    - iget LMain;->value:I                        (field ref)
    - invoke-static LHelper;->doWork              (plain method call)
    - return-void
    """
    b = _DexBuilder()

    s_lmain = b.add_string("LMain;")
    s_main = b.add_string("main")
    s_secret = b.add_string("secret")
    s_class = b.add_string("Ljava/lang/Class;")
    s_forname = b.add_string("forName")
    s_value = b.add_string("value")
    s_int = b.add_string("I")
    s_lhelper = b.add_string("LHelper;")
    s_dowork = b.add_string("doWork")

    t_lmain = b.add_type(s_lmain)
    t_class = b.add_type(s_class)
    t_int = b.add_type(s_int)
    b.add_type(s_lhelper)

    f_value = b.add_field(t_lmain, t_int, s_value)

    m_main = b.add_method(t_lmain, 0, s_main)
    m_forname = b.add_method(t_class, 0, s_forname)
    m_dowork = b.add_method(3, 0, s_dowork)  # type idx 3 == LHelper;

    insns = bytearray()
    insns += bytes([0x1a, 0x00, s_secret & 0xFF, (s_secret >> 8) & 0xFF])
    insns += bytes([0x71, 0x00, m_forname & 0xFF, (m_forname >> 8) & 0xFF, 0, 0])
    insns += bytes([0x52, 0x12, f_value & 0xFF, (f_value >> 8) & 0xFF])
    insns += bytes([0x71, 0x00, m_dowork & 0xFF, (m_dowork >> 8) & 0xFF, 0, 0])
    insns += bytes([0x0e, 0x00])

    insns_size = len(insns) // 2
    return b.build(t_lmain, [(m_main, 0x0008, bytes(insns), insns_size, 3)])


@pytest.fixture
def xref_dex_bytes() -> bytes:
    return _build_xref_dex()


@pytest.fixture
def builder() -> XrefBuilder:
    return XrefBuilder()


class TestXrefReport:
    def test_to_dict_structure(self):
        report = XrefReport()
        d = report.to_dict()
        assert set(d.keys()) == {"string_refs", "method_calls", "field_refs", "reflection_calls"}
        assert d["string_refs"] == {}
        assert d["method_calls"] == {}
        assert d["field_refs"] == {}
        assert d["reflection_calls"] == []


class TestXrefBuilderEmptyDex:
    def test_empty_dex_produces_empty_report(self, builder, synthetic_dex_bytes):
        report = builder.build(synthetic_dex_bytes)
        assert isinstance(report, XrefReport)
        assert report.string_refs == {}
        assert report.method_calls == {}
        assert report.field_refs == {}
        assert report.reflection_calls == []

    def test_corrupt_dex_produces_empty_report_not_raise(self, builder):
        report = builder.build(b"not a dex file at all")
        assert report.to_dict() == XrefReport().to_dict()

    def test_build_file_from_disk(self, builder, tmp_dex):
        report = builder.build_file(tmp_dex)
        assert report.string_refs == {}


class TestXrefBuilderRealMethod:
    def test_string_ref_collected(self, builder, xref_dex_bytes):
        report = builder.build(xref_dex_bytes)
        assert "secret" in report.string_refs
        assert report.string_refs["secret"] == [{"class": "LMain;", "method": "main"}]

    def test_method_call_collected(self, builder, xref_dex_bytes):
        report = builder.build(xref_dex_bytes)
        assert "LHelper;->doWork" in report.method_calls
        assert report.method_calls["LHelper;->doWork"] == [{"class": "LMain;", "method": "main"}]

    def test_field_ref_collected(self, builder, xref_dex_bytes):
        report = builder.build(xref_dex_bytes)
        assert "LMain;->value" in report.field_refs
        assert report.field_refs["LMain;->value"] == [{"class": "LMain;", "method": "main"}]

    def test_reflection_call_detected(self, builder, xref_dex_bytes):
        report = builder.build(xref_dex_bytes)
        assert len(report.reflection_calls) == 1
        call = report.reflection_calls[0]
        assert call["target"] == "Ljava/lang/Class;->forName"
        assert call["caller"] == {"class": "LMain;", "method": "main"}
        assert call["offset"] == 4

    def test_reflection_target_also_in_method_calls(self, builder, xref_dex_bytes):
        report = builder.build(xref_dex_bytes)
        assert "Ljava/lang/Class;->forName" in report.method_calls

    def test_non_reflection_call_not_flagged(self, builder, xref_dex_bytes):
        report = builder.build(xref_dex_bytes)
        targets = {c["target"] for c in report.reflection_calls}
        assert "LHelper;->doWork" not in targets

    def test_build_dex_matches_build_bytes(self, builder, xref_dex_bytes):
        dex = DexFile.parse(xref_dex_bytes)
        report_a = builder.build_dex(dex)
        report_b = builder.build(xref_dex_bytes)
        assert report_a.to_dict() == report_b.to_dict()


class TestReflectionSignatures:
    def test_known_sinks_present(self):
        assert ("Ljava/lang/Class;", "forName") in REFLECTION_SIGNATURES
        assert ("Ljava/lang/reflect/Method;", "invoke") in REFLECTION_SIGNATURES
        assert ("Ldalvik/system/DexClassLoader;", "<init>") in REFLECTION_SIGNATURES

    def test_unrelated_pair_absent(self):
        assert ("LHelper;", "doWork") not in REFLECTION_SIGNATURES


class TestXrefBuilderMerge:
    def test_merge_combines_callers(self, builder, xref_dex_bytes, synthetic_dex_bytes):
        report_a = builder.build(xref_dex_bytes)
        report_b = builder.build(synthetic_dex_bytes)
        merged = XrefBuilder.merge([report_a, report_b])
        assert merged.string_refs == report_a.string_refs
        assert merged.reflection_calls == report_a.reflection_calls

    def test_merge_empty_list(self):
        merged = XrefBuilder.merge([])
        assert merged.to_dict() == XrefReport().to_dict()


class TestXrefCli:
    def test_xref_help(self):
        result = runner.invoke(app, ["xref", "--help"])
        assert result.exit_code == 0

    def test_xref_nonexistent(self):
        result = runner.invoke(app, ["xref", "nonexistent.dex"])
        assert result.exit_code != 0

    def test_xref_single_file(self, tmp_path, xref_dex_bytes):
        dex_path = tmp_path / "classes.dex"
        dex_path.write_bytes(xref_dex_bytes)
        result = runner.invoke(app, ["xref", str(dex_path)])
        assert result.exit_code == 0
        assert "XREF" in result.output.upper()
        assert "forName" in result.output

    def test_xref_json_output(self, tmp_path, xref_dex_bytes):
        dex_path = tmp_path / "classes.dex"
        dex_path.write_bytes(xref_dex_bytes)
        out = tmp_path / "xref.json"
        result = runner.invoke(app, ["xref", str(dex_path), "--json", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "string_refs" in data
        assert "reflection_calls" in data
        assert data["reflection_calls"][0]["target"] == "Ljava/lang/Class;->forName"

    def test_xref_json_stdout_pipe(self, tmp_path, xref_dex_bytes):
        dex_path = tmp_path / "classes.dex"
        dex_path.write_bytes(xref_dex_bytes)
        result = runner.invoke(app, ["xref", str(dex_path), "--json", "-"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "method_calls" in data
