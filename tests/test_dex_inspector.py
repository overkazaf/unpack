from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib

from unpack.analysis.dex_inspector import DexInspector
from unpack.analysis.disasm import FullDalvikDisassembler
from unpack.analysis.vmp import VmpDetector
from unpack.analysis.xref import XrefBuilder
from unpack.repack.repacker import Repacker
from unpack.repair.dex_repair import DexRepairPipeline
from unpack.repair.verifier import DexVerifier


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


def _build_rich_dex() -> bytes:
    """Build a valid DEX containing two classes with normal, NOP, and VMP-stub methods."""
    strings = [
        "Lcom/acme/app/Main;",
        "Lcom/acme/packer/Disp;",
        "Ljava/lang/Object;",
        "I",
        "V",
        "run",
        "secret",
        "exec",
        "https://api.acme.example/v1/auth",
        "count",
    ]
    types = [0, 1, 2, 3, 4]  # LMain, LDisp, LObject, I, V
    protos = [(4, 4, 0)]  # shorty="V", ret=V, params=0
    fields = [(0, 3, 9)]  # Main->count:I
    methods = [
        (0, 0, 5),  # 0: Main->run()V
        (0, 0, 6),  # 1: Main->secret()V
        (1, 0, 7),  # 2: Disp->exec()V
    ]

    buf = bytearray(0x70)
    str_offs = []
    for s in strings:
        str_offs.append(len(buf))
        buf += _uleb128(len(s)) + s.encode("utf-8") + b"\x00"

    string_ids_off = len(buf)
    for o in str_offs:
        buf += struct.pack("<I", o)

    type_ids_off = len(buf)
    for tidx in types:
        buf += struct.pack("<I", tidx)

    proto_ids_off = len(buf)
    for sh, rt, po in protos:
        buf += struct.pack("<3I", sh, rt, po)

    field_ids_off = len(buf)
    for c, t, n in fields:
        buf += struct.pack("<HHI", c, t, n)

    method_ids_off = len(buf)
    for c, p, n in methods:
        buf += struct.pack("<HHI", c, p, n)

    # Method 0 (Main->run): const/4 v0, #1; const-string v1, url; invoke-static Disp->exec; return-void
    insns_normal = (
        bytes([0x12, 0x10])
        + bytes([0x1A, 0x01, 8, 0])
        + bytes([0x71, 0x00, 2, 0, 0, 0])
        + bytes([0x0E, 0x00])
    )
    # Method 1 (Main->secret): VMP stub (bare invoke-static Disp->exec, 3 units)
    insns_vmp = bytes([0x71, 0x00, 2, 0, 0, 0])
    # Method 2 (Disp->exec): NOP-filled (4 units)
    insns_nop = b"\x00\x00" * 4

    def _append_ci(code: bytes) -> int:
        while len(buf) % 4 != 0:
            buf.append(0)
        off = len(buf)
        buf.extend(struct.pack("<4H2I", 2, 0, 0, 0, 0, len(code) // 2))
        buf.extend(code)
        return off

    ci_normal = _append_ci(insns_normal)
    ci_vmp = _append_ci(insns_vmp)
    ci_nop = _append_ci(insns_nop)

    # class_data for Main (1 field, 2 direct methods)
    cd_main = len(buf)
    buf += _uleb128(1) + _uleb128(0) + _uleb128(2) + _uleb128(0)
    buf += _uleb128(0) + _uleb128(0x0009)  # public static count
    buf += _uleb128(0) + _uleb128(0x0009) + _uleb128(ci_normal)
    buf += _uleb128(1) + _uleb128(0x0002) + _uleb128(ci_vmp)

    # class_data for Disp (0 fields, 1 direct method)
    cd_disp = len(buf)
    buf += _uleb128(0) + _uleb128(0) + _uleb128(1) + _uleb128(0)
    buf += _uleb128(2) + _uleb128(0x0009) + _uleb128(ci_nop)

    while len(buf) % 4 != 0:
        buf.append(0)
    class_defs_off = len(buf)
    buf += struct.pack("<8I", 0, 0x1, 2, 0, 0xFFFFFFFF, 0, cd_main, 0)
    buf += struct.pack("<8I", 1, 0x1, 2, 0, 0xFFFFFFFF, 0, cd_disp, 0)

    file_size = len(buf)
    buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 32, file_size)
    struct.pack_into("<I", buf, 36, 0x70)
    struct.pack_into("<I", buf, 40, 0x12345678)
    struct.pack_into("<I", buf, 56, len(strings))
    struct.pack_into("<I", buf, 60, string_ids_off)
    struct.pack_into("<I", buf, 64, len(types))
    struct.pack_into("<I", buf, 68, type_ids_off)
    struct.pack_into("<I", buf, 72, len(protos))
    struct.pack_into("<I", buf, 76, proto_ids_off)
    struct.pack_into("<I", buf, 80, len(fields))
    struct.pack_into("<I", buf, 84, field_ids_off)
    struct.pack_into("<I", buf, 88, len(methods))
    struct.pack_into("<I", buf, 92, method_ids_off)
    struct.pack_into("<I", buf, 96, 2)
    struct.pack_into("<I", buf, 100, class_defs_off)
    struct.pack_into("<I", buf, 104, file_size - 0x70)
    struct.pack_into("<I", buf, 108, 0x70)

    buf[12:32] = hashlib.sha1(bytes(buf[32:])).digest()
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF)
    return bytes(buf)


class TestDexInspector:
    def test_summary_and_package_tree(self):
        dex_bytes = _build_rich_dex()
        insp = DexInspector.from_bytes(dex_bytes, name="classes.dex")
        ov = insp.summary()
        assert ov.class_count == 2
        assert ov.nop_method_count == 1
        assert ov.vmp_stub_count == 1
        assert ov.dex_version == "035"
        assert "sha256" in ov.to_dict()

        tree = insp.package_tree()
        pkgs = {n.package: n for n in tree}
        assert "com.acme.app" in pkgs
        assert "com.acme.packer" in pkgs
        assert pkgs["com.acme.app"].vmp_count == 1
        assert pkgs["com.acme.packer"].nop_count == 1

    def test_list_classes_filtering_and_pagination(self):
        insp = DexInspector.from_bytes(_build_rich_dex())
        page = insp.list_classes(query="Main")
        assert page.total == 1
        assert page.items[0].java_name == "com.acme.app.Main"
        assert page.items[0].health == "vmp_stub"

        nop_page = insp.list_classes(health="nop")
        assert nop_page.total == 1
        assert nop_page.items[0].simple_name == "Disp"

    def test_inspect_class_and_disassemble_method(self):
        insp = DexInspector.from_bytes(_build_rich_dex())
        detail = insp.inspect_class("com.acme.app.Main")
        assert detail is not None
        assert detail.superclass == "java.lang.Object"
        assert len(detail.fields) == 1
        assert detail.fields[0].name == "count"
        assert len(detail.methods) == 2

        disasm = insp.disassemble_method("com.acme.app.Main", "run")
        assert disasm is not None
        assert disasm.signature == "()V"
        assert disasm.code_off > 0
        assert disasm.to_dict()["code_off"] == disasm.code_off
        mnemonics = [i.mnemonic for i in disasm.instructions]
        assert mnemonics == ["const/4", "const-string", "invoke-static", "return-void"]
        assert "https://api.acme.example/v1/auth" in disasm.instructions[1].resolved_ref
        assert "Lcom/acme/packer/Disp;->exec()V" in disasm.instructions[2].resolved_ref

    def test_search_strings_categorization(self):
        insp = DexInspector.from_bytes(_build_rich_dex())
        urls = insp.search_strings(category="url")
        assert len(urls) == 1
        assert "api.acme.example" in urls[0].value

    def test_from_apk(self, tmp_path):
        apk = tmp_path / "multi.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", _build_rich_dex())
        inspectors = DexInspector.from_apk(apk)
        assert "classes.dex" in inspectors
        assert inspectors["classes.dex"].summary().class_count == 2


class TestRepairDiffAndVmpXrefRepack:
    def test_repair_with_diff_improves_health(self, tmp_path, synthetic_dex):
        data = bytearray(synthetic_dex)
        struct.pack_into("<I", data, 32, 999999)  # wrong file_size
        struct.pack_into("<I", data, 8, 0xDEADBEEF)  # wrong checksum
        broken = tmp_path / "broken.dex"
        broken.write_bytes(bytes(data))

        diff = DexRepairPipeline().repair_with_diff(broken)
        assert diff.before.valid is False
        assert diff.after.valid is True
        assert diff.health_delta > 0
        assert len(diff.resolved_issues) >= 2
        assert any(fd.field == "file_size" for fd in diff.field_diffs)
        assert "field_diffs" in diff.to_dict()

    def test_verifier_bytes_and_to_dict(self, synthetic_dex_bytes):
        vr = DexVerifier().verify_bytes(synthetic_dex_bytes)
        assert vr.valid is True
        assert vr.health_score == 100.0
        d = vr.to_dict()
        assert d["health_score"] == 100.0
        assert len(d["checks"]) >= 5

    def test_vmp_detailed_dict_preserves_to_dict(self):
        report = VmpDetector().analyze_dex(_build_rich_dex())
        assert set(report.to_dict().keys()) == {
            "total_methods", "normal_count", "nop_count",
            "vmp_count", "vmp_methods", "call_graph",
        }
        detailed = report.to_detailed_dict()
        assert detailed["vmp_count"] == 1
        assert detailed["verdict"] == "partial_vmp"
        assert len(detailed["dispatchers"]) == 1
        assert detailed["risk_score"] >= 30

    def test_xref_summary_preserves_to_dict(self):
        report = XrefBuilder().build(_build_rich_dex())
        assert set(report.to_dict().keys()) == {
            "string_refs", "method_calls", "field_refs", "reflection_calls",
        }
        summary = report.summary(limit=10)
        assert len(summary["iocs"]["urls"]) == 1
        assert summary["counts"]["strings"] >= 1

    def test_repacker_strips_stale_signatures_and_to_dict(self, tmp_path, synthetic_dex_bytes):
        apk = tmp_path / "signed.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("classes.dex", b"OLD")
            zf.writestr("AndroidManifest.xml", b"MANIFEST")
            zf.writestr("META-INF/MANIFEST.MF", b"mf")
            zf.writestr("META-INF/CERT.SF", b"sf")
            zf.writestr("META-INF/CERT.RSA", b"rsa")
        dex_dir = tmp_path / "dex"
        dex_dir.mkdir()
        (dex_dir / "classes.dex").write_bytes(synthetic_dex_bytes)

        res = Repacker().repack(apk, dex_dir, tmp_path / "out")
        assert res.success is True
        assert res.signatures_stripped == 3
        assert len(res.output_sha256) == 64
        with zipfile.ZipFile(res.output_path) as zf:
            assert "META-INF/CERT.RSA" not in zf.namelist()
            assert "AndroidManifest.xml" in zf.namelist()
        d = res.to_dict()
        assert d["signatures_stripped"] == 3
        assert d["output_size_bytes"] > 0

    def test_full_disassembler_handles_256_opcodes(self):
        # const/16 (2 units) + if-eqz (2 units) + return-void (1 unit)
        insns = bytes([0x13, 0x00, 0x2A, 0x00, 0x38, 0x00, 0x02, 0x00, 0x0E, 0x00])
        out = FullDalvikDisassembler().disassemble(insns, insns_size=5)
        assert [i.mnemonic for i in out] == ["const/16", "if-eqz", "return-void"]
        assert out[0].operands == "v0, #42"
