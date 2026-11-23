from __future__ import annotations

import os
import struct
import zipfile

from unpack.analysis.native import NativeAnalyzer, NativeLibInfo, shannon_entropy


def _build_synthetic_elf64(
    *,
    e_type: int = 3,  # ET_DYN (PIE)
    e_machine: int = 183,  # AArch64
    nx_stack: bool = True,
    relro: str = "full",  # "full" | "partial" | "none"
    symbols: list[str] | None = None,
    needed: list[str] | None = None,
    payload: bytes = b"\x00" * 64,
    stripped: bool = True,
) -> bytes:
    """Build a minimal valid ELF64 binary for testing the pure-Python ELF parser."""
    symbols = symbols or []
    needed = needed or []

    # Build .shstrtab
    shstr_names = [b"", b".shstrtab", b".text", b".dynstr", b".dynsym", b".dynamic"]
    if not stripped:
        shstr_names.append(b".symtab")
    shstrtab = bytearray()
    shstr_offs: dict[bytes, int] = {}
    for name in shstr_names:
        shstr_offs[name] = len(shstrtab)
        shstrtab += name + b"\x00"

    # Build .dynstr
    dynstr = bytearray(b"\x00")
    sym_offs: list[int] = []
    for s in symbols:
        sym_offs.append(len(dynstr))
        dynstr += s.encode("utf-8") + b"\x00"
    needed_offs: list[int] = []
    for lib in needed:
        needed_offs.append(len(dynstr))
        dynstr += lib.encode("utf-8") + b"\x00"

    # Build .dynsym (ELF64 Sym = 24 bytes: I, B, B, H, Q, Q)
    dynsym = bytearray(24)  # null symbol
    for off in sym_offs:
        dynsym += struct.pack("<IBBHQQ", off, 0x12, 0, 1, 0x1000, 16)

    # Build .dynamic (ELF64 Dyn = 16 bytes: q, Q)
    dynamic = bytearray()
    for noff in needed_offs:
        dynamic += struct.pack("<qQ", 1, noff)  # DT_NEEDED
    if relro == "full":
        dynamic += struct.pack("<qQ", 24, 0)  # DT_BIND_NOW
    dynamic += struct.pack("<qQ", 0, 0)  # DT_NULL

    # Program headers: PT_GNU_STACK + optional PT_GNU_RELRO
    ph_entries: list[bytes] = []
    stack_flags = 0x6 if nx_stack else 0x7  # RW vs RWX
    ph_entries.append(struct.pack("<IIQQQQQQ", 0x6474E551, stack_flags, 0, 0, 0, 0, 0, 16))
    if relro in ("partial", "full"):
        ph_entries.append(struct.pack("<IIQQQQQQ", 0x6474E552, 0x4, 0, 0, 0, 0, 0, 8))

    ehdr_size = 64
    phoff = ehdr_size
    ph_blob = b"".join(ph_entries)

    cur = phoff + len(ph_blob)
    text_off = cur
    cur += len(payload)
    shstr_off = cur
    cur += len(shstrtab)
    dynstr_off = cur
    cur += len(dynstr)
    dynsym_off = cur
    cur += len(dynsym)
    dynamic_off = cur
    cur += len(dynamic)

    shoff = cur
    # Section header: 64 bytes (<IIQQQQIIQQ)
    sections = [
        # 0: NULL
        struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        # 1: .shstrtab
        struct.pack("<IIQQQQIIQQ", shstr_offs[b".shstrtab"], 3, 0, 0, shstr_off, len(shstrtab), 0, 0, 1, 0),
        # 2: .text
        struct.pack("<IIQQQQIIQQ", shstr_offs[b".text"], 1, 6, 0x1000, text_off, len(payload), 0, 0, 16, 0),
        # 3: .dynstr
        struct.pack("<IIQQQQIIQQ", shstr_offs[b".dynstr"], 3, 2, 0, dynstr_off, len(dynstr), 0, 0, 1, 0),
        # 4: .dynsym (link=3 -> .dynstr)
        struct.pack("<IIQQQQIIQQ", shstr_offs[b".dynsym"], 11, 2, 0, dynsym_off, len(dynsym), 3, 0, 8, 24),
        # 5: .dynamic (link=3 -> .dynstr)
        struct.pack("<IIQQQQIIQQ", shstr_offs[b".dynamic"], 6, 3, 0, dynamic_off, len(dynamic), 3, 0, 8, 16),
    ]
    if not stripped:
        sections.append(
            struct.pack("<IIQQQQIIQQ", shstr_offs[b".symtab"], 2, 0, 0, dynsym_off, len(dynsym), 3, 0, 8, 24)
        )

    e_ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,
        e_machine,
        1,  # EV_CURRENT
        0,  # e_entry
        phoff,
        shoff,
        0,  # e_flags
        ehdr_size,
        56,
        len(ph_entries),
        64,
        len(sections),
        1,  # e_shstrndx
    )

    return bytes(ehdr + ph_blob + payload + shstrtab + dynstr + dynsym + dynamic + b"".join(sections))


class TestShannonEntropy:
    def test_zero_bytes_zero_entropy(self):
        assert shannon_entropy(b"\x00" * 256) == 0.0

    def test_empty_bytes(self):
        assert shannon_entropy(b"") == 0.0

    def test_high_entropy_random(self):
        data = os.urandom(4096)
        assert shannon_entropy(data) > 7.5


class TestNativeAnalyzerBuiltinElf:
    def test_hardened_elf64_all_mitigations(self):
        elf = _build_synthetic_elf64(
            nx_stack=True,
            relro="full",
            symbols=["JNI_OnLoad", "Java_com_demo_Main_check", "__stack_chk_fail"],
            needed=["libc.so", "liblog.so"],
            stripped=True,
        )
        info = NativeAnalyzer().analyze_bytes(elf, name="libdemo.so", path="lib/arm64-v8a/libdemo.so")
        assert isinstance(info, NativeLibInfo)
        assert info.is_elf is True
        assert info.elf_class == "ELF64"
        assert info.arch == "arm64-v8a"
        assert info.abi == "arm64-v8a"
        assert info.is_pie is True
        assert info.has_nx is True
        assert info.relro == "full"
        assert info.has_canary is True
        assert info.is_stripped is True
        assert info.has_jni_onload is True
        assert "Java_com_demo_Main_check" in info.jni_exports
        assert "libc.so" in info.needed_libs
        assert info.risk_flags == []

        d = info.to_dict()
        assert d["is_elf"] is True
        assert d["relro"] == "full"
        assert len(d["sections"]) >= 1

    def test_weak_elf_and_vmp_antidebug_symbols(self):
        high_ent = os.urandom(8192)
        elf = _build_synthetic_elf64(
            e_type=2,  # ET_EXEC (non-PIE)
            nx_stack=False,
            relro="none",
            symbols=["vmp_interpret_entry", "ptrace", "dex2c_bridge", "AES_encrypt"],
            payload=high_ent,
            stripped=False,
        )
        info = NativeAnalyzer().analyze_bytes(elf, name="libjiagu_vmp.so", abi="arm64-v8a")
        assert info.is_pie is False
        assert info.has_nx is False
        assert info.relro == "none"
        assert info.has_canary is False
        assert info.is_stripped is False
        assert info.is_security_related is True
        assert info.max_section_entropy > 7.2
        assert "vmp_interpret_entry" in info.vmp_indicators
        assert "dex2c_bridge" in info.dex2c_indicators
        assert "ptrace" in info.anti_debug_indicators
        assert "AES_encrypt" in info.crypto_indicators
        assert "no_pie" in info.risk_flags
        assert "executable_stack" in info.risk_flags
        assert "no_relro" in info.risk_flags
        assert "high_entropy_packed" in info.risk_flags
        assert "vmp_symbols" in info.risk_flags

    def test_non_elf_data_graceful(self):
        info = NativeAnalyzer().analyze_bytes(b"not an elf binary", name="libfake.so", abi="x86_64")
        assert info.is_elf is False
        assert info.abi == "x86_64"
        assert info.size_bytes == 17
        assert info.sha256 != ""

    def test_analyze_apk(self, tmp_path):
        apk = tmp_path / "sample.apk"
        elf = _build_synthetic_elf64(symbols=["JNI_OnLoad"])
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("lib/arm64-v8a/libfoo.so", elf)
            zf.writestr("lib/armeabi-v7a/libbar.so", b"not_elf")
        libs = NativeAnalyzer().analyze_apk(apk)
        assert len(libs) == 2
        by_abi = {l.abi: l for l in libs}
        assert by_abi["arm64-v8a"].is_elf is True
        assert by_abi["armeabi-v7a"].is_elf is False
