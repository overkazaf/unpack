"""Native ELF (.so) binary analyzer with pure-Python ELF32/ELF64 fallback.

Inspects Android native libraries for architecture, security mitigations
(PIE, NX, RELRO, stack canary, stripped status), section Shannon entropy
(packing/encryption detection), JNI exports, dynamic dependencies, and
anti-debug / anti-Frida / VMP / DEX2C symbol indicators.

Works 100% offline with zero external dependencies via a pure-Python
ELF32/ELF64 parser, and optionally enriches symbol tables when ``lief`` is
installed.
"""

from __future__ import annotations

import hashlib
import math
import struct
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ELF constants
_ELF_MAGIC = b"\x7fELF"
_ELFCLASS32 = 1
_ELFCLASS64 = 2
_ELFDATA2LSB = 1
_ELFDATA2MSB = 2

_ET_EXEC = 2
_ET_DYN = 3

_PT_DYNAMIC = 2
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552

_PF_X = 0x1

_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHT_DYNAMIC = 6
_SHT_DYNSYM = 11

_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_BIND_NOW = 24
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6FFFFFFB
_DF_BIND_NOW = 0x8
_DF_1_NOW = 0x1

_EM_MAP: dict[int, str] = {
    3: "x86",
    40: "armeabi-v7a",
    62: "x86_64",
    183: "arm64-v8a",
    243: "riscv64",
}

_VMP_SYMBOL_PATTERNS: tuple[str, ...] = (
    "vmp", "vm_interpret", "vminterpret", "bytecode_handler",
    "vmp_entry", "vmpentry", "runvmp", "vmp_decode", "vm_exec",
)
_DEX2C_SYMBOL_PATTERNS: tuple[str, ...] = (
    "dex2c", "java2c", "dtcloader", "native_bridge",
)
_ANTI_DEBUG_PATTERNS: tuple[str, ...] = (
    "ptrace", "inotify_add_watch", "frida", "gum-js-loop",
    "tracerpid", "android_dlopen_ext", "anti_debug", "antidebug",
)
_CRYPTO_PATTERNS: tuple[str, ...] = (
    "aes_", "evp_encrypt", "evp_decrypt", "rc4", "chacha",
    "sha256", "hmac", "rsa_", "whitebox",
)
_SECURITY_LIB_KEYWORDS: tuple[str, ...] = (
    "jiagu", "shell", "protect", "shield", "guard", "sec", "safe",
    "vmp", "dexhelper", "chaos", "mogosec", "ijiami", "nqshield",
    "covault", "liapp", "dexprotector", "sgmain", "mobisec", "obfus",
)


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits/byte (range 0.0 .. 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    ent = 0.0
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)
    return round(ent, 3)


@dataclass
class ElfSectionInfo:
    name: str
    offset: int
    size: int
    entropy: float
    flags: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
            "entropy": self.entropy,
            "flags": self.flags,
        }


@dataclass
class NativeLibInfo:
    name: str
    path: str = ""
    abi: str = ""
    size_bytes: int = 0
    sha256: str = ""
    is_elf: bool = False
    elf_class: str = ""  # "ELF64" | "ELF32" | ""
    arch: str = ""
    is_pie: bool = False
    has_nx: bool = False
    relro: str = "none"  # "full" | "partial" | "none"
    has_canary: bool = False
    is_stripped: bool = True
    has_jni_onload: bool = False
    jni_exports: list[str] = field(default_factory=list)
    needed_libs: list[str] = field(default_factory=list)
    entropy: float = 0.0
    max_section_entropy: float = 0.0
    sections: list[ElfSectionInfo] = field(default_factory=list)
    vmp_indicators: list[str] = field(default_factory=list)
    dex2c_indicators: list[str] = field(default_factory=list)
    anti_debug_indicators: list[str] = field(default_factory=list)
    crypto_indicators: list[str] = field(default_factory=list)
    is_security_related: bool = False
    parser_backend: str = "builtin"
    risk_flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "abi": self.abi,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "is_elf": self.is_elf,
            "elf_class": self.elf_class,
            "arch": self.arch,
            "is_pie": self.is_pie,
            "has_nx": self.has_nx,
            "relro": self.relro,
            "has_canary": self.has_canary,
            "is_stripped": self.is_stripped,
            "has_jni_onload": self.has_jni_onload,
            "jni_exports": self.jni_exports,
            "needed_libs": self.needed_libs,
            "entropy": self.entropy,
            "max_section_entropy": self.max_section_entropy,
            "sections": [s.to_dict() for s in self.sections],
            "vmp_indicators": self.vmp_indicators,
            "dex2c_indicators": self.dex2c_indicators,
            "anti_debug_indicators": self.anti_debug_indicators,
            "crypto_indicators": self.crypto_indicators,
            "is_security_related": self.is_security_related,
            "parser_backend": self.parser_backend,
            "risk_flags": self.risk_flags,
        }


def _read_cstr(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end == -1:
        end = min(len(blob), offset + 256)
    return blob[offset:end].decode("utf-8", errors="replace")


def _infer_abi_from_path(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 3 and parts[0] == "lib":
        return parts[1]
    return ""


class NativeAnalyzer:
    """Analyzes native ELF ``.so`` files from bytes, disk, or inside APKs."""

    def analyze_bytes(
        self,
        data: bytes,
        name: str,
        abi: str = "",
        path: str = "",
    ) -> NativeLibInfo:
        info = NativeLibInfo(
            name=name,
            path=path or name,
            abi=abi or _infer_abi_from_path(path),
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            entropy=shannon_entropy(data[: 2 * 1024 * 1024]),
            is_security_related=any(kw in name.lower() for kw in _SECURITY_LIB_KEYWORDS),
        )

        if len(data) < 52 or data[:4] != _ELF_MAGIC:
            return info

        info.is_elf = True
        self._parse_elf_builtin(data, info)

        # Optional LIEF enrichment when available
        self._try_enrich_lief(data, info)

        # Derive risk flags
        self._compute_risk_flags(info)
        return info

    def analyze_file(self, so_path: Path, abi: str = "") -> NativeLibInfo:
        data = so_path.read_bytes()
        return self.analyze_bytes(data, name=so_path.name, abi=abi, path=str(so_path))

    def analyze_apk(
        self,
        apk_path: Path,
        max_libs: int = 200,
    ) -> list[NativeLibInfo]:
        results: list[NativeLibInfo] = []
        if not zipfile.is_zipfile(apk_path):
            return results
        with zipfile.ZipFile(apk_path, "r") as zf:
            so_entries = sorted(
                e for e in zf.namelist()
                if e.startswith("lib/") and e.endswith(".so")
            )
            for entry in so_entries[:max_libs]:
                try:
                    data = zf.read(entry)
                except (KeyError, zipfile.BadZipFile, OSError):
                    continue
                basename = entry.rsplit("/", 1)[-1]
                abi = _infer_abi_from_path(entry)
                results.append(self.analyze_bytes(data, name=basename, abi=abi, path=entry))
        return results

    # -- Builtin ELF32 / ELF64 parser --------------------------------------

    def _parse_elf_builtin(self, data: bytes, info: NativeLibInfo) -> None:
        ei_class = data[4]
        ei_data = data[5]
        if ei_class not in (_ELFCLASS32, _ELFCLASS64):
            return
        endian = "<" if ei_data == _ELFDATA2LSB else (">" if ei_data == _ELFDATA2MSB else "<")
        is64 = ei_class == _ELFCLASS64
        info.elf_class = "ELF64" if is64 else "ELF32"

        try:
            if is64:
                if len(data) < 64:
                    return
                e_type, e_machine = struct.unpack_from(f"{endian}HH", data, 16)
                e_phoff, e_shoff = struct.unpack_from(f"{endian}QQ", data, 32)
                e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                    f"{endian}5H", data, 54
                )
            else:
                e_type, e_machine = struct.unpack_from(f"{endian}HH", data, 16)
                e_phoff, e_shoff = struct.unpack_from(f"{endian}II", data, 28)
                e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                    f"{endian}5H", data, 42
                )
        except struct.error:
            return

        info.arch = _EM_MAP.get(e_machine, f"machine_{e_machine}")
        info.is_pie = e_type == _ET_DYN

        # Program headers: NX, RELRO, dynamic segment
        has_gnu_stack = False
        stack_exec = False
        has_relro = False
        bind_now = False
        dyn_file_off = 0
        dyn_file_size = 0

        if e_phoff > 0 and e_phnum > 0 and e_phentsize >= (56 if is64 else 32):
            for i in range(min(e_phnum, 256)):
                off = e_phoff + i * e_phentsize
                if off + (56 if is64 else 32) > len(data):
                    break
                if is64:
                    p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz = struct.unpack_from(
                        f"{endian}IIQQQQ", data, off
                    )
                else:
                    p_type, p_offset, _vaddr, _paddr, p_filesz, _memsz, p_flags = (
                        struct.unpack_from(f"{endian}7I", data, off)
                    )

                if p_type == _PT_GNU_STACK:
                    has_gnu_stack = True
                    stack_exec = bool(p_flags & _PF_X)
                elif p_type == _PT_GNU_RELRO:
                    has_relro = True
                elif p_type == _PT_DYNAMIC:
                    dyn_file_off = p_offset
                    dyn_file_size = p_filesz

        info.has_nx = has_gnu_stack and not stack_exec

        # Section headers
        raw_sections: list[tuple[int, int, int, int, int, int, int]] = []
        if e_shoff > 0 and e_shnum > 0 and e_shentsize >= (64 if is64 else 40):
            for i in range(min(e_shnum, 512)):
                off = e_shoff + i * e_shentsize
                if off + (64 if is64 else 40) > len(data):
                    break
                if is64:
                    (
                        sh_name, sh_type, sh_flags, _addr, sh_offset,
                        sh_size, sh_link, _info, _align, sh_entsize,
                    ) = struct.unpack_from(f"{endian}IIQQQQIIQQ", data, off)
                else:
                    (
                        sh_name, sh_type, sh_flags, _addr, sh_offset,
                        sh_size, sh_link, _info, _align, sh_entsize,
                    ) = struct.unpack_from(f"{endian}10I", data, off)
                raw_sections.append((sh_name, sh_type, sh_flags, sh_offset, sh_size, sh_link, sh_entsize))

        shstrtab = b""
        if 0 <= e_shstrndx < len(raw_sections):
            _, _, _, s_off, s_size, _, _ = raw_sections[e_shstrndx]
            if s_off + s_size <= len(data):
                shstrtab = data[s_off : s_off + s_size]

        has_symtab = False
        dynsym_sec: tuple[int, int, int, int] | None = None
        symtab_sec: tuple[int, int, int, int] | None = None
        dynamic_sec: tuple[int, int, int] | None = None

        max_ent = 0.0
        for sh_name, sh_type, sh_flags, sh_offset, sh_size, sh_link, sh_entsize in raw_sections:
            sec_name = _read_cstr(shstrtab, sh_name) if shstrtab else ""
            if sh_type == _SHT_SYMTAB:
                has_symtab = True
                symtab_sec = (sh_offset, sh_size, sh_link, sh_entsize)
            elif sh_type == _SHT_DYNSYM:
                dynsym_sec = (sh_offset, sh_size, sh_link, sh_entsize)
            elif sh_type == _SHT_DYNAMIC:
                dynamic_sec = (sh_offset, sh_size, sh_link)

            if sec_name and sh_size > 0 and sh_offset + sh_size <= len(data):
                # Cap per-section entropy sample at 1MB for speed
                sec_ent = shannon_entropy(data[sh_offset : sh_offset + min(sh_size, 1024 * 1024)])
                if sec_ent > max_ent:
                    max_ent = sec_ent
                info.sections.append(
                    ElfSectionInfo(
                        name=sec_name,
                        offset=sh_offset,
                        size=sh_size,
                        entropy=sec_ent,
                        flags=sh_flags,
                    )
                )

        info.is_stripped = not has_symtab
        info.max_section_entropy = round(max_ent, 3)

        # Parse .dynamic for DT_BIND_NOW / DT_FLAGS / DT_NEEDED
        dyn_off = dynamic_sec[0] if dynamic_sec else dyn_file_off
        dyn_sz = dynamic_sec[1] if dynamic_sec else dyn_file_size
        dynstr = b""
        if dynamic_sec and 0 <= dynamic_sec[2] < len(raw_sections):
            _, _, _, ds_off, ds_sz, _, _ = raw_sections[dynamic_sec[2]]
            if ds_off + ds_sz <= len(data):
                dynstr = data[ds_off : ds_off + ds_sz]

        needed_offsets: list[int] = []
        if dyn_off > 0 and dyn_sz > 0 and dyn_off + dyn_sz <= len(data):
            entry_sz = 16 if is64 else 8
            fmt = f"{endian}qQ" if is64 else f"{endian}iI"
            for off in range(dyn_off, dyn_off + dyn_sz - entry_sz + 1, entry_sz):
                d_tag, d_val = struct.unpack_from(fmt, data, off)
                if d_tag == _DT_NULL:
                    break
                if d_tag == _DT_BIND_NOW:
                    bind_now = True
                elif d_tag == _DT_FLAGS and (d_val & _DF_BIND_NOW):
                    bind_now = True
                elif d_tag == _DT_FLAGS_1 and (d_val & _DF_1_NOW):
                    bind_now = True
                elif d_tag == _DT_NEEDED:
                    needed_offsets.append(d_val)

        if dynstr and needed_offsets:
            info.needed_libs = [
                lib for lib in (_read_cstr(dynstr, off) for off in needed_offsets) if lib
            ]

        if has_relro:
            info.relro = "full" if bind_now else "partial"
        else:
            info.relro = "none"

        # Parse symbols from .dynsym (and .symtab if unstripped)
        symbols: set[str] = set()
        for sym_sec in (dynsym_sec, symtab_sec):
            if not sym_sec:
                continue
            s_off, s_size, s_link, s_entsize = sym_sec
            if s_link < 0 or s_link >= len(raw_sections):
                continue
            _, _, _, st_off, st_sz, _, _ = raw_sections[s_link]
            if st_off + st_sz > len(data):
                continue
            strtab = data[st_off : st_off + st_sz]
            ent_sz = s_entsize or (24 if is64 else 16)
            if ent_sz < 16 or s_off + s_size > len(data):
                continue
            count = min(s_size // ent_sz, 20000)
            for idx in range(count):
                pos = s_off + idx * ent_sz
                st_name = struct.unpack_from(f"{endian}I", data, pos)[0]
                if st_name == 0:
                    continue
                name = _read_cstr(strtab, st_name)
                if name:
                    symbols.add(name)

        self._classify_symbols(symbols, info)

    def _try_enrich_lief(self, data: bytes, info: NativeLibInfo) -> None:
        try:
            import lief  # type: ignore[import-not-found]
        except ImportError:
            return
        try:
            binary = lief.ELF.parse(list(data))
            if binary is None:
                return
            info.parser_backend = "lief"
            extra_syms = {s.name for s in binary.exported_symbols if s.name}
            extra_syms.update(s.name for s in binary.imported_symbols if s.name)
            self._classify_symbols(extra_syms, info)
        except Exception:
            pass

    @staticmethod
    def _classify_symbols(symbols: set[str], info: NativeLibInfo) -> None:
        jni_set = set(info.jni_exports)
        vmp_set = set(info.vmp_indicators)
        dex2c_set = set(info.dex2c_indicators)
        antidbg_set = set(info.anti_debug_indicators)
        crypto_set = set(info.crypto_indicators)

        for sym in symbols:
            lower = sym.lower()
            if sym == "JNI_OnLoad":
                info.has_jni_onload = True
            if sym.startswith("Java_") or sym == "JNI_OnLoad":
                jni_set.add(sym)
            if sym in ("__stack_chk_fail", "__stack_chk_guard"):
                info.has_canary = True
            for pat in _VMP_SYMBOL_PATTERNS:
                if pat in lower:
                    vmp_set.add(sym)
                    break
            for pat in _DEX2C_SYMBOL_PATTERNS:
                if pat in lower:
                    dex2c_set.add(sym)
                    break
            for pat in _ANTI_DEBUG_PATTERNS:
                if pat in lower:
                    antidbg_set.add(sym)
                    break
            for pat in _CRYPTO_PATTERNS:
                if pat in lower:
                    crypto_set.add(sym)
                    break

        info.jni_exports = sorted(jni_set)[:100]
        info.vmp_indicators = sorted(vmp_set)[:50]
        info.dex2c_indicators = sorted(dex2c_set)[:50]
        info.anti_debug_indicators = sorted(antidbg_set)[:50]
        info.crypto_indicators = sorted(crypto_set)[:50]

    @staticmethod
    def _compute_risk_flags(info: NativeLibInfo) -> None:
        flags: list[str] = []
        if info.is_elf:
            if not info.is_pie:
                flags.append("no_pie")
            if not info.has_nx:
                flags.append("executable_stack")
            if info.relro == "none":
                flags.append("no_relro")
            if not info.has_canary:
                flags.append("no_canary")
            if info.max_section_entropy >= 7.2 or info.entropy >= 7.2:
                flags.append("high_entropy_packed")
            if info.vmp_indicators:
                flags.append("vmp_symbols")
            if info.dex2c_indicators:
                flags.append("dex2c_symbols")
            if info.anti_debug_indicators:
                flags.append("anti_debug_symbols")
        info.risk_flags = flags
