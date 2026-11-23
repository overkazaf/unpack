"""Minimal Dalvik bytecode disassembler.

Decodes a DEX method's raw ``insns`` byte stream into a flat list of
:class:`Instruction` records. This is intentionally not a full Dalvik
disassembler — it covers the handful of opcode families that matter for
static analysis of packer-touched code: control transfer out of a method
(``invoke-*``), literal pool references (``const-string*``, ``const-class``,
``check-cast``, ``new-instance``), and field access (``iget*``/``sget*``/
``sput*`` etc). Everything else is decoded as an opaque, correctly-sized
instruction for the formats this module understands, or as a single
code-unit ``op_XX`` placeholder for anything it doesn't — so callers that
just need to walk the instruction stream without derailing on an
unsupported opcode can still do so.

Opcode reference: https://source.android.com/docs/core/runtime/dalvik-bytecode
"""

from __future__ import annotations

from dataclasses import dataclass

# Code-unit size (16-bit units) for each Dalvik instruction format this
# decoder understands.
FORMAT_SIZES: dict[str, int] = {
    "10x": 1,
    "11x": 1,
    "21c": 2,
    "22c": 2,
    "31c": 3,
    "35c": 3,
    "3rc": 3,
}

# ref_kind identifies which DEX table an instruction's index operand
# resolves against; this maps 1:1 to the Instruction.*_idx field it fills.
_STRING = "string"
_TYPE = "type"
_METHOD = "method"
_FIELD = "field"

# opcode -> (mnemonic, format, ref_kind or None)
OPCODE_TABLE: dict[int, tuple[str, str, str | None]] = {
    0x00: ("nop", "10x", None),
    0x0e: ("return-void", "11x", None),
    0x0f: ("return", "11x", None),
    0x10: ("return-wide", "11x", None),
    0x11: ("return-object", "11x", None),
    0x1a: ("const-string", "21c", _STRING),
    0x1b: ("const-string/jumbo", "31c", _STRING),
    0x1c: ("const-class", "21c", _TYPE),
    0x1f: ("check-cast", "21c", _TYPE),
    0x22: ("new-instance", "21c", _TYPE),
    # iget/iput family (22c, field ref)
    0x52: ("iget", "22c", _FIELD),
    0x53: ("iget-wide", "22c", _FIELD),
    0x54: ("iget-object", "22c", _FIELD),
    0x55: ("iget-boolean", "22c", _FIELD),
    0x56: ("iget-byte", "22c", _FIELD),
    0x57: ("iget-char", "22c", _FIELD),
    0x58: ("iget-short", "22c", _FIELD),
    0x59: ("iput", "22c", _FIELD),
    0x5a: ("iput-wide", "22c", _FIELD),
    0x5b: ("iput-object", "22c", _FIELD),
    0x5c: ("iput-boolean", "22c", _FIELD),
    # sget/sput family (21c, field ref)
    0x60: ("sget", "21c", _FIELD),
    0x61: ("sget-wide", "21c", _FIELD),
    0x62: ("sget-object", "21c", _FIELD),
    0x63: ("sget-boolean", "21c", _FIELD),
    0x64: ("sget-byte", "21c", _FIELD),
    0x65: ("sget-char", "21c", _FIELD),
    0x66: ("sget-short", "21c", _FIELD),
    0x67: ("sput", "21c", _FIELD),
    0x68: ("sput-wide", "21c", _FIELD),
    0x69: ("sput-object", "21c", _FIELD),
    0x6a: ("sput-boolean", "21c", _FIELD),
    # invoke-* (35c, method ref)
    0x6e: ("invoke-virtual", "35c", _METHOD),
    0x6f: ("invoke-super", "35c", _METHOD),
    0x70: ("invoke-direct", "35c", _METHOD),
    0x71: ("invoke-static", "35c", _METHOD),
    0x72: ("invoke-interface", "35c", _METHOD),
    # invoke-*/range (3rc, method ref)
    0x74: ("invoke-virtual/range", "3rc", _METHOD),
    0x75: ("invoke-super/range", "3rc", _METHOD),
    0x76: ("invoke-direct/range", "3rc", _METHOD),
    0x77: ("invoke-static/range", "3rc", _METHOD),
    0x78: ("invoke-interface/range", "3rc", _METHOD),
}


@dataclass
class Instruction:
    """A single decoded Dalvik instruction.

    ``offset`` is the byte offset of the instruction within the method's
    ``insns`` buffer. ``size`` is the instruction length in 16-bit code
    units. At most one of ``string_idx`` / ``type_idx`` / ``method_idx`` /
    ``field_idx`` is set, identifying which DEX table the decoded index
    operand (if any) belongs to.
    """

    offset: int
    opcode: int
    mnemonic: str
    size: int
    string_idx: int | None = None
    type_idx: int | None = None
    method_idx: int | None = None
    field_idx: int | None = None


class DalvikDecoder:
    """Decodes raw Dalvik ``insns`` bytes into :class:`Instruction` records."""

    def decode_one(self, insns: bytes, pos: int) -> Instruction:
        """Decode a single instruction starting at byte offset ``pos``.

        Unknown opcodes decode as a 1-code-unit ``op_XX`` placeholder so the
        caller can keep walking the stream.
        """
        opcode = insns[pos]
        entry = OPCODE_TABLE.get(opcode)
        if entry is None:
            return Instruction(offset=pos, opcode=opcode, mnemonic=f"op_{opcode:02X}", size=1)

        mnemonic, fmt, ref_kind = entry
        size = FORMAT_SIZES[fmt]
        kwargs: dict[str, int] = {}

        if ref_kind is not None:
            width = 4 if fmt == "31c" else 2
            idx = self._read_uint(insns, pos + 2, width)
            if idx is not None:
                kwargs[f"{ref_kind}_idx"] = idx

        return Instruction(offset=pos, opcode=opcode, mnemonic=mnemonic, size=size, **kwargs)

    @staticmethod
    def _read_uint(data: bytes, pos: int, width: int) -> int | None:
        if pos + width > len(data):
            return None
        return int.from_bytes(data[pos:pos + width], "little")

    def decode(self, insns: bytes, insns_size: int) -> list[Instruction]:
        """Decode a full instruction stream.

        ``insns_size`` is the code-unit count from the DEX ``code_item``
        header; decoding stops at ``min(len(insns), insns_size * 2)`` bytes
        so a truncated/padded buffer can't run the decoder past the
        method's real body.
        """
        instructions: list[Instruction] = []
        limit = min(len(insns), insns_size * 2)
        pos = 0
        while pos < limit:
            insn = self.decode_one(insns, pos)
            instructions.append(insn)
            step = insn.size * 2
            if step <= 0:
                break
            pos += step
        return instructions


# ---------------------------------------------------------------------------
# Full 256-opcode Dalvik disassembler for DEX Inspector & disassembly preview
# ---------------------------------------------------------------------------

FULL_FORMAT_SIZES: dict[str, int] = {
    "10x": 1, "12x": 1, "11n": 1, "11x": 1, "10t": 1,
    "20t": 2, "22x": 2, "21t": 2, "21s": 2, "21h": 2,
    "21c": 2, "23x": 2, "22b": 2, "22t": 2, "22s": 2, "22c": 2,
    "30t": 3, "32x": 3, "31i": 3, "31t": 3, "31c": 3, "35c": 3, "3rc": 3,
    "45cc": 4, "4rcc": 4, "51l": 5,
}

# Complete Dalvik opcode specification: opcode -> (mnemonic, format, ref_kind)
FULL_OPCODE_TABLE: dict[int, tuple[str, str, str | None]] = {
    0x00: ("nop", "10x", None),
    0x01: ("move", "12x", None),
    0x02: ("move/from16", "22x", None),
    0x03: ("move/16", "32x", None),
    0x04: ("move-wide", "12x", None),
    0x05: ("move-wide/from16", "22x", None),
    0x06: ("move-wide/16", "32x", None),
    0x07: ("move-object", "12x", None),
    0x08: ("move-object/from16", "22x", None),
    0x09: ("move-object/16", "32x", None),
    0x0a: ("move-result", "11x", None),
    0x0b: ("move-result-wide", "11x", None),
    0x0c: ("move-result-object", "11x", None),
    0x0d: ("move-exception", "11x", None),
    0x0e: ("return-void", "10x", None),
    0x0f: ("return", "11x", None),
    0x10: ("return-wide", "11x", None),
    0x11: ("return-object", "11x", None),
    0x12: ("const/4", "11n", None),
    0x13: ("const/16", "21s", None),
    0x14: ("const", "31i", None),
    0x15: ("const/high16", "21h", None),
    0x16: ("const-wide/16", "21s", None),
    0x17: ("const-wide/32", "31i", None),
    0x18: ("const-wide", "51l", None),
    0x19: ("const-wide/high16", "21h", None),
    0x1a: ("const-string", "21c", _STRING),
    0x1b: ("const-string/jumbo", "31c", _STRING),
    0x1c: ("const-class", "21c", _TYPE),
    0x1d: ("monitor-enter", "11x", None),
    0x1e: ("monitor-exit", "11x", None),
    0x1f: ("check-cast", "21c", _TYPE),
    0x20: ("instance-of", "22c", _TYPE),
    0x21: ("array-length", "12x", None),
    0x22: ("new-instance", "21c", _TYPE),
    0x23: ("new-array", "22c", _TYPE),
    0x24: ("filled-new-array", "35c", _TYPE),
    0x25: ("filled-new-array/range", "3rc", _TYPE),
    0x26: ("fill-array-data", "31t", None),
    0x27: ("throw", "11x", None),
    0x28: ("goto", "10t", None),
    0x29: ("goto/16", "20t", None),
    0x2a: ("goto/32", "30t", None),
    0x2b: ("packed-switch", "31t", None),
    0x2c: ("sparse-switch", "31t", None),
    0x2d: ("cmpl-float", "23x", None),
    0x2e: ("cmpg-float", "23x", None),
    0x2f: ("cmpl-double", "23x", None),
    0x30: ("cmpg-double", "23x", None),
    0x31: ("cmp-long", "23x", None),
    0x32: ("if-eq", "22t", None),
    0x33: ("if-ne", "22t", None),
    0x34: ("if-lt", "22t", None),
    0x35: ("if-ge", "22t", None),
    0x36: ("if-gt", "22t", None),
    0x37: ("if-le", "22t", None),
    0x38: ("if-eqz", "21t", None),
    0x39: ("if-nez", "21t", None),
    0x3a: ("if-ltz", "21t", None),
    0x3b: ("if-gez", "21t", None),
    0x3c: ("if-gtz", "21t", None),
    0x3d: ("if-lez", "21t", None),
    0x44: ("aget", "23x", None),
    0x45: ("aget-wide", "23x", None),
    0x46: ("aget-object", "23x", None),
    0x47: ("aget-boolean", "23x", None),
    0x48: ("aget-byte", "23x", None),
    0x49: ("aget-char", "23x", None),
    0x4a: ("aget-short", "23x", None),
    0x4b: ("aput", "23x", None),
    0x4c: ("aput-wide", "23x", None),
    0x4d: ("aput-object", "23x", None),
    0x4e: ("aput-boolean", "23x", None),
    0x4f: ("aput-byte", "23x", None),
    0x50: ("aput-char", "23x", None),
    0x51: ("aput-short", "23x", None),
    0x52: ("iget", "22c", _FIELD),
    0x53: ("iget-wide", "22c", _FIELD),
    0x54: ("iget-object", "22c", _FIELD),
    0x55: ("iget-boolean", "22c", _FIELD),
    0x56: ("iget-byte", "22c", _FIELD),
    0x57: ("iget-char", "22c", _FIELD),
    0x58: ("iget-short", "22c", _FIELD),
    0x59: ("iput", "22c", _FIELD),
    0x5a: ("iput-wide", "22c", _FIELD),
    0x5b: ("iput-object", "22c", _FIELD),
    0x5c: ("iput-boolean", "22c", _FIELD),
    0x5d: ("iput-byte", "22c", _FIELD),
    0x5e: ("iput-char", "22c", _FIELD),
    0x5f: ("iput-short", "22c", _FIELD),
    0x60: ("sget", "21c", _FIELD),
    0x61: ("sget-wide", "21c", _FIELD),
    0x62: ("sget-object", "21c", _FIELD),
    0x63: ("sget-boolean", "21c", _FIELD),
    0x64: ("sget-byte", "21c", _FIELD),
    0x65: ("sget-char", "21c", _FIELD),
    0x66: ("sget-short", "21c", _FIELD),
    0x67: ("sput", "21c", _FIELD),
    0x68: ("sput-wide", "21c", _FIELD),
    0x69: ("sput-object", "21c", _FIELD),
    0x6a: ("sput-boolean", "21c", _FIELD),
    0x6b: ("sput-byte", "21c", _FIELD),
    0x6c: ("sput-char", "21c", _FIELD),
    0x6d: ("sput-short", "21c", _FIELD),
    0x6e: ("invoke-virtual", "35c", _METHOD),
    0x6f: ("invoke-super", "35c", _METHOD),
    0x70: ("invoke-direct", "35c", _METHOD),
    0x71: ("invoke-static", "35c", _METHOD),
    0x72: ("invoke-interface", "35c", _METHOD),
    0x74: ("invoke-virtual/range", "3rc", _METHOD),
    0x75: ("invoke-super/range", "3rc", _METHOD),
    0x76: ("invoke-direct/range", "3rc", _METHOD),
    0x77: ("invoke-static/range", "3rc", _METHOD),
    0x78: ("invoke-interface/range", "3rc", _METHOD),
    0x7b: ("neg-int", "12x", None),
    0x7c: ("not-int", "12x", None),
    0x7d: ("neg-long", "12x", None),
    0x7e: ("not-long", "12x", None),
    0x7f: ("neg-float", "12x", None),
    0x80: ("neg-double", "12x", None),
    0x81: ("int-to-long", "12x", None),
    0x82: ("int-to-float", "12x", None),
    0x83: ("int-to-double", "12x", None),
    0x84: ("long-to-int", "12x", None),
    0x85: ("long-to-float", "12x", None),
    0x86: ("long-to-double", "12x", None),
    0x87: ("float-to-int", "12x", None),
    0x88: ("float-to-long", "12x", None),
    0x89: ("float-to-double", "12x", None),
    0x8a: ("double-to-int", "12x", None),
    0x8b: ("double-to-long", "12x", None),
    0x8c: ("double-to-float", "12x", None),
    0x8d: ("int-to-byte", "12x", None),
    0x8e: ("int-to-char", "12x", None),
    0x8f: ("int-to-short", "12x", None),
    0x90: ("add-int", "23x", None),
    0x91: ("sub-int", "23x", None),
    0x92: ("mul-int", "23x", None),
    0x93: ("div-int", "23x", None),
    0x94: ("rem-int", "23x", None),
    0x95: ("and-int", "23x", None),
    0x96: ("or-int", "23x", None),
    0x97: ("xor-int", "23x", None),
    0x98: ("shl-int", "23x", None),
    0x99: ("shr-int", "23x", None),
    0x9a: ("ushr-int", "23x", None),
    0x9b: ("add-long", "23x", None),
    0x9c: ("sub-long", "23x", None),
    0x9d: ("mul-long", "23x", None),
    0x9e: ("div-long", "23x", None),
    0x9f: ("rem-long", "23x", None),
    0xa0: ("and-long", "23x", None),
    0xa1: ("or-long", "23x", None),
    0xa2: ("xor-long", "23x", None),
    0xa3: ("shl-long", "23x", None),
    0xa4: ("shr-long", "23x", None),
    0xa5: ("ushr-long", "23x", None),
    0xa6: ("add-float", "23x", None),
    0xa7: ("sub-float", "23x", None),
    0xa8: ("mul-float", "23x", None),
    0xa9: ("div-float", "23x", None),
    0xaa: ("rem-float", "23x", None),
    0xab: ("add-double", "23x", None),
    0xac: ("sub-double", "23x", None),
    0xad: ("mul-double", "23x", None),
    0xae: ("div-double", "23x", None),
    0xaf: ("rem-double", "23x", None),
    0xb0: ("add-int/2addr", "12x", None),
    0xb1: ("sub-int/2addr", "12x", None),
    0xb2: ("mul-int/2addr", "12x", None),
    0xb3: ("div-int/2addr", "12x", None),
    0xb4: ("rem-int/2addr", "12x", None),
    0xb5: ("and-int/2addr", "12x", None),
    0xb6: ("or-int/2addr", "12x", None),
    0xb7: ("xor-int/2addr", "12x", None),
    0xb8: ("shl-int/2addr", "12x", None),
    0xb9: ("shr-int/2addr", "12x", None),
    0xba: ("ushr-int/2addr", "12x", None),
    0xbb: ("add-long/2addr", "12x", None),
    0xbc: ("sub-long/2addr", "12x", None),
    0xbd: ("mul-long/2addr", "12x", None),
    0xbe: ("div-long/2addr", "12x", None),
    0xbf: ("rem-long/2addr", "12x", None),
    0xc0: ("and-long/2addr", "12x", None),
    0xc1: ("or-long/2addr", "12x", None),
    0xc2: ("xor-long/2addr", "12x", None),
    0xc3: ("shl-long/2addr", "12x", None),
    0xc4: ("shr-long/2addr", "12x", None),
    0xc5: ("ushr-long/2addr", "12x", None),
    0xc6: ("add-float/2addr", "12x", None),
    0xc7: ("sub-float/2addr", "12x", None),
    0xc8: ("mul-float/2addr", "12x", None),
    0xc9: ("div-float/2addr", "12x", None),
    0xca: ("rem-float/2addr", "12x", None),
    0xcb: ("add-double/2addr", "12x", None),
    0xcc: ("sub-double/2addr", "12x", None),
    0xcd: ("mul-double/2addr", "12x", None),
    0xce: ("div-double/2addr", "12x", None),
    0xcf: ("rem-double/2addr", "12x", None),
    0xd0: ("add-int/lit16", "22s", None),
    0xd1: ("rsub-int", "22s", None),
    0xd2: ("mul-int/lit16", "22s", None),
    0xd3: ("div-int/lit16", "22s", None),
    0xd4: ("rem-int/lit16", "22s", None),
    0xd5: ("and-int/lit16", "22s", None),
    0xd6: ("or-int/lit16", "22s", None),
    0xd7: ("xor-int/lit16", "22s", None),
    0xd8: ("add-int/lit8", "22b", None),
    0xd9: ("rsub-int/lit8", "22b", None),
    0xda: ("mul-int/lit8", "22b", None),
    0xdb: ("div-int/lit8", "22b", None),
    0xdc: ("rem-int/lit8", "22b", None),
    0xdd: ("and-int/lit8", "22b", None),
    0xde: ("or-int/lit8", "22b", None),
    0xdf: ("xor-int/lit8", "22b", None),
    0xe0: ("shl-int/lit8", "22b", None),
    0xe1: ("shr-int/lit8", "22b", None),
    0xe2: ("ushr-int/lit8", "22b", None),
    0xfa: ("invoke-polymorphic", "45cc", _METHOD),
    0xfb: ("invoke-polymorphic/range", "4rcc", _METHOD),
    0xfc: ("invoke-custom", "35c", None),
    0xfd: ("invoke-custom/range", "3rc", None),
}


@dataclass
class DecodedInstruction:
    """Rich decoded Dalvik instruction for UI/CLI disassembly preview."""

    offset: int
    opcode: int
    mnemonic: str
    size: int
    raw_hex: str
    operands: str = ""
    resolved_ref: str = ""
    ref_kind: str | None = None
    ref_idx: int | None = None

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "offset_hex": f"{self.offset:04x}",
            "opcode": self.opcode,
            "mnemonic": self.mnemonic,
            "size": self.size,
            "raw_hex": self.raw_hex,
            "operands": self.operands,
            "resolved_ref": self.resolved_ref,
            "ref_kind": self.ref_kind,
            "ref_idx": self.ref_idx,
        }


def _signed(val: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (val & (sign_bit - 1)) - (val & sign_bit)


class FullDalvikDisassembler:
    """Complete 256-opcode Dalvik disassembler with smali-style formatting."""

    def disassemble(
        self,
        insns: bytes,
        insns_size: int,
        dex=None,
        max_insns: int = 500,
    ) -> list[DecodedInstruction]:
        results: list[DecodedInstruction] = []
        limit = min(len(insns), insns_size * 2)
        pos = 0
        while pos < limit and len(results) < max_insns:
            unit0 = int.from_bytes(insns[pos : pos + 2], "little") if pos + 2 <= limit else insns[pos]
            # Handle Dalvik pseudo-instruction data payloads
            if unit0 in (0x0100, 0x0200, 0x0300) and pos + 4 <= limit:
                payload_insn = self._decode_payload(insns, pos, limit, unit0)
                if payload_insn is not None:
                    results.append(payload_insn)
                    pos += payload_insn.size * 2
                    continue

            opcode = insns[pos]
            entry = FULL_OPCODE_TABLE.get(opcode)
            if entry is None:
                raw = insns[pos : min(pos + 2, limit)].hex()
                results.append(
                    DecodedInstruction(
                        offset=pos,
                        opcode=opcode,
                        mnemonic=f"op_{opcode:02X}",
                        size=1,
                        raw_hex=raw,
                    )
                )
                pos += 2
                continue

            mnemonic, fmt, ref_kind = entry
            size = FULL_FORMAT_SIZES[fmt]
            byte_len = min(size * 2, limit - pos)
            chunk = insns[pos : pos + byte_len]
            operands, ref_idx = self._format_operands(fmt, chunk, pos, ref_kind)
            resolved = self._resolve_ref(dex, ref_kind, ref_idx) if (dex and ref_kind and ref_idx is not None) else ""
            if resolved:
                operands = f"{operands}, {resolved}" if operands else resolved
            results.append(
                DecodedInstruction(
                    offset=pos,
                    opcode=opcode,
                    mnemonic=mnemonic,
                    size=size,
                    raw_hex=chunk.hex(),
                    operands=operands,
                    resolved_ref=resolved,
                    ref_kind=ref_kind,
                    ref_idx=ref_idx,
                )
            )
            pos += size * 2
        return results

    @staticmethod
    def _decode_payload(insns: bytes, pos: int, limit: int, ident: int) -> DecodedInstruction | None:
        if ident == 0x0100 and pos + 8 <= limit:
            count = int.from_bytes(insns[pos + 2 : pos + 4], "little")
            units = min((limit - pos) // 2, count * 2 + 4)
            return DecodedInstruction(
                offset=pos,
                opcode=0x00,
                mnemonic=".packed-switch-data",
                size=max(1, units),
                raw_hex=insns[pos : pos + 8].hex(),
                operands=f"({count} targets)",
            )
        if ident == 0x0200 and pos + 4 <= limit:
            count = int.from_bytes(insns[pos + 2 : pos + 4], "little")
            units = min((limit - pos) // 2, count * 4 + 2)
            return DecodedInstruction(
                offset=pos,
                opcode=0x00,
                mnemonic=".sparse-switch-data",
                size=max(1, units),
                raw_hex=insns[pos : pos + 4].hex(),
                operands=f"({count} cases)",
            )
        if ident == 0x0300 and pos + 8 <= limit:
            elem_width = int.from_bytes(insns[pos + 2 : pos + 4], "little")
            elem_count = int.from_bytes(insns[pos + 4 : pos + 8], "little")
            data_units = (elem_count * elem_width + 1) // 2
            units = min((limit - pos) // 2, data_units + 4)
            return DecodedInstruction(
                offset=pos,
                opcode=0x00,
                mnemonic=".array-data",
                size=max(1, units),
                raw_hex=insns[pos : pos + 8].hex(),
                operands=f"({elem_count} x {elem_width}B)",
            )
        return None

    @staticmethod
    def _format_operands(
        fmt: str, chunk: bytes, pos: int, ref_kind: str | None
    ) -> tuple[str, int | None]:
        n = len(chunk)
        b1 = chunk[1] if n > 1 else 0
        u16 = lambda o: int.from_bytes(chunk[o : o + 2], "little") if o + 2 <= n else 0
        u32 = lambda o: int.from_bytes(chunk[o : o + 4], "little") if o + 4 <= n else 0

        if fmt == "10x":
            return "", None
        if fmt == "11x":
            return f"v{b1}", None
        if fmt == "12x":
            return f"v{b1 & 0xF}, v{b1 >> 4}", None
        if fmt == "11n":
            lit = _signed(b1 >> 4, 4)
            return f"v{b1 & 0xF}, #{lit}", None
        if fmt == "10t":
            target = pos + _signed(b1, 8) * 2
            return f":{target:04x}", None
        if fmt == "20t":
            target = pos + _signed(u16(2), 16) * 2
            return f":{target:04x}", None
        if fmt == "30t":
            target = pos + _signed(u32(2), 32) * 2
            return f":{target:04x}", None
        if fmt == "22x":
            return f"v{b1}, v{u16(2)}", None
        if fmt == "32x":
            return f"v{u16(2)}, v{u16(4)}", None
        if fmt == "21s":
            return f"v{b1}, #{_signed(u16(2), 16)}", None
        if fmt == "21h":
            return f"v{b1}, #{u16(2):#x}0000", None
        if fmt == "21t":
            target = pos + _signed(u16(2), 16) * 2
            return f"v{b1}, :{target:04x}", None
        if fmt == "22t":
            target = pos + _signed(u16(2), 16) * 2
            return f"v{b1 & 0xF}, v{b1 >> 4}, :{target:04x}", None
        if fmt == "22s":
            return f"v{b1 & 0xF}, v{b1 >> 4}, #{_signed(u16(2), 16)}", None
        if fmt == "22b":
            cc = chunk[2] if n > 2 else 0
            lit = _signed(chunk[3], 8) if n > 3 else 0
            return f"v{b1}, v{cc}, #{lit}", None
        if fmt == "23x":
            bb = chunk[2] if n > 2 else 0
            cc = chunk[3] if n > 3 else 0
            return f"v{b1}, v{bb}, v{cc}", None
        if fmt == "31i":
            return f"v{b1}, #{_signed(u32(2), 32)}", None
        if fmt == "31t":
            target = pos + _signed(u32(2), 32) * 2
            return f"v{b1}, :{target:04x}", None
        if fmt == "51l" and n >= 10:
            val = int.from_bytes(chunk[2:10], "little", signed=True)
            return f"v{b1}, #{val:#x}", None
        if fmt == "21c":
            idx = u16(2) if n >= 4 else None
            return f"v{b1}", idx
        if fmt == "31c":
            idx = u32(2) if n >= 6 else None
            return f"v{b1}", idx
        if fmt == "22c":
            idx = u16(2) if n >= 4 else None
            return f"v{b1 & 0xF}, v{b1 >> 4}", idx
        if fmt in ("35c", "45cc"):
            count = b1 >> 4
            g_reg = b1 & 0xF
            idx = u16(2) if n >= 4 else None
            regs_word = u16(4) if n >= 6 else 0
            all_regs = [
                regs_word & 0xF,
                (regs_word >> 4) & 0xF,
                (regs_word >> 8) & 0xF,
                (regs_word >> 12) & 0xF,
                g_reg,
            ]
            reg_list = ", ".join(f"v{r}" for r in all_regs[: min(count, 5)])
            return f"{{{reg_list}}}", idx
        if fmt in ("3rc", "4rcc"):
            count = b1
            idx = u16(2) if n >= 4 else None
            start = u16(4) if n >= 6 else 0
            end = start + max(0, count - 1)
            reg_str = f"{{v{start} .. v{end}}}" if count > 0 else "{}"
            return reg_str, idx
        return "", None

    @staticmethod
    def _resolve_ref(dex, ref_kind: str | None, ref_idx: int | None) -> str:
        if dex is None or ref_kind is None or ref_idx is None:
            return ""
        if ref_kind == _STRING:
            val = dex.get_string(ref_idx)
            if val is None:
                return f"string@{ref_idx}"
            escaped = val.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
            if len(escaped) > 96:
                escaped = escaped[:93] + "..."
            return f'"{escaped}"'
        if ref_kind == _TYPE:
            return dex.get_type_name(ref_idx) or f"type@{ref_idx}"
        if ref_kind == _METHOD:
            if hasattr(dex, "get_method_signature"):
                cls, name, proto = dex.get_method_signature(ref_idx)
                if cls or name:
                    return f"{cls or ''}->{name or ''}{proto}"
            cls, name = dex.get_method_full(ref_idx)
            if cls or name:
                return f"{cls or ''}->{name or ''}"
            return f"method@{ref_idx}"
        if ref_kind == _FIELD:
            if hasattr(dex, "get_field_detail"):
                cls, name, ftype = dex.get_field_detail(ref_idx)
                if cls or name:
                    return f"{cls or ''}->{name or ''}:{ftype or ''}"
            cls, name = dex.get_field_full(ref_idx)
            if cls or name:
                return f"{cls or ''}->{name or ''}"
            return f"field@{ref_idx}"
        return ""
