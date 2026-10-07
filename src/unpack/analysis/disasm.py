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
