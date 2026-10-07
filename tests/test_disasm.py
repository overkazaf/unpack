from __future__ import annotations

from unpack.analysis.disasm import DalvikDecoder, FORMAT_SIZES, Instruction, OPCODE_TABLE


class TestFormatSizes:
    def test_known_format_sizes(self):
        assert FORMAT_SIZES["10x"] == 1
        assert FORMAT_SIZES["11x"] == 1
        assert FORMAT_SIZES["21c"] == 2
        assert FORMAT_SIZES["22c"] == 2
        assert FORMAT_SIZES["31c"] == 3
        assert FORMAT_SIZES["35c"] == 3
        assert FORMAT_SIZES["3rc"] == 3


class TestDalvikDecoderSingleOpcodes:
    def setup_method(self):
        self.decoder = DalvikDecoder()

    def test_nop(self):
        insn = self.decoder.decode_one(b"\x00\x00", 0)
        assert insn.opcode == 0x00
        assert insn.mnemonic == "nop"
        assert insn.size == 1
        assert insn.string_idx is None

    def test_return_void(self):
        insn = self.decoder.decode_one(b"\x0e\x00", 0)
        assert insn.mnemonic == "return-void"
        assert insn.size == 1

    def test_return(self):
        insn = self.decoder.decode_one(b"\x0f\x00", 0)
        assert insn.mnemonic == "return"
        assert insn.size == 1

    def test_return_wide(self):
        insn = self.decoder.decode_one(b"\x10\x00", 0)
        assert insn.mnemonic == "return-wide"
        assert insn.size == 1

    def test_return_object(self):
        insn = self.decoder.decode_one(b"\x11\x00", 0)
        assert insn.mnemonic == "return-object"
        assert insn.size == 1

    def test_const_string(self):
        # const-string v0, string@0x1234
        insn = self.decoder.decode_one(b"\x1a\x00\x34\x12", 0)
        assert insn.mnemonic == "const-string"
        assert insn.size == 2
        assert insn.string_idx == 0x1234
        assert insn.type_idx is None
        assert insn.method_idx is None
        assert insn.field_idx is None

    def test_const_string_jumbo(self):
        # const-string/jumbo v0, string@0x12345678
        insn = self.decoder.decode_one(b"\x1b\x00\x78\x56\x34\x12", 0)
        assert insn.mnemonic == "const-string/jumbo"
        assert insn.size == 3
        assert insn.string_idx == 0x12345678

    def test_const_class(self):
        insn = self.decoder.decode_one(b"\x1c\x00\x05\x00", 0)
        assert insn.mnemonic == "const-class"
        assert insn.size == 2
        assert insn.type_idx == 5
        assert insn.string_idx is None

    def test_check_cast(self):
        insn = self.decoder.decode_one(b"\x1f\x00\x07\x00", 0)
        assert insn.mnemonic == "check-cast"
        assert insn.size == 2
        assert insn.type_idx == 7

    def test_new_instance(self):
        insn = self.decoder.decode_one(b"\x22\x00\x09\x00", 0)
        assert insn.mnemonic == "new-instance"
        assert insn.size == 2
        assert insn.type_idx == 9

    def test_iget(self):
        insn = self.decoder.decode_one(b"\x52\x10\x03\x00", 0)
        assert insn.mnemonic == "iget"
        assert insn.size == 2
        assert insn.field_idx == 3

    def test_iget_wide(self):
        insn = self.decoder.decode_one(b"\x53\x10\x00\x00", 0)
        assert insn.mnemonic == "iget-wide"
        assert insn.field_idx == 0

    def test_iput(self):
        insn = self.decoder.decode_one(b"\x59\x10\x02\x00", 0)
        assert insn.mnemonic == "iput"
        assert insn.size == 2
        assert insn.field_idx == 2

    def test_iput_boolean(self):
        insn = self.decoder.decode_one(b"\x5c\x10\x01\x00", 0)
        assert insn.mnemonic == "iput-boolean"
        assert insn.field_idx == 1

    def test_sget(self):
        insn = self.decoder.decode_one(b"\x60\x00\x0a\x00", 0)
        assert insn.mnemonic == "sget"
        assert insn.size == 2
        assert insn.field_idx == 0x0a

    def test_sput_boolean(self):
        insn = self.decoder.decode_one(b"\x6a\x00\x0b\x00", 0)
        assert insn.mnemonic == "sput-boolean"
        assert insn.field_idx == 0x0b

    def test_invoke_virtual(self):
        # invoke-virtual {v0}, method@0x0010
        insn = self.decoder.decode_one(b"\x6e\x10\x10\x00\x00\x00", 0)
        assert insn.mnemonic == "invoke-virtual"
        assert insn.size == 3
        assert insn.method_idx == 0x10
        assert insn.string_idx is None
        assert insn.field_idx is None

    def test_invoke_super(self):
        insn = self.decoder.decode_one(b"\x6f\x10\x01\x00\x00\x00", 0)
        assert insn.mnemonic == "invoke-super"
        assert insn.method_idx == 1

    def test_invoke_direct(self):
        insn = self.decoder.decode_one(b"\x70\x10\x02\x00\x00\x00", 0)
        assert insn.mnemonic == "invoke-direct"
        assert insn.method_idx == 2

    def test_invoke_static(self):
        insn = self.decoder.decode_one(b"\x71\x00\x05\x00\x00\x00", 0)
        assert insn.mnemonic == "invoke-static"
        assert insn.size == 3
        assert insn.method_idx == 5

    def test_invoke_interface(self):
        insn = self.decoder.decode_one(b"\x72\x10\x03\x00\x00\x00", 0)
        assert insn.mnemonic == "invoke-interface"
        assert insn.method_idx == 3

    def test_invoke_virtual_range(self):
        insn = self.decoder.decode_one(b"\x74\x01\x20\x00\x00\x00", 0)
        assert insn.mnemonic == "invoke-virtual/range"
        assert insn.size == 3
        assert insn.method_idx == 0x20

    def test_invoke_static_range(self):
        insn = self.decoder.decode_one(b"\x77\x01\x21\x00\x00\x00", 0)
        assert insn.mnemonic == "invoke-static/range"
        assert insn.method_idx == 0x21

    def test_invoke_interface_range(self):
        insn = self.decoder.decode_one(b"\x78\x01\x22\x00\x00\x00", 0)
        assert insn.mnemonic == "invoke-interface/range"
        assert insn.method_idx == 0x22

    def test_unknown_opcode(self):
        insn = self.decoder.decode_one(b"\x05\x00", 0)
        assert insn.mnemonic == "op_05"
        assert insn.size == 1
        assert insn.opcode == 0x05

    def test_unknown_opcode_high_byte(self):
        insn = self.decoder.decode_one(b"\xff\x00", 0)
        assert insn.mnemonic == "op_FF"
        assert insn.size == 1


class TestDalvikDecoderSequences:
    def setup_method(self):
        self.decoder = DalvikDecoder()

    def test_decode_sequence_const_string_then_invoke_then_return(self):
        insns = (
            b"\x1a\x00\x02\x00"       # const-string v0, string@2
            b"\x71\x00\x01\x00\x00\x00"  # invoke-static method@1
            b"\x0e\x00"                 # return-void
        )
        insns_size = len(insns) // 2
        instructions = self.decoder.decode(insns, insns_size)
        assert [i.mnemonic for i in instructions] == [
            "const-string", "invoke-static", "return-void",
        ]
        assert [i.offset for i in instructions] == [0, 4, 10]
        assert instructions[0].string_idx == 2
        assert instructions[1].method_idx == 1
        assert instructions[2].string_idx is None

    def test_decode_sequence_field_and_nop(self):
        insns = (
            b"\x00\x00"               # nop
            b"\x60\x00\x03\x00"       # sget v0, field@3
            b"\x0e\x00"               # return-void
        )
        instructions = self.decoder.decode(insns, len(insns) // 2)
        assert [i.mnemonic for i in instructions] == ["nop", "sget", "return-void"]
        assert instructions[1].field_idx == 3

    def test_decode_sequence_with_unknown_opcode_in_middle(self):
        insns = (
            b"\x0e\x00"       # return-void
            b"\x05\x00"       # unknown opcode
            b"\x0e\x00"       # return-void
        )
        instructions = self.decoder.decode(insns, len(insns) // 2)
        assert [i.mnemonic for i in instructions] == ["return-void", "op_05", "return-void"]
        assert [i.offset for i in instructions] == [0, 2, 4]

    def test_decode_respects_insns_size_truncation(self):
        # Buffer has more bytes than insns_size claims; decode must stop
        # at the code-unit boundary, not run past it.
        insns = b"\x0e\x00" + b"\x71\x00\x01\x00\x00\x00"
        instructions = self.decoder.decode(insns, insns_size=1)
        assert len(instructions) == 1
        assert instructions[0].mnemonic == "return-void"

    def test_decode_empty_insns(self):
        assert self.decoder.decode(b"", insns_size=0) == []

    def test_decode_all_nop(self):
        insns = b"\x00\x00" * 4
        instructions = self.decoder.decode(insns, insns_size=4)
        assert len(instructions) == 4
        assert all(i.mnemonic == "nop" for i in instructions)

    def test_const_string_jumbo_truncated_ref_returns_none_idx(self):
        # Buffer too short to hold the 4-byte string index.
        decoder = DalvikDecoder()
        insn = decoder.decode_one(b"\x1b\x00\x78\x56", 0)
        assert insn.mnemonic == "const-string/jumbo"
        assert insn.string_idx is None


class TestInstructionDataclass:
    def test_defaults(self):
        insn = Instruction(offset=0, opcode=0x00, mnemonic="nop", size=1)
        assert insn.string_idx is None
        assert insn.type_idx is None
        assert insn.method_idx is None
        assert insn.field_idx is None

    def test_opcode_table_covers_expected_count(self):
        # Sanity check that the opcode table is in the right ballpark
        # (the spec calls for ~40 opcodes).
        assert len(OPCODE_TABLE) >= 35
