from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import ClassVar

DEX_MAGIC_035 = b"dex\n035\x00"
DEX_MAGIC_037 = b"dex\n037\x00"
DEX_MAGIC_038 = b"dex\n038\x00"
DEX_MAGIC_039 = b"dex\n039\x00"
DEX_MAGIC_041 = b"dex\n041\x00"
VALID_MAGICS = {DEX_MAGIC_035, DEX_MAGIC_037, DEX_MAGIC_038, DEX_MAGIC_039, DEX_MAGIC_041}

CDEX_MAGIC = b"cdex001\x00"
CDEX_MAGICS = {CDEX_MAGIC}

ENDIAN_CONSTANT = 0x12345678
REVERSE_ENDIAN_CONSTANT = 0x78563412

HEADER_SIZE = 0x70


def is_cdex(data: bytes) -> bool:
    """Return True if data starts with the CompactDex (CDEX) magic."""
    if len(data) < 8:
        return False
    return data[:4] == b"cdex"


def _uleb128(data: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    n = len(data)
    for _ in range(5):
        if off >= n:
            raise IndexError("truncated uleb128")
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, off


def _sleb128(data: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    n = len(data)
    for _ in range(5):
        if off >= n:
            raise IndexError("truncated sleb128")
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            if shift < 32 and (b & 0x40):
                result |= -(1 << shift)
            break
    return result, off


_ACCESS_FLAGS_COMMON: tuple[tuple[int, str], ...] = (
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0020, "synchronized"),
    (0x0100, "native"),
    (0x0200, "interface"),
    (0x0400, "abstract"),
    (0x1000, "synthetic"),
    (0x2000, "annotation"),
    (0x4000, "enum"),
    (0x10000, "constructor"),
)


def decode_access_flags(flags: int, is_field: bool = False) -> list[str]:
    """Decode DEX access_flags bitmask into human-readable modifier names."""
    names: list[str] = []
    for bit, label in _ACCESS_FLAGS_COMMON:
        if bit == 0x0020 and is_field:
            continue
        if flags & bit:
            names.append(label)
    if is_field:
        if flags & 0x0040:
            names.append("volatile")
        if flags & 0x0080:
            names.append("transient")
    return names


@dataclass
class DexHeader:
    magic: bytes
    checksum: int
    signature: bytes
    file_size: int
    header_size: int
    endian_tag: int
    link_size: int
    link_off: int
    map_off: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int

    @staticmethod
    def parse(data: bytes, fmt: str) -> DexHeader:
        magic = data[:8]
        checksum = struct.unpack_from(f"{fmt}I", data, 8)[0]
        signature = data[12:32]
        fields = struct.unpack_from(f"{fmt}20I", data, 32)
        return DexHeader(
            magic=magic,
            checksum=checksum,
            signature=signature,
            file_size=fields[0],
            header_size=fields[1],
            endian_tag=fields[2],
            link_size=fields[3],
            link_off=fields[4],
            map_off=fields[5],
            string_ids_size=fields[6],
            string_ids_off=fields[7],
            type_ids_size=fields[8],
            type_ids_off=fields[9],
            proto_ids_size=fields[10],
            proto_ids_off=fields[11],
            field_ids_size=fields[12],
            field_ids_off=fields[13],
            method_ids_size=fields[14],
            method_ids_off=fields[15],
            class_defs_size=fields[16],
            class_defs_off=fields[17],
            data_size=fields[18],
            data_off=fields[19],
        )


@dataclass
class CodeItem:
    registers_size: int
    ins_size: int
    outs_size: int
    tries_size: int
    debug_info_off: int
    insns_size: int
    insns: bytes
    offset: int  # absolute offset in dex data

    @property
    def is_nop_only(self) -> bool:
        if self.insns_size == 0:
            return False
        return all(b == 0 for b in self.insns)


@dataclass
class EncodedMethod:
    method_idx: int  # absolute, not diff
    access_flags: int
    code_off: int
    code_item: CodeItem | None = None


@dataclass
class EncodedField:
    field_idx: int
    access_flags: int


@dataclass
class ClassData:
    static_fields: list[EncodedField]
    instance_fields: list[EncodedField]
    direct_methods: list[EncodedMethod]
    virtual_methods: list[EncodedMethod]


@dataclass
class ClassDef:
    class_idx: int
    access_flags: int
    superclass_idx: int
    interfaces_off: int
    source_file_idx: int
    annotations_off: int
    class_data_off: int
    static_values_off: int
    class_data: ClassData | None = None


@dataclass
class DexFile:
    data: bytes
    fmt: str  # '<' or '>'
    header: DexHeader
    class_defs: list[ClassDef] = field(default_factory=list)
    _code_items: list[CodeItem] = field(default_factory=list)

    CLASSDEF_STRUCT_SIZE: ClassVar[int] = 32

    @staticmethod
    def parse(data: bytes) -> DexFile:
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Data too small for DEX header: {len(data)} < {HEADER_SIZE}")

        endian_tag = struct.unpack_from("<I", data, 40)[0]
        if endian_tag == ENDIAN_CONSTANT:
            fmt = "<"
        elif endian_tag == REVERSE_ENDIAN_CONSTANT:
            fmt = ">"
        else:
            fmt = "<"

        header = DexHeader.parse(data, fmt)
        dex = DexFile(data=data, fmt=fmt, header=header)
        dex._parse_class_defs()
        return dex

    def _parse_class_defs(self):
        h = self.header
        if h.class_defs_size == 0 or h.class_defs_off == 0:
            return

        for i in range(h.class_defs_size):
            off = h.class_defs_off + i * self.CLASSDEF_STRUCT_SIZE
            if off + self.CLASSDEF_STRUCT_SIZE > len(self.data):
                break
            vals = struct.unpack_from(f"{self.fmt}8I", self.data, off)
            cdef = ClassDef(
                class_idx=vals[0],
                access_flags=vals[1],
                superclass_idx=vals[2],
                interfaces_off=vals[3],
                source_file_idx=vals[4],
                annotations_off=vals[5],
                class_data_off=vals[6],
                static_values_off=vals[7],
            )
            if cdef.class_data_off != 0 and cdef.class_data_off < len(self.data):
                try:
                    cdef.class_data = self._parse_class_data(cdef.class_data_off)
                except (IndexError, struct.error):
                    pass
            self.class_defs.append(cdef)

    def _parse_class_data(self, off: int) -> ClassData:
        static_fields_size, off = _uleb128(self.data, off)
        instance_fields_size, off = _uleb128(self.data, off)
        direct_methods_size, off = _uleb128(self.data, off)
        virtual_methods_size, off = _uleb128(self.data, off)

        static_fields, off = self._parse_encoded_fields(off, static_fields_size)
        instance_fields, off = self._parse_encoded_fields(off, instance_fields_size)
        direct_methods, off = self._parse_encoded_methods(off, direct_methods_size)
        virtual_methods, off = self._parse_encoded_methods(off, virtual_methods_size)

        return ClassData(
            static_fields=static_fields,
            instance_fields=instance_fields,
            direct_methods=direct_methods,
            virtual_methods=virtual_methods,
        )

    def _parse_encoded_fields(self, off: int, count: int) -> tuple[list[EncodedField], int]:
        fields = []
        idx = 0
        for _ in range(count):
            idx_diff, off = _uleb128(self.data, off)
            access_flags, off = _uleb128(self.data, off)
            idx += idx_diff
            fields.append(EncodedField(field_idx=idx, access_flags=access_flags))
        return fields, off

    def _parse_encoded_methods(self, off: int, count: int) -> tuple[list[EncodedMethod], int]:
        methods = []
        idx = 0
        for _ in range(count):
            idx_diff, off = _uleb128(self.data, off)
            access_flags, off = _uleb128(self.data, off)
            code_off, off = _uleb128(self.data, off)
            idx += idx_diff
            code_item = None
            if code_off != 0 and code_off < len(self.data):
                try:
                    code_item = self._parse_code_item(code_off)
                except (IndexError, struct.error):
                    pass
            methods.append(EncodedMethod(
                method_idx=idx,
                access_flags=access_flags,
                code_off=code_off,
                code_item=code_item,
            ))
        return methods, off

    def _parse_code_item(self, off: int) -> CodeItem:
        vals = struct.unpack_from(f"{self.fmt}4H2I", self.data, off)
        registers_size = vals[0]
        ins_size = vals[1]
        outs_size = vals[2]
        tries_size = vals[3]
        debug_info_off = vals[4]
        insns_size = vals[5]

        insns_off = off + 16
        insns_byte_count = insns_size * 2
        insns = self.data[insns_off:insns_off + insns_byte_count]

        item = CodeItem(
            registers_size=registers_size,
            ins_size=ins_size,
            outs_size=outs_size,
            tries_size=tries_size,
            debug_info_off=debug_info_off,
            insns_size=insns_size,
            insns=insns,
            offset=off,
        )
        self._code_items.append(item)
        return item

    @property
    def code_items(self) -> list[CodeItem]:
        return list(self._code_items)

    def get_string(self, idx: int) -> str | None:
        h = self.header
        if idx < 0 or idx >= h.string_ids_size:
            return None
        str_id_off = h.string_ids_off + idx * 4
        if str_id_off + 4 > len(self.data):
            return None
        data_off = struct.unpack_from(f"{self.fmt}I", self.data, str_id_off)[0]
        if data_off >= len(self.data):
            return None
        # skip MUTF-8 size (uleb128)
        try:
            _, pos = _uleb128(self.data, data_off)
            end = self.data.index(0, pos)
            return self.data[pos:end].decode("utf-8", errors="replace")
        except (IndexError, ValueError, UnicodeDecodeError):
            return None

    def get_type_name(self, idx: int) -> str | None:
        h = self.header
        if idx < 0 or idx >= h.type_ids_size:
            return None
        type_id_off = h.type_ids_off + idx * 4
        if type_id_off + 4 > len(self.data):
            return None
        string_idx = struct.unpack_from(f"{self.fmt}I", self.data, type_id_off)[0]
        return self.get_string(string_idx)

    def get_proto(self, idx: int) -> tuple[str | None, str | None, list[str]]:
        """Resolve proto_idx to (shorty, return_type, param_types)."""
        h = self.header
        if idx < 0 or idx >= h.proto_ids_size:
            return None, None, []
        pid_off = h.proto_ids_off + idx * 12
        if pid_off + 12 > len(self.data):
            return None, None, []
        shorty_idx, ret_type_idx, params_off = struct.unpack_from(f"{self.fmt}3I", self.data, pid_off)
        shorty = self.get_string(shorty_idx)
        ret_type = self.get_type_name(ret_type_idx)
        params: list[str] = []
        if params_off != 0 and params_off + 4 <= len(self.data):
            count = struct.unpack_from(f"{self.fmt}I", self.data, params_off)[0]
            if count <= 256 and params_off + 4 + count * 2 <= len(self.data):
                for i in range(count):
                    t_idx = struct.unpack_from(f"{self.fmt}H", self.data, params_off + 4 + i * 2)[0]
                    t_name = self.get_type_name(t_idx)
                    if t_name:
                        params.append(t_name)
        return shorty, ret_type, params

    def get_method_name(self, idx: int) -> str | None:
        """Resolve method_idx to the method's simple name."""
        h = self.header
        if idx < 0 or idx >= h.method_ids_size:
            return None
        mid_off = h.method_ids_off + idx * 8
        if mid_off + 8 > len(self.data):
            return None
        name_idx = struct.unpack_from(f"{self.fmt}HHI", self.data, mid_off)[2]
        return self.get_string(name_idx)

    def get_method_full(self, idx: int) -> tuple[str | None, str | None]:
        """Resolve method_idx to (class_descriptor, method_name)."""
        h = self.header
        if idx < 0 or idx >= h.method_ids_size:
            return None, None
        mid_off = h.method_ids_off + idx * 8
        if mid_off + 8 > len(self.data):
            return None, None
        vals = struct.unpack_from(f"{self.fmt}HHI", self.data, mid_off)
        return self.get_type_name(vals[0]), self.get_string(vals[2])

    def get_method_signature(self, idx: int) -> tuple[str | None, str | None, str]:
        """Resolve method_idx to (class_descriptor, method_name, '(params)ret')."""
        h = self.header
        if idx < 0 or idx >= h.method_ids_size:
            return None, None, "()?"
        mid_off = h.method_ids_off + idx * 8
        if mid_off + 8 > len(self.data):
            return None, None, "()?"
        cls_idx, proto_idx, name_idx = struct.unpack_from(f"{self.fmt}HHI", self.data, mid_off)
        _, ret_type, params = self.get_proto(proto_idx)
        proto_str = f"({''.join(params)}){ret_type or 'V'}"
        return self.get_type_name(cls_idx), self.get_string(name_idx), proto_str

    def get_field_full(self, idx: int) -> tuple[str | None, str | None]:
        """Resolve field_idx to (class_descriptor, field_name)."""
        h = self.header
        if idx < 0 or idx >= h.field_ids_size:
            return None, None
        fid_off = h.field_ids_off + idx * 8
        if fid_off + 8 > len(self.data):
            return None, None
        vals = struct.unpack_from(f"{self.fmt}HHI", self.data, fid_off)
        return self.get_type_name(vals[0]), self.get_string(vals[2])

    def get_field_detail(self, idx: int) -> tuple[str | None, str | None, str | None]:
        """Resolve field_idx to (class_descriptor, field_name, field_type)."""
        h = self.header
        if idx < 0 or idx >= h.field_ids_size:
            return None, None, None
        fid_off = h.field_ids_off + idx * 8
        if fid_off + 8 > len(self.data):
            return None, None, None
        cls_idx, type_idx, name_idx = struct.unpack_from(f"{self.fmt}HHI", self.data, fid_off)
        return self.get_type_name(cls_idx), self.get_string(name_idx), self.get_type_name(type_idx)

    def get_interfaces(self, cdef: ClassDef) -> list[str]:
        """Resolve the interface type descriptors implemented by ``cdef``."""
        off = cdef.interfaces_off
        if off == 0 or off + 4 > len(self.data):
            return []
        count = struct.unpack_from(f"{self.fmt}I", self.data, off)[0]
        if count > 256 or off + 4 + count * 2 > len(self.data):
            return []
        interfaces: list[str] = []
        for i in range(count):
            t_idx = struct.unpack_from(f"{self.fmt}H", self.data, off + 4 + i * 2)[0]
            t_name = self.get_type_name(t_idx)
            if t_name:
                interfaces.append(t_name)
        return interfaces

    def get_source_file(self, cdef: ClassDef) -> str | None:
        if cdef.source_file_idx == 0xFFFFFFFF:
            return None
        return self.get_string(cdef.source_file_idx)

    @property
    def all_methods(self) -> list[EncodedMethod]:
        methods = []
        for cdef in self.class_defs:
            if cdef.class_data:
                methods.extend(cdef.class_data.direct_methods)
                methods.extend(cdef.class_data.virtual_methods)
        return methods

    def compute_checksum(self) -> int:
        import zlib
        return zlib.adler32(self.data[12:]) & 0xFFFFFFFF

    def compute_signature(self) -> bytes:
        return hashlib.sha1(self.data[32:]).digest()
