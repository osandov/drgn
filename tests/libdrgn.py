import ctypes
import enum
from enum import auto
import os
from typing import BinaryIO, NamedTuple, Optional, Sequence, Union

import drgn
from drgn.internal.mock import MockType
from tests import _drgn_pydll, _drgn_cdll
from tests.libelf import _Elf, Elf
from tests.libdw import _Dwarf_Die, Die


class _drgn_error(ctypes.Structure):
    _fields_ = [
        ('code', ctypes.c_uint),
        ('errnum', ctypes.c_int),
        ('path', ctypes.c_char_p),
        ('msg', ctypes.c_char_p),
    ]


_drgn_pydll.set_drgn_error.restype = ctypes.py_object
_drgn_pydll.set_drgn_error.argtypes = [ctypes.POINTER(_drgn_error)]


def _check_err(err):
    if err:
        return _drgn_pydll.set_drgn_error(err)


class _path_iterator_component(ctypes.Structure):
    _fields_ = [
        ('path', ctypes.c_char_p),
        ('len', ctypes.c_size_t),
    ]


class _path_iterator(ctypes.Structure):
    _fields_ = [
        ('components', ctypes.POINTER(_path_iterator_component)),
        ('num_components', ctypes.c_size_t),
        ('dot_dot', ctypes.c_size_t),
    ]


_drgn_cdll.drgn_test_path_iterator_next.restype = ctypes.c_bool
_drgn_cdll.drgn_test_path_iterator_next.argtypes = [
    ctypes.POINTER(_path_iterator),
    ctypes.POINTER(ctypes.POINTER(ctypes.c_char)),
    ctypes.POINTER(ctypes.c_size_t),
]


class PathIterator:
    def __init__(self, *paths):
        components = (_path_iterator_component * len(paths))()
        for i, path in enumerate(paths):
            path = os.fsencode(path)
            components[i].path = path
            components[i].len = len(path)
        self._it = _path_iterator(components, len(paths))

    def __iter__(self):
        return self

    def __next__(self):
        component = ctypes.POINTER(ctypes.c_char)()
        component_len = ctypes.c_size_t()
        if _drgn_cdll.drgn_test_path_iterator_next(ctypes.pointer(self._it),
                                                   ctypes.pointer(component),
                                                   ctypes.pointer(component_len)):
            return os.fsdecode(ctypes.string_at(component,
                                                component_len.value))
        else:
            raise StopIteration()


_drgn_cdll.drgn_test_path_ends_with.restype = ctypes.c_bool
_drgn_cdll.drgn_test_path_ends_with.argtypes = [
    ctypes.POINTER(_path_iterator), ctypes.POINTER(_path_iterator),
]


def path_ends_with(path1: PathIterator, path2: PathIterator):
    return _drgn_cdll.drgn_test_path_ends_with(ctypes.pointer(path1._it),
                                               ctypes.pointer(path2._it))


class _drgn_type(ctypes.Structure):
    pass


class _drgn_qualified_type(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.POINTER(_drgn_type)),
        ('qualifiers', ctypes.c_uint),
    ]


_drgn_pydll.DrgnType_wrap.restype = ctypes.py_object
_drgn_pydll.DrgnType_wrap.argtypes = [_drgn_qualified_type, ctypes.py_object]


class _drgn_memory_reader(ctypes.Structure):
    pass


class _drgn_memory_file_segment(ctypes.Structure):
    _fields_ = [
	('file_offset', ctypes.c_uint64),
	('virt_addr', ctypes.c_uint64),
	('phys_addr', ctypes.c_uint64),
	('file_size', ctypes.c_uint64),
	('mem_size', ctypes.c_uint64),
    ]


_drgn_cdll.drgn_test_memory_reader_read.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_memory_reader_read.argtypes = [
    ctypes.POINTER(_drgn_memory_reader), ctypes.c_void_p, ctypes.c_uint64,
    ctypes.c_size_t, ctypes.c_bool,
]
_drgn_cdll.drgn_test_memory_reader_destroy.restype = None
_drgn_cdll.drgn_test_memory_reader_destroy.argtypes = [
    ctypes.POINTER(_drgn_memory_reader),
]
_drgn_cdll.drgn_test_memory_file_reader_create.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_memory_file_reader_create.argtypes = [
    ctypes.c_int, ctypes.POINTER(ctypes.POINTER(_drgn_memory_reader)),
]
_drgn_cdll.drgn_test_memory_file_reader_add_segment.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_memory_file_reader_add_segment.argtypes = [
    ctypes.POINTER(_drgn_memory_reader),
    ctypes.POINTER(_drgn_memory_file_segment),
]


class MemoryReader:
    def __init__(self, reader):
        self._reader = reader

    def __del__(self):
        if hasattr(self, '_reader'):
            _drgn_cdll.drgn_test_memory_reader_destroy(self._reader)

    def read(self, address: int, count: int, physical: bool = False):
        buf = ctypes.create_string_buffer(count)
        _check_err(_drgn_cdll.drgn_test_memory_reader_read(self._reader, buf,
                                                           address, count,
                                                           physical))
        return bytes(buf)


class MemoryFileSegment(NamedTuple):
    file_offset: int
    file_size: int
    mem_size: int
    virt_addr: Optional[int] = None
    phys_addr: Optional[int] = None


class MemoryFileReader(MemoryReader):
    def __init__(self, segments: Sequence[MemoryFileSegment],
                 file: Union[BinaryIO, int]) -> None:
        if isinstance(file, int):
            fd = file
        else:
            fd = file.fileno()
        reader = ctypes.POINTER(_drgn_memory_reader)()
        _check_err(_drgn_cdll.drgn_test_memory_file_reader_create(
            fd, ctypes.pointer(reader)))
        super().__init__(reader)
        for segment in segments:
            self.add_segment(segment)

    def add_segment(self, segment: MemoryFileSegment):
        c_segment = _drgn_memory_file_segment()
        c_segment.file_offset = segment.file_offset
        c_segment.file_size = segment.file_size
        c_segment.mem_size = segment.mem_size
        if segment.virt_addr is None:
            c_segment.virt_addr = 2**64 - 1
        else:
            c_segment.virt_addr = segment.virt_addr
        if segment.phys_addr is None:
            c_segment.phys_addr = 2**64 - 1
        else:
            c_segment.phys_addr = segment.phys_addr
        _check_err(_drgn_cdll.drgn_test_memory_file_reader_add_segment(
            self._reader, ctypes.pointer(c_segment)))


class _drgn_dwarf_index(ctypes.Structure):
    pass


_drgn_cdll.drgn_test_dwarf_index_create.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_dwarf_index_create.argtypes = [
    ctypes.c_int, ctypes.POINTER(ctypes.POINTER(_drgn_dwarf_index)),
]
_drgn_cdll.drgn_test_dwarf_index_destroy.restype = None
_drgn_cdll.drgn_test_dwarf_index_destroy.argtypes = [
    ctypes.POINTER(_drgn_dwarf_index),
]
_drgn_cdll.drgn_test_dwarf_index_open.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_dwarf_index_open.argtypes = [
    ctypes.POINTER(_drgn_dwarf_index), ctypes.c_char_p,
    ctypes.POINTER(ctypes.POINTER(_Elf)),
]
_drgn_cdll.drgn_test_dwarf_index_open_elf.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_dwarf_index_open_elf.argtypes = [
    ctypes.POINTER(_drgn_dwarf_index), ctypes.POINTER(_Elf),
]
_drgn_cdll.drgn_test_dwarf_index_update.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_dwarf_index_update.argtypes = [
    ctypes.POINTER(_drgn_dwarf_index),
]


class DwarfIndex:
    def __init__(self):
        dindex = ctypes.POINTER(_drgn_dwarf_index)()
        _check_err(_drgn_cdll.drgn_test_dwarf_index_create(
            0xf, ctypes.pointer(dindex)))
        self._dindex = dindex
        self._files = []

    def __del__(self):
        if hasattr(self, '_dindex'):
            _drgn_cdll.drgn_test_dwarf_index_destroy(self._dindex)

    def open(self, file: Union[str, Elf]):
        if isinstance(file, Elf):
            _check_err(_drgn_cdll.drgn_test_dwarf_index_open_elf(
                self._dindex, file._elf))
            # Need to keep a reference on the Elf handle.
            self._files.append(file)
        else:
            _check_err(_drgn_cdll.drgn_test_dwarf_index_open(
                self._dindex, os.fsencode(file), 0))

    def update(self):
        _check_err(_drgn_cdll.drgn_test_dwarf_index_update(self._dindex))


class _drgn_type_index(ctypes.Structure):
    pass


_drgn_cdll.drgn_test_type_index_destroy.restype = None
_drgn_cdll.drgn_test_type_index_destroy.argtypes = [
    ctypes.POINTER(_drgn_type_index),
]
_drgn_cdll.drgn_test_type_index_find.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_type_index_find.argtypes = [
    ctypes.POINTER(_drgn_type_index), ctypes.c_char_p, ctypes.c_char_p,
    ctypes.POINTER(_drgn_qualified_type),
]


class TypeIndex:
    def __init__(self, tindex):
        self._tindex = tindex

    def __del__(self):
        if hasattr(self, '_tindex'):
            _drgn_cdll.drgn_test_type_index_destroy(self._tindex)

    def find(self, name: str, filename: Optional[str] = None):
        qualified_type = _drgn_qualified_type()
        _check_err(_drgn_cdll.drgn_test_type_index_find(
            self._tindex, name.encode(),
            None if filename is None else os.fsencode(filename),
            ctypes.pointer(qualified_type)))
        return _drgn_pydll.DrgnType_wrap(qualified_type, self)


_drgn_cdll.drgn_test_dwarf_type_index_create.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_dwarf_type_index_create.argtypes = [
    ctypes.POINTER(_drgn_dwarf_index),
    ctypes.POINTER(ctypes.POINTER(_drgn_type_index)),
]
_drgn_cdll.drgn_test_type_from_dwarf.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_type_from_dwarf.argtypes = [
    ctypes.POINTER(_drgn_type_index),
    ctypes.POINTER(_Dwarf_Die),
    ctypes.POINTER(_drgn_qualified_type),
]


class DwarfTypeIndex(TypeIndex):
    def __init__(self, dindex: DwarfIndex):
        tindex = ctypes.POINTER(_drgn_type_index)()
        _check_err(_drgn_cdll.drgn_test_dwarf_type_index_create(
            dindex._dindex, ctypes.pointer(tindex)))
        self._dindex = dindex
        self._dwarves = set()
        super().__init__(tindex)

    def type_from_dwarf(self, die: Die) -> drgn.Type:
        qualified_type = _drgn_qualified_type()
        # We're caching this Dwarf instance now, so we have to keep it alive.
        self._dwarves.add(die._dwarf)
        _check_err(_drgn_cdll.drgn_test_type_from_dwarf(
            self._tindex, die._die, ctypes.pointer(qualified_type)))
        return _drgn_pydll.DrgnType_wrap(qualified_type, self)


class _drgn_mock_type(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.POINTER(_drgn_type)),
        ('filename', ctypes.c_char_p),
    ]


_drgn_cdll.drgn_test_mock_type_index_create.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_mock_type_index_create.argtypes = [
    ctypes.c_uint8, ctypes.c_bool, ctypes.POINTER(_drgn_mock_type),
    ctypes.c_size_t, ctypes.POINTER(ctypes.POINTER(_drgn_type_index)),
]


class MockTypeIndex(TypeIndex):
    def __init__(self, word_size: int, byteorder: str,
                 types: Sequence[MockType]) -> None:
        if byteorder == 'little':
            little_endian = True
        elif byteorder == 'big':
            little_endian = False
        else:
            raise ValueError("byteorder must be either 'little' or 'big'")
        self._types = (_drgn_mock_type * len(types))()
        self._type_objs = []
        for i, mock_type in enumerate(types):
            self._type_objs.append(mock_type.type)
            self._types[i].type = ctypes.cast(mock_type.type._ptr,
                                              ctypes.POINTER(_drgn_type))
            filename = (None if mock_type.filename is None else
                        os.fsencode(mock_type.filename))
            self._types[i].filename = filename
        tindex = ctypes.POINTER(_drgn_type_index)()
        _check_err(_drgn_cdll.drgn_test_mock_type_index_create(
            word_size, little_endian, self._types, len(types),
            ctypes.pointer(tindex)))
        super().__init__(tindex)


class _drgn_partial_object_union(ctypes.Union):
    _fields_ = [
        ('address', ctypes.c_uint64),
        ('svalue', ctypes.c_int64),
        ('uvalue', ctypes.c_uint64),
    ]


class _drgn_partial_object(ctypes.Structure):
    _anonymous_ = ('u',)
    _fields_ = [
        ('type', _drgn_qualified_type),
        ('is_enumerator', ctypes.c_bool),
        ('little_endian', ctypes.c_bool),
        ('u', _drgn_partial_object_union),
    ]


class PartialObject(NamedTuple):
    type: drgn.Type
    is_enumerator: bool = False
    value: Optional[int] = None
    address: Optional[int] = None
    little_endian: Optional[bool] = None


def _partial_object_wrap(pobj, parent):
    type_ = _drgn_pydll.DrgnType_wrap(pobj.type, parent)
    if pobj.is_enumerator:
        value = pobj.svalue if type_.type.is_signed else pobj.uvalue
        return PartialObject(type_, is_enumerator=True, value=value)
    else:
        return PartialObject(type_, address=pobj.address,
                             little_endian=pobj.little_endian)


class _drgn_object_index(ctypes.Structure):
    pass


_drgn_cdll.drgn_test_object_index_find.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_object_index_find.argtypes = [
    ctypes.POINTER(_drgn_object_index), ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_uint, ctypes.POINTER(_drgn_partial_object),
]
_drgn_cdll.drgn_test_object_index_destroy.restype = None
_drgn_cdll.drgn_test_object_index_destroy.argtypes = [
    ctypes.POINTER(_drgn_object_index),
]


class FindObjectFlags(enum.Flag):
    CONSTANT = 1 << 0
    FUNCTION = 1 << 1
    VARIABLE = 1 << 2
    ANY = (1 << 3) - 1


class ObjectIndex:
    def __init__(self, oindex):
        self._oindex = oindex

    def __del__(self):
        if hasattr(self, '_oindex'):
            _drgn_cdll.drgn_test_object_index_destroy(self._oindex)

    def find(self, name: str, filename: Optional[str] = None,
             flags=FindObjectFlags.ANY) -> PartialObject:
        pobj = _drgn_partial_object()
        _check_err(_drgn_cdll.drgn_test_object_index_find(
            self._oindex, name.encode(),
            None if filename is None else os.fsencode(filename), flags.value,
            ctypes.pointer(pobj)))
        return _partial_object_wrap(pobj, self)


_drgn_cdll.drgn_test_dwarf_object_index_create.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_dwarf_object_index_create.argtypes = [
    ctypes.POINTER(_drgn_type_index),
    ctypes.POINTER(ctypes.POINTER(_drgn_object_index)),
]


class DwarfObjectIndex(ObjectIndex):
    def __init__(self, dtindex: DwarfTypeIndex):
        oindex = ctypes.POINTER(_drgn_object_index)()
        _check_err(_drgn_cdll.drgn_test_dwarf_object_index_create(
            dtindex._tindex, ctypes.pointer(oindex)))
        self._dtindex = dtindex
        super().__init__(oindex)


class _drgn_token(ctypes.Structure):
    _fields_ = [
        ('kind', ctypes.c_int),
        ('value', ctypes.c_void_p),
        ('len', ctypes.c_size_t),
    ]


class _drgn_lexer(ctypes.Structure):
    _fields_ = [
        ('func', ctypes.c_void_p),
        ('p', ctypes.c_void_p),
        ('stack', ctypes.POINTER(_drgn_token)),
        ('stack_len', ctypes.c_size_t),
        ('stack_capacity', ctypes.c_size_t),
    ]


drgn_lexer_func = ctypes.CFUNCTYPE(ctypes.POINTER(_drgn_error),
                                   ctypes.POINTER(_drgn_lexer),
                                   ctypes.POINTER(_drgn_token))


_drgn_cdll.drgn_test_lexer_init.restype = None
_drgn_cdll.drgn_test_lexer_init.argtypes = [
    ctypes.POINTER(_drgn_lexer), ctypes.POINTER(drgn_lexer_func),
    ctypes.c_char_p,
]
_drgn_cdll.drgn_test_lexer_deinit.restype = None
_drgn_cdll.drgn_test_lexer_deinit.argtypes = [ctypes.POINTER(_drgn_lexer)]
_drgn_cdll.drgn_test_lexer_pop.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_lexer_pop.argtypes = [
    ctypes.POINTER(_drgn_lexer), ctypes.POINTER(_drgn_token),
]
_drgn_cdll.drgn_test_lexer_push.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_lexer_push.argtypes = [
    ctypes.POINTER(_drgn_lexer), ctypes.POINTER(_drgn_token),
]
_drgn_cdll.drgn_test_lexer_peek.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_lexer_peek.argtypes = [
    ctypes.POINTER(_drgn_lexer), ctypes.POINTER(_drgn_token),
]


drgn_lexer_c = drgn_lexer_func.in_dll(_drgn_cdll, 'drgn_test_lexer_c')
drgn_test_lexer_func = drgn_lexer_func.in_dll(_drgn_cdll, 'drgn_test_lexer_func')


class C_TOKEN(enum.IntEnum):
    EOF = -1
    VOID = auto()
    CHAR = auto()
    SHORT = auto()
    INT = auto()
    LONG = auto()
    SIGNED = auto()
    UNSIGNED = auto()
    BOOL = auto()
    FLOAT = auto()
    DOUBLE = auto()
    COMPLEX = auto()
    CONST = auto()
    RESTRICT = auto()
    VOLATILE = auto()
    ATOMIC = auto()
    STRUCT = auto()
    UNION = auto()
    ENUM = auto()
    LPAREN = auto()
    RPAREN = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    ASTERISK = auto()
    DOT = auto()
    NUMBER = auto()
    IDENTIFIER = auto()


class Token:
    def __init__(self, token):
        self._token = token

    @property
    def kind(self):
        return self._token.kind

    @property
    def value(self):
        return ctypes.string_at(self._token.value, self._token.len).decode()

    def __repr__(self):
        return f'Token({self.kind}, {self.value!r})'


class Lexer:
    def __init__(self, func, str):
        self._lexer = _drgn_lexer()
        self._func = func
        self._str = str.encode()
        _drgn_cdll.drgn_test_lexer_init(ctypes.pointer(self._lexer),
                                        self._func, self._str)

    def __del__(self):
        _drgn_cdll.drgn_test_lexer_deinit(ctypes.pointer(self._lexer))

    def pop(self):
        token = _drgn_token()
        _check_err(_drgn_cdll.drgn_test_lexer_pop(ctypes.pointer(self._lexer),
                                                  ctypes.pointer(token)))
        return Token(token)

    def push(self, token):
        _check_err(_drgn_cdll.drgn_test_lexer_push(ctypes.pointer(self._lexer),
                                                   ctypes.pointer(token._token)))

    def peek(self):
        token = _drgn_token()
        _check_err(_drgn_cdll.drgn_test_lexer_peek(ctypes.pointer(self._lexer),
                                                   ctypes.pointer(token)))
        return Token(token)


_drgn_cdll.drgn_test_serialize_bits.restype = None
_drgn_cdll.drgn_test_serialize_bits.argtypes = [
    ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint8,
    ctypes.c_bool,
]
_drgn_cdll.drgn_test_deserialize_bits.restype = ctypes.c_uint64
_drgn_cdll.drgn_test_deserialize_bits.argtypes = [
    ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint8, ctypes.c_bool,
]


def serialize_bits(buf, bit_offset, uvalue, bit_size, little_endian):
    assert (bit_offset + bit_size + 7) // 8 <= len(buf)
    c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
    return _drgn_cdll.drgn_test_serialize_bits(c_buf, bit_offset, uvalue,
                                               bit_size, little_endian)


def deserialize_bits(buf, bit_offset, bit_size, little_endian):
    assert (bit_offset + bit_size + 7) // 8 <= len(buf)
    c_buf = (ctypes.c_char * len(buf)).from_buffer_copy(buf)
    return _drgn_cdll.drgn_test_deserialize_bits(c_buf, bit_offset, bit_size,
                                                 little_endian)
