import ctypes

from tests import _drgn_cdll
from tests.libelf import _Elf, Elf


_DWARF_C_READ = 0
_DWARF_C_RDWR = 1
_DWARF_C_WRITE = 2


class _Dwarf(ctypes.Structure):
    pass


class _Dwarf_CU(ctypes.Structure):
    pass


class _Dwarf_Die(ctypes.Structure):
    _fields_ = [
        ('addr', ctypes.c_void_p),
        ('cu', ctypes.POINTER(_Dwarf_CU)),
        ('abbrev', ctypes.c_void_p),
        ('padding__', ctypes.c_long),
    ]


_drgn_cdll.drgn_test_dwarf_errmsg.restype = ctypes.c_char_p
_drgn_cdll.drgn_test_dwarf_errmsg.argtypes = [ctypes.c_int]
_drgn_cdll.drgn_test_dwarf_begin_elf.restype = ctypes.POINTER(_Dwarf)
_drgn_cdll.drgn_test_dwarf_begin_elf.argtypes = [
    ctypes.POINTER(_Elf), ctypes.c_uint, ctypes.c_void_p,
]
_drgn_cdll.drgn_test_dwarf_end.restype = ctypes.c_int
_drgn_cdll.drgn_test_dwarf_end.argtypes = [ctypes.POINTER(_Dwarf)]
_drgn_cdll.drgn_test_dwarf_nextcu.restype = ctypes.c_int
_drgn_cdll.drgn_test_dwarf_nextcu.argtypes = [
    ctypes.POINTER(_Dwarf), ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8),
]
_drgn_cdll.drgn_test_dwarf_offdie.restype = ctypes.POINTER(_Dwarf_Die)
_drgn_cdll.drgn_test_dwarf_offdie.argtypes = [
    ctypes.POINTER(_Dwarf), ctypes.c_uint64, ctypes.POINTER(_Dwarf_Die),
]
_drgn_cdll.drgn_test_dwarf_tag.restype = ctypes.c_int
_drgn_cdll.drgn_test_dwarf_tag.argtypes = [ctypes.POINTER(_Dwarf_Die)]
_drgn_cdll.drgn_test_dwarf_child.restype = ctypes.c_int
_drgn_cdll.drgn_test_dwarf_child.argtypes = [
    ctypes.POINTER(_Dwarf_Die), ctypes.POINTER(_Dwarf_Die),
]
_drgn_cdll.drgn_test_dwarf_siblingof.restype = ctypes.c_int
_drgn_cdll.drgn_test_dwarf_siblingof.argtypes = [
    ctypes.POINTER(_Dwarf_Die), ctypes.POINTER(_Dwarf_Die),
]


def _dwarf_exception():
    raise Exception(_drgn_cdll.drgn_test_dwarf_errmsg(-1).decode())


class Dwarf:
    def __init__(self, elf: Elf, mode: str = 'r'):
        if mode == 'r':
            cmd = _DWARF_C_READ
        elif mode == 'w':
            cmd = _DWARF_C_WRITE
        elif mode == 'rw':
            cmd = _DWARF_C_RDWR
        else:
            raise ValueError("mode must be 'r', 'w', or 'rw'")

        self._elf = elf
        self._dwarf = _drgn_cdll.drgn_test_dwarf_begin_elf(elf._elf, cmd, None)
        if not self._dwarf:
            _dwarf_exception()

    def __del__(self):
        _drgn_cdll.drgn_test_dwarf_end(self._dwarf)

    def cus(self):
        offset = ctypes.c_uint64()
        header_size = ctypes.c_size_t()
        while True:
            old_offset = offset.value
            if _drgn_cdll.drgn_test_dwarf_nextcu(self._dwarf, old_offset,
                                                 ctypes.pointer(offset),
                                                 ctypes.pointer(header_size),
                                                 None, None, None):
                break
            yield self.offdie(old_offset + header_size.value)

    def offdie(self, offset: int) -> 'Die':
        die = _Dwarf_Die()
        if not _drgn_cdll.drgn_test_dwarf_offdie(self._dwarf, offset,
                                                 ctypes.pointer(die)):
            _dwarf_exception()
        return Die(self, die)


class Die:
    def __init__(self, dwarf, die):
        self._dwarf = dwarf
        self._die = die

    @property
    def tag(self):
        return _drgn_cdll.drgn_test_dwarf_tag(ctypes.pointer(self._die))

    def children(self):
        child = _Dwarf_Die()
        ret = _drgn_cdll.drgn_test_dwarf_child(self._die, ctypes.pointer(child))
        while ret == 0:
            yield Die(self._dwarf, child)
            prev = child
            child = _Dwarf_Die()
            ret = _drgn_cdll.drgn_test_dwarf_siblingof(prev, child)
        if ret == -1:
            _dwarf_exception()
