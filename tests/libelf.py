import ctypes

from tests import _drgn_cdll


class _Elf(ctypes.Structure):
    pass


_drgn_cdll.drgn_test_elf_errmsg.restype = ctypes.c_char_p
_drgn_cdll.drgn_test_elf_errmsg.argtypes = [ctypes.c_int]
_drgn_cdll.drgn_test_elf_memory.restype = ctypes.POINTER(_Elf)
_drgn_cdll.drgn_test_elf_memory.argtypes = [
    ctypes.POINTER(ctypes.c_char), ctypes.c_size_t,
]
_drgn_cdll.drgn_test_elf_end.restype = ctypes.c_int
_drgn_cdll.drgn_test_elf_end.argtypes = [ctypes.POINTER(_Elf)]


class Elf:
    def __init__(self, elf):
        self._elf = elf

    def __del__(self):
        _drgn_cdll.drgn_test_elf_end(self._elf)


def elf_memory(image: bytes, mutable: bool = False):
    if mutable:
        image = ctypes.create_string_buffer(image)
    c_elf = _drgn_cdll.drgn_test_elf_memory(image, len(image))
    if not c_elf:
        raise Exception(_drgn_cdll.drgn_test_elf_errmsg(-1).decode())
    elf = Elf(c_elf)
    elf._image = image
    return elf
