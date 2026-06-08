# (C) Copyright IBM Corp. 2026
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Host-runnable unit tests for the kmodify machine-code generators. These exercise
the pure ``_Arch_*.code_gen`` functions with no kernel or virtual machine; the
end-to-end authority for instruction encoding is the integration test
(``tests/linux_kernel/helpers/test_kmodify.py``) run on each architecture's VM.
"""

import unittest

from drgn.helpers.experimental.kmodify import (
    _Arch_X86_64,
    _Call,
    _Function,
    _Integer,
    _Return,
    _ReturnIfLastReturnValueNonZero,
    _StoreReturnValue,
    _Symbol,
)

_X86_64_GOLDEN_FUNCTION = _Function(
    [
        _Call(
            _Symbol("func"),
            [_Integer(4, -12345), _Symbol(".data", section=True, offset=8)],
        ),
        _StoreReturnValue(8, _Symbol(".data", section=True)),
        _ReturnIfLastReturnValueNonZero(_Integer(4, -14)),
        _Return(_Integer(4, -115)),
    ]
)

# Captured from main before the _Arch refactor.
_X86_64_GOLDEN_CODE = (
    b"\xf3\x0f\x1e\xfaUH\x89\xe5\xbf\xc7\xcf\xff\xffH\xc7\xc6\x00\x00\x00\x00"
    b"\xe8\x00\x00\x00\x00H\x89\x05\x00\x00\x00\x00H\x89\xc2\xb8\xf2\xff\xff"
    b"\xffH\x85\xd2\x0f\x85\x05\x00\x00\x00\xb8\x8d\xff\xff\xff\xc9\xc3"
)
_X86_64_GOLDEN_RELOCS = [
    (16, 11, ".data", True, 8),
    (21, 4, "func", False, -4),
    (28, 2, ".data", True, -4),
]


class TestX86_64CodegenGolden(unittest.TestCase):
    def test_codegen_unchanged(self):
        result = _Arch_X86_64.code_gen(_X86_64_GOLDEN_FUNCTION)
        self.assertEqual(bytes(result.code), _X86_64_GOLDEN_CODE)
        self.assertEqual(
            [tuple(r) for r in result.code_relocations], _X86_64_GOLDEN_RELOCS
        )
        self.assertEqual(bytes(result.toc), b"")
        self.assertEqual(list(result.toc_relocations), [])


class TestArchSelection(unittest.TestCase):
    def test_ppc64_arch_constants(self):
        from drgn.helpers.experimental.kmodify import _Arch_PPC64

        self.assertEqual(_Arch_PPC64.ELF_MACHINE, 21)  # EM_PPC64
        self.assertTrue(_Arch_PPC64.RELA)
        self.assertEqual(
            _Arch_PPC64.ABSOLUTE_ADDRESS_RELOCATION_TYPE, 38
        )  # R_PPC64_ADDR64
