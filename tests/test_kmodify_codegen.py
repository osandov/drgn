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


def _words(code):
    return [
        int.from_bytes(bytes(code)[i : i + 4], "little") for i in range(0, len(code), 4)
    ]


class TestPPC64Emitters(unittest.TestCase):
    def cg(self):
        from drgn.helpers.experimental.kmodify import _CodeGen_ppc64le

        return _CodeGen_ppc64le()

    def test_word_emitted_little_endian(self):
        cg = self.cg()
        cg._emit(0x60000000)  # nop (ori 0,0,0) — known-good constant
        self.assertEqual(bytes(cg.code), b"\x00\x00\x00\x60")

    def test_known_constant_encodings(self):
        # Independently-known encodings (from the Power ISA / kernel PPC_RAW_*).
        cg = self.cg()
        self.assertEqual(cg._mflr(0), 0x7C0802A6)  # mflr r0
        self.assertEqual(cg._mtctr(12), 0x7C0903A6 | (12 << 21))  # mtctr r12
        self.assertEqual(cg._BLR, 0x4E800020)
        self.assertEqual(cg._BCTRL, 0x4E800421)

    def test_li_negative_sign_extends(self):
        cg = self.cg()
        cg._emit(cg._addi(3, 0, -12345))  # li r3, -12345
        self.assertEqual(
            bytes(cg.code),
            (0x38000000 | (3 << 21) | (-12345 & 0xFFFF)).to_bytes(4, "little"),
        )

    def test_load_imm_small_negative_is_single_li(self):
        cg = self.cg()
        cg._load_imm(3, -12345)  # fits signed 16-bit -> one li (sign-extends)
        self.assertEqual(_words(cg.code), [cg._addi(3, 0, -12345)])

    def test_load_imm_32bit(self):
        cg = self.cg()
        cg._load_imm(3, 0x0001D431)  # > 16-bit, < 2^31 -> lis + ori
        self.assertEqual(
            _words(cg.code),
            [cg._addis(3, 0, 0x0001), cg._ori(3, 3, 0xD431)],
        )

    def test_load_imm_full64_all_pieces(self):
        cg = self.cg()
        cg._load_imm(3, 0x123456789ABCDEF0)
        self.assertEqual(
            _words(cg.code),
            [
                cg._addis(3, 0, 0x1234),  # lis  -> bits 48-63
                cg._ori(3, 3, 0x5678),  # ori  -> bits 32-47
                cg._rldicr32(3, 3),  # << 32
                cg._oris(3, 3, 0x9ABC),  # oris -> bits 16-31
                cg._ori(3, 3, 0xDEF0),  # ori  -> bits 0-15
            ],
        )

    def test_load_imm_full64_kernel_address(self):
        # Typical kernel text address: high 16 bits set, low 16 set, middle 0.
        cg = self.cg()
        cg._load_imm(12, 0xC000000000001234)
        self.assertEqual(
            _words(cg.code),
            [
                cg._addis(12, 0, 0xC000),  # lis (middle pieces skipped)
                cg._rldicr32(12, 12),
                cg._ori(12, 12, 0x1234),
            ],
        )


class TestArchSelection(unittest.TestCase):
    def test_ppc64_arch_constants(self):
        from drgn.helpers.experimental.kmodify import _Arch_PPC64

        self.assertEqual(_Arch_PPC64.ELF_MACHINE, 21)  # EM_PPC64
        self.assertTrue(_Arch_PPC64.RELA)
        self.assertEqual(
            _Arch_PPC64.ABSOLUTE_ADDRESS_RELOCATION_TYPE, 38
        )  # R_PPC64_ADDR64
