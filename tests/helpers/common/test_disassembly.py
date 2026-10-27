# Copyright 2026 Anthropic PBC
# (C) Copyright IBM Corp. 2026
# SPDX-License-Identifier: LGPL-2.1-or-later

import io
import unittest.mock

from drgn import (
    Architecture,
    FaultError,
    Object,
    Platform,
    Program,
    Symbol,
    SymbolBinding,
    SymbolKind,
)
from drgn.helpers.common.disassembly import disasm
from tests import MockMemorySegment, TestCase, mock_program, skip_unless_have_capstone


def mock_symbol(name, address, size, kind=SymbolKind.FUNC):
    return Symbol(name, address, size, SymbolBinding.GLOBAL, kind)


class TestNoCapstone(TestCase):
    def test_no_capstone(self):
        with unittest.mock.patch.dict("sys.modules", {"capstone": None}):
            self.assertRaisesRegex(
                NotImplementedError,
                "Capstone",
                disasm,
                mock_program(Platform(Architecture.X86_64)),
                0xF000,
            )


@skip_unless_have_capstone
class TestDisasmErrors(TestCase):
    def test_no_platform(self):
        self.assertRaises(ValueError, disasm, Program(), 0xF000)

    def test_unknown_arch(self):
        self.assertRaises(NotImplementedError, disasm, mock_program(), 0xF000)

    def test_invalid_arguments(self):
        for name, value in (
            ("mode", "foo"),
            ("num_insns", 0),
            ("num_insns", -1),
            ("offset_base", 8),
        ):
            with self.subTest(**{name: value}):
                self.assertRaisesRegex(
                    ValueError,
                    name,
                    disasm,
                    mock_program(Platform(Architecture.X86_64)),
                    0xF000,
                    **{name: value},
                )


DISCLAIMER = "(could not find function containing 0xf000)\n"


@skip_unless_have_capstone
class TestDisasmX86_64(TestCase):
    PLATFORM = Platform(Architecture.X86_64)

    # Disassemble code at 0xf000 + offset, optionally in a symbol named foo.
    def disasm(
        self,
        code,
        *,
        code_after=b"",
        symbol=True,
        symbol_size=None,
        symbol_kind=SymbolKind.FUNC,
        offset=0,
        symbolize=False,
        **kwargs,
    ):
        prog = mock_program(
            self.PLATFORM,
            segments=(MockMemorySegment(code + code_after, 0xF000),),
        )
        if symbol:
            foo = mock_symbol(
                "foo",
                0xF000,
                len(code) if symbol_size is None else symbol_size,
                symbol_kind,
            )

            # Like the ELF symbol finder and unlike SymbolIndex, this matches
            # addresses after a sizeless symbol.
            def find_symbol(prog, name, address, one):
                if address >= foo.address and (
                    foo.size == 0 or address < foo.address + foo.size
                ):
                    return [foo]
                return []

            prog.register_symbol_finder("mock", find_symbol, enable_index=0)
        f = io.StringIO()
        disasm(prog, 0xF000 + offset, symbolize=symbolize, file=f, **kwargs)
        return f.getvalue()

    def _test_1_instruction(self, code, asm):
        for symbol, mode, num_insns in (
            (True, None, None),
            (True, None, 1),
            (True, "symbol", None),
            (True, "symbol", 1),
            (True, "from", None),
            (True, "from", 1),
            (True, "up_to", None),
            (True, "up_to", 1),
            (False, None, 1),
            (False, "from", None),
            (False, "from", 1),
        ):
            with self.subTest(symbol=symbol, mode=mode, num_insns=num_insns):
                self.assertEqual(
                    self.disasm(code, symbol=symbol, mode=mode, num_insns=num_insns),
                    asm,
                )

    def test_10_byte_instruction(self):
        self._test_1_instruction(
            b"\x48\xb8\x67\x69\x72\x61\x66\x66\x65\x73",
            "0xf000:  movabsq $0x7365666661726967, %rax\n",
        )

    def test_long_mnemonic(self):
        self.assertEqual(
            self.disasm(
                b"\x5d\x48\xb8\x67\x69\x72\x61\x66\x66\x65\x73\xf0\x48\x0f\xb1\x0f"
            ),
            """\
0xf000:  popq    %rbp
0xf001:  movabsq $0x7365666661726967, %rax
0xf00b:  lock cmpxchgq %rcx, (%rdi)
""",
        )

    # mode=None

    def test_default_symbol(self):
        for symbol_kind in (SymbolKind.FUNC, SymbolKind.IFUNC, SymbolKind.UNKNOWN):
            with self.subTest(symbol_kind=symbol_kind):
                self.assertEqual(
                    self.disasm(b"\xff\xc0\xc3", symbol_kind=symbol_kind),
                    """\
0xf000:  incl    %eax
0xf002:  retq
""",
                )

    def test_default_symbol_offset(self):
        for offset in (1, 2):
            with self.subTest(offset=offset):
                self.assertEqual(
                    self.disasm(b"\x90\xff\xc0\xc3", offset=offset),
                    """\
   0xf000:  nop
=> 0xf001:  incl    %eax
   0xf003:  retq
""",
                )

    def test_default_num_insns(self):
        # This counts from the address, not the symbol.
        self.assertEqual(
            self.disasm(b"\x90\xff\xc0\xc3", offset=1, num_insns=1),
            "0xf001:  incl    %eax\n",
        )

    def test_default_no_symbol(self):
        self.assertEqual(
            self.disasm(b"\xff\xc0\xc3", symbol=False),
            DISCLAIMER + "0xf000:  incl    %eax\n",
        )

    def test_default_unusable_symbol(self):
        # The symbol can't be used as bounds, but it can be used for
        # symbolization.
        for kwargs in ({"symbol_size": 0}, {"symbol_kind": SymbolKind.OBJECT}):
            with self.subTest(**kwargs):
                self.assertEqual(
                    self.disasm(b"\xff\xc0\xc3", symbolize=True, **kwargs),
                    DISCLAIMER + "0xf000 <foo>:  incl    %eax\n",
                )

    # mode="symbol"

    def test_symbol_num_insns(self):
        self.assertEqual(
            self.disasm(b"\x90\xff\xc0\xc3", mode="symbol", offset=3, num_insns=2),
            """\
   0xf000:  nop
   0xf001:  incl    %eax
""",
        )

    def test_symbol_instruction_extends_past_end(self):
        self.assertEqual(
            self.disasm(b"\x90\x48\x89", code_after=b"\xe5\x90", mode="symbol"),
            """\
0xf000:  nop
0xf001:  movq    %rsp, %rbp
""",
        )

    def test_symbol_not_found(self):
        for kwargs in (
            {"symbol": False},
            {"symbol_size": 0},
            {"symbol_kind": SymbolKind.OBJECT},
        ):
            for mode in ("symbol", "up_to"):
                with self.subTest(**kwargs, mode=mode):
                    self.assertRaisesRegex(
                        LookupError,
                        "could not find function containing 0xf000",
                        self.disasm,
                        b"\xff\xc0\xc3",
                        mode=mode,
                        **kwargs,
                    )

    # mode="from"

    def test_from(self):
        self.assertEqual(
            self.disasm(
                b"\x90\xff\xc0\xc3", code_after=b"\x90" * 32, mode="from", offset=1
            ),
            """\
0xf001:  incl    %eax
0xf003:  retq
""",
        )

    def test_from_num_insns_beyond_end(self):
        self.assertEqual(
            self.disasm(
                b"\x90\xff\xc0\xc3",
                code_after=b"\x90\x90",
                mode="from",
                offset=1,
                num_insns=3,
            ),
            """\
0xf001:  incl    %eax
0xf003:  retq
0xf004:  nop
""",
        )

    def test_from_middle_of_instruction(self):
        code = b"\xf3\x0f\x1e\xfa\xc3"
        asm = """\
0xf003:  cli
0xf004:  retq
"""
        for symbol, num_insns in (
            (True, None),
            (True, 2),
            (False, 2),
        ):
            with self.subTest(symbol=symbol, num_insns=num_insns):
                self.assertEqual(
                    self.disasm(
                        code, symbol=symbol, mode="from", offset=3, num_insns=num_insns
                    ),
                    asm,
                )

    # mode="up_to"

    def test_up_to(self):
        code = b"\x90\xff\xc0\xc3\x90"
        asm = """\
0xf000:  nop
0xf001:  incl    %eax
0xf003:  retq
"""
        for num_insns in (None, 3):
            with self.subTest(num_insns=num_insns):
                self.assertEqual(
                    self.disasm(code, mode="up_to", offset=3, num_insns=num_insns), asm
                )

    def test_up_to_num_insns(self):
        self.assertEqual(
            self.disasm(b"\x90\xff\xc0\xc3\x90", mode="up_to", offset=3, num_insns=2),
            """\
0xf001:  incl    %eax
0xf003:  retq
""",
        )

    def test_up_to_middle_of_instruction(self):
        self.assertEqual(
            self.disasm(b"\x90\xff\xc0\xc3", mode="up_to", offset=2),
            """\
0xf000:  nop
0xf001:  incl    %eax
""",
        )

    # Invalid instructions

    def test_partial_instruction(self):
        self._test_1_instruction(b"\x48", "0xf000:  .byte   0x48\n")

    def test_bad_byte_between_instructions(self):
        code = b"\xeb\x01\x60\xc3"
        asm = """\
0xf000:  jmp     0xf003
0xf002:  .byte   0x60
0xf003:  retq
"""
        for symbol, kwargs in (
            (True, {}),
            (True, {"num_insns": 3}),
            (True, {"mode": "up_to", "offset": 3}),
            (True, {"mode": "up_to", "offset": 3, "num_insns": 3}),
            (False, {"num_insns": 3}),
        ):
            for code_after in (b"", b"\x90" * 16):
                with self.subTest(symbol=symbol, code_after=code_after, **kwargs):
                    self.assertEqual(
                        self.disasm(
                            code, code_after=code_after, symbol=symbol, **kwargs
                        ),
                        asm,
                    )

    # Unreadable memory

    def test_fault(self):
        for symbol in (True, False):
            for mode in (None, "symbol", "from", "up_to") if symbol else (None, "from"):
                for num_insns in (None, 1):
                    with self.subTest(symbol=symbol, mode=mode, num_insns=num_insns):
                        self.assertRaises(
                            FaultError,
                            self.disasm,
                            b"",
                            symbol=symbol,
                            symbol_size=16,
                            mode=mode,
                            num_insns=num_insns,
                        )

    def test_num_insns_unreadable(self):
        asm = """\
0xf000:  incl    %eax
0xf002:  retq
0xf003:  <unreadable>
"""
        for symbol in (True, False):
            with self.subTest(symbol=symbol):
                self.assertEqual(
                    self.disasm(b"\xff\xc0\xc3", symbol=symbol, num_insns=5), asm
                )

    def test_symbol_unreadable_sizes(self):
        for n in range(1, 32):
            with self.subTest(n=n):
                self.assertEqual(
                    self.disasm(b"\x90" * n, symbol_size=32),
                    "".join([f"{0xf000 + i:#x}:  nop\n" for i in range(n)])
                    + f"{0xf000 + n:#x}:  <unreadable>\n",
                )

    def test_up_to_unreadable_before_address(self):
        self.assertRaises(
            FaultError,
            self.disasm,
            b"\xff\xc0\xc3",
            symbol_size=0x100,
            mode="up_to",
            offset=0x20,
            num_insns=2,
        )

    # Address argument

    def test_symbol_name_outer(self):
        prog = mock_program(
            self.PLATFORM,
            segments=(MockMemorySegment(b"\x90\xff\xc0\xc3", 0xF000),),
        )

        # Looking up the address of outer finds inner instead.
        def find_symbol(prog, name, address, one):
            if name == "outer":
                return [mock_symbol("outer", 0xF000, 4)]
            elif address == 0xF000:
                return [mock_symbol("inner", 0xF000, 1)]
            else:
                return []

        prog.register_symbol_finder("mock", find_symbol, enable_index=0)
        f = io.StringIO()
        disasm(prog, "outer", file=f)
        self.assertEqual(
            f.getvalue(),
            """\
0xf000 <outer>:      nop
0xf001 <outer+0x1>:  incl    %eax
0xf003 <outer+0x3>:  retq
""",
        )

    def test_symbol_name_and_offset_in_other_symbol(self):
        prog = mock_program(
            self.PLATFORM,
            segments=(MockMemorySegment(b"\x90\xff\xc0\xc3", 0xF000),),
            symbols=(mock_symbol("foo", 0xF000, 1), mock_symbol("bar", 0xF001, 3)),
        )
        f = io.StringIO()
        disasm(prog, "foo+1", file=f)
        self.assertEqual(
            f.getvalue(),
            """\
0xf001 <bar>:      incl    %eax
0xf003 <bar+0x2>:  retq
""",
        )

    def test_function_object(self):
        prog = mock_program(
            self.PLATFORM, segments=(MockMemorySegment(b"\xc3", 0xF000),)
        )
        function_type = prog.function_type(prog.void_type(), ())
        for type_ in (function_type, prog.typedef_type("fn_t", function_type)):
            with self.subTest(type=type_):
                f = io.StringIO()
                disasm(Object(prog, type_, address=0xF000), num_insns=1, file=f)
                self.assertEqual(f.getvalue(), "0xf000:  retq\n")

    # Symbolization

    def _test_symbolize(self, code, **kwargs):
        prog = mock_program(
            self.PLATFORM,
            segments=(MockMemorySegment(code, 0xFFFFFFFF81000000),),
            symbols=(
                mock_symbol("foo", 0xFFFFFFFF81000000, len(code)),
                mock_symbol("bar", 0xFFFFFFFF81001000, 0x20),
                mock_symbol("var", 0xFFFFFFFF823B5C60, 0x40, SymbolKind.OBJECT),
                mock_symbol("low", 0x3B5C60, 0x40, SymbolKind.OBJECT),
            ),
        )
        f = io.StringIO()
        disasm(prog, "foo", file=f, **kwargs)
        return f.getvalue()

    def test_symbolize_instruction_address(self):
        code = b"\x48\xb8\x67\x69\x72\x61\x66\x66\x65\x73\xc3"
        self.assertEqual(
            self._test_symbolize(code),
            """\
0xffffffff81000000 <foo>:      movabsq $0x7365666661726967, %rax
0xffffffff8100000a <foo+0xa>:  retq
""",
        )
        self.assertEqual(
            self._test_symbolize(code, offset_base=10),
            """\
0xffffffff81000000 <foo>:     movabsq $0x7365666661726967, %rax
0xffffffff8100000a <foo+10>:  retq
""",
        )

    def test_symbolize_branch(self):
        self.assertEqual(
            self._test_symbolize(b"\xe8\xfb\x0f\x00\x00\xe9\x06\x10\x00\x00\x75\xf4"),
            """\
0xffffffff81000000 <foo>:      callq   0xffffffff81001000 <bar>
0xffffffff81000005 <foo+0x5>:  jmp     0xffffffff81001010 <bar+0x10>
0xffffffff8100000a <foo+0xa>:  jne     0xffffffff81000000 <foo>
""",
        )

    def test_symbolize_multiple_symbols(self):
        prog = mock_program(
            self.PLATFORM,
            segments=(MockMemorySegment(b"\x90" * 7, 0xF000),),
            symbols=(
                mock_symbol("foo", 0xF000, 2),
                mock_symbol("bar", 0xF002, 2),
                mock_symbol("baz", 0xF005, 2),
            ),
        )
        f = io.StringIO()
        disasm(prog, "foo", num_insns=7, file=f)
        self.assertEqual(
            f.getvalue(),
            """\
0xf000 <foo>:      nop
0xf001 <foo+0x1>:  nop
0xf002 <bar>:      nop
0xf003 <bar+0x1>:  nop
0xf004:            nop
0xf005 <baz>:      nop
0xf006 <baz+0x1>:  nop
""",
        )

    def test_symbolize_unreadable(self):
        prog = mock_program(
            self.PLATFORM,
            segments=(MockMemorySegment(b"\x90" * 2, 0xFFFE),),
            symbols=(mock_symbol("foo", 0xFFFE, 4),),
        )
        f = io.StringIO()
        disasm(prog, "foo+1", file=f)
        self.assertEqual(
            f.getvalue(),
            """\
   0xfffe <foo>:       nop
=> 0xffff <foo+0x1>:   nop
   0x10000 <foo+0x2>:  <unreadable>
""",
        )

    def test_symbolize_absolute(self):
        self.assertEqual(
            self._test_symbolize(b"\x48\x03\x14\xc5\x60\x5c\x3b\x82"),
            "0xffffffff81000000 <foo>:  addq    -0x7dc4a3a0(, %rax, 8), %rdx <var>\n",
        )

    def test_symbolize_multiple_operands(self):
        self.assertEqual(
            self._test_symbolize(b"\x48\xc7\x05\xf5\x0f\x00\x00\x60\x5c\x3b\x00"),
            "0xffffffff81000000 <foo>:  movq    $0x3b5c60, 0xff5(%rip) <low> <bar>\n",
        )

    def test_symbolize_not_found(self):
        self.assertEqual(
            self._test_symbolize(
                b"\x48\x83\xec\x28\x65\x48\x8b\x04\x25\x28\x00\x00\x00\x60"
            ),
            """\
0xffffffff81000000 <foo>:      subq    $0x28, %rsp
0xffffffff81000004 <foo+0x4>:  movq    %gs:0x28, %rax
0xffffffff8100000d <foo+0xd>:  .byte   0x60
""",
        )
