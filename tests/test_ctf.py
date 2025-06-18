# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
import math
from typing import List, Optional
from unittest import SkipTest

from _drgn import _linux_helper_load_ctf
from drgn import Program, Symbol, SymbolBinding, SymbolKind, TypeKind
from tests import TestCase
from tests.resources import get_resource

TYPEDEF_TYPEDEF = {
    "u64": "__u64",
    "u32": "__u32",
    "u16": "__u16",
    "u8": "__u8",
}

TYPEDEF_INTEGER = {
    "__u64": "unsigned long",
    "__u32": "unsigned int",
    "__u16": "unsigned short",
    "__u8": "unsigned char",
    "ulong_t": "unsigned long",
}

ENUMERATOR_VALUES = {
    "CONST_ONE": 1,
    "CONST_TWO": 2,
    "CONST_THREE": 3,
}


def fake_symbol_finder(
    prog: Program, name: Optional[str], address: Optional[str], one: bool
) -> List[Symbol]:
    if one and name is not None:
        return [Symbol(name, 0, 0, SymbolBinding.GLOBAL, SymbolKind.OBJECT)]
    return []


class TestTypes(object):
    def test_typedef_to_typedef(self):
        for src, dst in TYPEDEF_TYPEDEF.items():
            typ = self.prog.type(src)
            self.assertIs(typ.kind, TypeKind.TYPEDEF)
            self.assertIs(typ.type.kind, TypeKind.TYPEDEF)
            self.assertEqual(typ.name, src)
            self.assertEqual(typ.type.name, dst)

    def test_typedef_to_integer(self):
        for src, dst in TYPEDEF_INTEGER.items():
            typ = self.prog.type(src)
            self.assertIs(typ.kind, TypeKind.TYPEDEF)
            self.assertIs(typ.type.kind, TypeKind.INT)
            self.assertEqual(typ.name, src)
            self.assertEqual(typ.type.name, dst)

    def test_basic_struct(self):
        typ = self.prog.type("struct basic_struct")

        m = typ.member("member_int")
        self.assertEqual(m.type.kind, TypeKind.INT)
        self.assertEqual(m.bit_offset, 0)

        m = typ.member("member_ptr")
        self.assertEqual(m.type.kind, TypeKind.POINTER)
        self.assertEqual(m.type.type.kind, TypeKind.INT)
        self.assertEqual(m.type.type.name, "char")
        self.assertEqual(m.bit_offset, 64)  # padded

        m = typ.member("member_vptr")
        self.assertEqual(m.type.kind, TypeKind.POINTER)
        self.assertEqual(m.type.type.kind, TypeKind.VOID)
        self.assertEqual(m.bit_offset, 128)

        m = typ.member("name")
        self.assertEqual(m.type.kind, TypeKind.ARRAY)
        self.assertEqual(m.type.length, 16)
        self.assertEqual(m.type.type.kind, TypeKind.INT)
        self.assertEqual(m.type.type.name, "char")

    def test_bitfield(self):
        fields = [
            # member name, bit offset, bit size, underlying byte size
            ("sixteen", 0, 16, 8),
            ("eight", 16, 8, 8),
            ("four", 24, 4, 8),
            ("one", 28, 1, 8),
            ("rem", 29, 35, 8),
            ("sixteen_td", 64, 16, 8),
            ("eight_td", 80, 8, 8),
            ("four_td", 88, 4, 8),
            ("one_td", 92, 1, 8),
            ("rem_td", 93, 35, 8),
            ("not_a_bitfield", 128, None, 4),
        ]
        typ = self.prog.type("struct bitfield")
        for name, bit_offset, bit_field_size, byte_size in fields:
            m = typ.member(name)
            self.assertEqual(m.bit_offset, bit_offset, name)
            self.assertEqual(m.bit_field_size, bit_field_size, name)

            if bit_field_size is not None and self.kind == "CTF (dwarf2ctf)":
                # Known CTF data issue for dwarf2ctf: the underlying integer
                # types don't have the correct size, instead they use the
                # smallest power of 2 number of bytes that would fit the bit
                # size.
                bytes = math.ceil(bit_field_size / 8)
                pow2 = math.ceil(math.log2(bytes))
                byte_size = 2**pow2

            if m.type.kind == TypeKind.TYPEDEF:
                # 2 layer typedef
                self.assertEqual(m.type.type.type.size, byte_size, name)
            else:
                self.assertEqual(m.type.size, byte_size, name)

    def test_enum(self):
        typ = self.prog.type("enum constants")
        enumerators = list(typ.enumerators)
        self.assertEqual(len(enumerators), len(ENUMERATOR_VALUES))
        for enumerator in enumerators:
            name = enumerator[0]
            self.assertIn(name, ENUMERATOR_VALUES, name)
            self.assertEqual(enumerator[1], ENUMERATOR_VALUES[name], name)

    def test_enum_lookup(self):
        for name, val in ENUMERATOR_VALUES.items():
            obj = self.prog.constant(name)
            self.assertEqual(obj.value_(), val, name)
            self.assertEqual(obj.type_.type_name(), "enum constants", name)

    def test_multidim_arr(self):
        obj = self.prog["multidim"]
        self.assertEqual(obj.type_.kind, TypeKind.ARRAY)

        if self.kind == "CTF (dwarf2ctf)":
            # Known data issue with dwarf2ctf: multidimensional arrays are
            # broken. They are represented as a single dimensional array, whose
            # length is the last dimension of the real array type.
            self.assertEqual(obj.type_.length, 5)
            self.assertEqual(obj.type_.type.kind, TypeKind.INT)
        else:
            # CTF (GCC) is represented backwards. This is a bug, but our
            # implementation can detect it and correct for it.
            # DWARF is correct
            self.assertEqual(obj.type_.length, 3)
            self.assertEqual(obj.type_.type.kind, TypeKind.ARRAY)
            self.assertEqual(obj.type_.type.length, 4)
            self.assertEqual(obj.type_.type.type.kind, TypeKind.ARRAY)
            self.assertEqual(obj.type_.type.type.length, 5)
            self.assertEqual(obj.type_.type.type.type.kind, TypeKind.INT)

    def test_simple_flex_array(self):
        typ = self.prog.type("struct simple_flex_array")
        dtype = typ.member("data").type
        self.assertEqual(dtype.kind, TypeKind.ARRAY)
        self.assertEqual(dtype.length, 0)
        self.assertTrue(dtype.is_complete())
        self.assertEqual(dtype.type.kind, TypeKind.INT)

    def test_blank_flex_array(self):
        typ = self.prog.type("struct blank_flex_array")
        dtype = typ.member("data").type
        self.assertEqual(dtype.kind, TypeKind.ARRAY)
        if self.kind.startswith("CTF"):
            # Known difference in CTF encodings compared to DWARF: CTF always
            # represents an array with a blank index at the end of an array as a
            # zero-length array type, rather than an incomplete array type.
            self.assertEqual(dtype.length, 0)
            self.assertTrue(dtype.is_complete())
        else:
            self.assertEqual(dtype.length, None)
            self.assertFalse(dtype.is_complete())
        self.assertEqual(dtype.type.kind, TypeKind.INT)

    def test_multidim_flex_array(self):
        typ = self.prog.type("struct multidim_flex_array")
        dtype = typ.member("data").type
        self.assertEqual(dtype.kind, TypeKind.ARRAY)
        if self.kind == "CTF (dwarf2ctf)":
            # Again, known issue with dwarf2ctf, multidimensional arrays are
            # represented as a single dimension with size equal to the last
            # dimension's size.
            self.assertEqual(dtype.length, 16)
        else:
            self.assertEqual(dtype.length, 0)
            self.assertEqual(dtype.type.kind, TypeKind.ARRAY)
            self.assertEqual(dtype.type.length, 16)
            self.assertEqual(dtype.type.type.kind, TypeKind.INT)

    def test_function_noarg(self):
        if self.kind == "CTF (dwarf2ctf)":
            # Known issue: dwarf2ctf does not contain function data, but it
            # does contain data on function pointers!
            # Further issue: dwarf2ctf represents all function pointers as
            # "int (*)(void)", which is totally useless. Don't bother testing
            # this.
            return
        names = ("function_voidarg", "function_noarg", "fptr_voidarg", "fptr_noarg")
        for funcname in names:
            func = self.prog[funcname].type_
            if funcname.startswith("fptr_"):
                self.assertEqual(func.kind, TypeKind.POINTER, funcname)
                func = func.type
            self.assertEqual(func.type.kind, TypeKind.VOID, funcname)
            self.assertEqual(len(func.parameters), 0, funcname)
            if funcname != "fptr_noarg":
                # fptr_noarg is represented as variadic
                self.assertFalse(func.is_variadic, funcname)

    def test_function_onearg(self):
        if self.kind == "CTF (dwarf2ctf)":
            # Known issues: see above
            return
        for funcname in ("function_onearg", "fptr_onearg"):
            func = self.prog[funcname].type_
            if funcname.startswith("fptr_"):
                self.assertEqual(func.kind, TypeKind.POINTER, funcname)
                func = func.type
            self.assertEqual(func.type.kind, TypeKind.INT)
            self.assertEqual(func.type.type_name(), "int")
            self.assertEqual(len(func.parameters), 1)
            self.assertFalse(func.is_variadic)
            self.assertEqual(func.parameters[0].type.kind, TypeKind.INT)
            self.assertEqual(func.parameters[0].type.type_name(), "int")
            if self.kind == "DWARF" and not funcname.startswith("fptr_"):
                self.assertEqual(func.parameters[0].name, "foo")
            else:
                # Known difference: CTF does not encode parameter names
                self.assertEqual(func.parameters[0].name, None)

    def test_function_vararg(self):
        if self.kind == "CTF (dwarf2ctf)":
            # Known issues: see above
            return
        for funcname in ("function_vararg", "fptr_vararg"):
            func = self.prog.function("function_varargs").type_
            self.assertEqual(func.type.kind, TypeKind.INT)
            self.assertEqual(func.type.type_name(), "int")
            self.assertEqual(len(func.parameters), 1)
            self.assertTrue(func.is_variadic)
            self.assertEqual(func.parameters[0].type.kind, TypeKind.POINTER)
            self.assertEqual(func.parameters[0].type.type_name(), "char *")
            if self.kind == "DWARF":
                # Strangely, DWARF includes the parameter name here, but not for
                # fptr_onearg()?
                self.assertEqual(func.parameters[0].name, "format")
            else:
                # Known difference: CTF does not encode parameter names
                self.assertEqual(func.parameters[0].name, None)


class TestDwarf(TestTypes, TestCase):
    kind = "DWARF"

    @classmethod
    def setUpClass(cls):
        cls.prog = Program()
        cls.prog.set_core_dump(get_resource("core"))
        cls.prog.load_debug_info([get_resource("test")])


class TestCtf(TestTypes, TestCase):
    kind = "CTF (GCC)"

    @classmethod
    def setUpClass(cls):
        cls.prog = Program()
        cls.prog.set_core_dump(get_resource("core"))
        try:
            _linux_helper_load_ctf(cls.prog, str(get_resource("test.ctf")))
        except NotImplementedError:
            raise SkipTest("Drgn is not built with CTF enabled")
        # fake symbol finder so that we can lookup variable types, despite not
        # having a symbol table
        cls.prog.register_symbol_finder("test", fake_symbol_finder, enable_index=0)


class TestDwarf2Ctf(TestTypes, TestCase):
    kind = "CTF (dwarf2ctf)"

    @classmethod
    def setUpClass(cls):
        cls.prog = Program()
        cls.prog.set_core_dump(get_resource("core"))
        try:
            _linux_helper_load_ctf(cls.prog, str(get_resource("test.dwarf2ctf")))
        except NotImplementedError:
            raise SkipTest("Drgn is not built with CTF enabled")
        # fake symbol finder so that we can lookup variable types, despite not
        # having a symbol table
        cls.prog.register_symbol_finder("test", fake_symbol_finder, enable_index=0)
