# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import TypeKind, TypeKindSet
from tests import TestCase


class TestTypeKindSet(TestCase):
    def test_repr(self):
        self.assertEqual(
            repr(TypeKindSet()),
            "TypeKindSet()",
        )
        self.assertEqual(
            repr(TypeKindSet({TypeKind.STRUCT})),
            "TypeKindSet({TypeKind.STRUCT})",
        )
        self.assertEqual(
            repr(TypeKindSet({TypeKind.STRUCT, TypeKind.CLASS})),
            "TypeKindSet({TypeKind.STRUCT, TypeKind.CLASS})",
        )

    def test_len(self):
        self.assertEqual(len(TypeKindSet()), 0)
        self.assertEqual(len(TypeKindSet({TypeKind.STRUCT})), 1)
        self.assertEqual(len(TypeKindSet({TypeKind.INT, TypeKind.STRUCT})), 2)

    def test_in(self):
        self.assertNotIn(TypeKind.INT, TypeKindSet())
        self.assertIn(TypeKind.INT, TypeKindSet({TypeKind.INT}))
        self.assertIn(TypeKind.INT, TypeKindSet({TypeKind.INT, TypeKind.STRUCT}))
        self.assertIn(TypeKind.STRUCT, TypeKindSet({TypeKind.INT, TypeKind.STRUCT}))
        self.assertNotIn(TypeKind.UNION, TypeKindSet({TypeKind.INT, TypeKind.STRUCT}))
        self.assertNotIn(0, TypeKindSet({TypeKind.INT}))
        self.assertNotIn(TypeKind.INT.value, TypeKindSet({TypeKind.INT}))

    def test_iter(self):
        for s in (
            set(),
            {TypeKind.VOID},
            {TypeKind.ARRAY, TypeKind.POINTER},
        ):
            self.assertEqual(set(TypeKindSet(s)), s)

    def test_eq(self):
        self.assertTrue(TypeKindSet() == TypeKindSet())
        self.assertFalse(TypeKindSet() == TypeKindSet({TypeKind.BOOL}))
        self.assertTrue(TypeKindSet({TypeKind.FLOAT}) == TypeKindSet({TypeKind.FLOAT}))
        self.assertFalse(
            TypeKindSet({TypeKind.FUNCTION}) == TypeKindSet({TypeKind.BOOL})
        )
        self.assertTrue(
            TypeKindSet({TypeKind.FLOAT, TypeKind.TYPEDEF})
            == TypeKindSet({TypeKind.FLOAT, TypeKind.TYPEDEF})
        )
        self.assertFalse(
            TypeKindSet({TypeKind.BOOL, TypeKind.FUNCTION})
            == TypeKindSet({TypeKind.BOOL, TypeKind.ARRAY}),
        )
        self.assertTrue(
            TypeKindSet({TypeKind.FLOAT, TypeKind.TYPEDEF})
            == {TypeKind.FLOAT, TypeKind.TYPEDEF}
        )
        self.assertFalse(TypeKindSet() == {"asdf"})
        self.assertFalse(
            TypeKindSet({TypeKind.FLOAT, TypeKind.TYPEDEF})
            == {TypeKind.FLOAT, TypeKind.TYPEDEF, "foo"}
        )
        self.assertFalse(
            TypeKindSet({TypeKind.FLOAT, TypeKind.TYPEDEF})
            == [TypeKind.FLOAT, TypeKind.TYPEDEF]
        )

    def test_ne(self):
        self.assertFalse(TypeKindSet() != TypeKindSet())
        self.assertTrue(TypeKindSet() != TypeKindSet({TypeKind.BOOL}))
        self.assertFalse(TypeKindSet({TypeKind.FLOAT}) != TypeKindSet({TypeKind.FLOAT}))
        self.assertTrue(
            TypeKindSet({TypeKind.FUNCTION}) != TypeKindSet({TypeKind.BOOL})
        )
        self.assertFalse(
            TypeKindSet({TypeKind.FLOAT, TypeKind.TYPEDEF})
            != TypeKindSet({TypeKind.FLOAT, TypeKind.TYPEDEF})
        )
        self.assertTrue(
            TypeKindSet({TypeKind.BOOL, TypeKind.FUNCTION})
            != TypeKindSet({TypeKind.BOOL, TypeKind.ARRAY}),
        )
        self.assertFalse(
            TypeKindSet({TypeKind.FLOAT, TypeKind.TYPEDEF})
            != {TypeKind.FLOAT, TypeKind.TYPEDEF}
        )
        self.assertTrue(TypeKindSet() != {"asdf"})
        self.assertTrue(
            TypeKindSet({TypeKind.FLOAT, TypeKind.TYPEDEF})
            != {TypeKind.FLOAT, TypeKind.TYPEDEF, "foo"}
        )
        self.assertTrue(
            TypeKindSet({TypeKind.FLOAT, TypeKind.TYPEDEF})
            != [TypeKind.FLOAT, TypeKind.TYPEDEF]
        )

    def test_lt(self):
        self.assertFalse(TypeKindSet() < TypeKindSet())
        self.assertTrue(TypeKindSet() < TypeKindSet({TypeKind.BOOL}))
        self.assertFalse(TypeKindSet({TypeKind.BOOL}) < TypeKindSet())
        self.assertFalse(TypeKindSet({TypeKind.BOOL}) < TypeKindSet({TypeKind.BOOL}))
        self.assertTrue(
            TypeKindSet({TypeKind.BOOL}) < TypeKindSet({TypeKind.BOOL, TypeKind.FLOAT})
        )
        self.assertFalse(
            TypeKindSet({TypeKind.BOOL, TypeKind.FLOAT}) < TypeKindSet({TypeKind.BOOL})
        )
        self.assertFalse(TypeKindSet({TypeKind.INT}) < TypeKindSet({TypeKind.BOOL}))
        self.assertTrue(
            TypeKindSet({TypeKind.BOOL}) < {TypeKind.BOOL, TypeKind.FLOAT, "foo"}
        )
        with self.assertRaises(TypeError):
            TypeKindSet({TypeKind.BOOL}) < [TypeKind.BOOL, TypeKind.FLOAT]

    def test_gt(self):
        self.assertFalse(TypeKindSet() > TypeKindSet())
        self.assertFalse(TypeKindSet() > TypeKindSet({TypeKind.BOOL}))
        self.assertTrue(TypeKindSet({TypeKind.BOOL}) > TypeKindSet())
        self.assertFalse(TypeKindSet({TypeKind.BOOL}) > TypeKindSet({TypeKind.BOOL}))
        self.assertFalse(
            TypeKindSet({TypeKind.BOOL}) > TypeKindSet({TypeKind.BOOL, TypeKind.FLOAT})
        )
        self.assertTrue(
            TypeKindSet({TypeKind.BOOL, TypeKind.FLOAT}) > TypeKindSet({TypeKind.BOOL})
        )
        self.assertFalse(TypeKindSet({TypeKind.INT}) > TypeKindSet({TypeKind.BOOL}))
        self.assertFalse(
            TypeKindSet({TypeKind.BOOL, TypeKind.FLOAT}) > {TypeKind.BOOL, "foo"}
        )
        with self.assertRaises(TypeError):
            TypeKindSet({TypeKind.BOOL}) > []

    def test_le(self):
        self.assertTrue(TypeKindSet() <= TypeKindSet())
        self.assertTrue(TypeKindSet() <= TypeKindSet({TypeKind.BOOL}))
        self.assertFalse(TypeKindSet({TypeKind.BOOL}) <= TypeKindSet())
        self.assertTrue(TypeKindSet({TypeKind.BOOL}) <= TypeKindSet({TypeKind.BOOL}))
        self.assertTrue(
            TypeKindSet({TypeKind.BOOL}) <= TypeKindSet({TypeKind.BOOL, TypeKind.FLOAT})
        )
        self.assertFalse(
            TypeKindSet({TypeKind.BOOL, TypeKind.FLOAT}) <= TypeKindSet({TypeKind.BOOL})
        )
        self.assertFalse(TypeKindSet({TypeKind.INT}) <= TypeKindSet({TypeKind.BOOL}))
        self.assertTrue(TypeKindSet({TypeKind.BOOL}) <= {TypeKind.BOOL, "foo"})
        with self.assertRaises(TypeError):
            TypeKindSet({TypeKind.BOOL}) <= [TypeKind.BOOL, TypeKind.FLOAT]

    def test_ge(self):
        self.assertTrue(TypeKindSet() >= TypeKindSet())
        self.assertFalse(TypeKindSet() >= TypeKindSet({TypeKind.BOOL}))
        self.assertTrue(TypeKindSet({TypeKind.BOOL}) >= TypeKindSet())
        self.assertTrue(TypeKindSet({TypeKind.BOOL}) >= TypeKindSet({TypeKind.BOOL}))
        self.assertFalse(
            TypeKindSet({TypeKind.BOOL}) >= TypeKindSet({TypeKind.BOOL, TypeKind.FLOAT})
        )
        self.assertTrue(
            TypeKindSet({TypeKind.BOOL, TypeKind.FLOAT}) >= TypeKindSet({TypeKind.BOOL})
        )
        self.assertFalse(TypeKindSet({TypeKind.INT}) >= TypeKindSet({TypeKind.BOOL}))
        self.assertFalse(TypeKindSet({TypeKind.BOOL}) >= {TypeKind.BOOL, "foo"})
        with self.assertRaises(TypeError):
            TypeKindSet({TypeKind.BOOL}) >= [TypeKind.BOOL]

    def test_isdisjoint(self):
        self.assertTrue(TypeKindSet().isdisjoint(TypeKindSet()))
        self.assertTrue(
            TypeKindSet({TypeKind.POINTER}).isdisjoint(TypeKindSet({TypeKind.ARRAY}))
        )
        self.assertFalse(
            TypeKindSet({TypeKind.POINTER}).isdisjoint(TypeKindSet({TypeKind.POINTER}))
        )
        self.assertFalse(
            TypeKindSet({TypeKind.ARRAY}).isdisjoint(
                TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY})
            )
        )
        self.assertFalse(
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}).isdisjoint(
                TypeKindSet({TypeKind.ARRAY})
            )
        )
        self.assertTrue(TypeKindSet({TypeKind.POINTER}).isdisjoint({TypeKind.ARRAY}))
        self.assertTrue(TypeKindSet({TypeKind.POINTER}).isdisjoint([TypeKind.ARRAY]))
        self.assertFalse(TypeKindSet({TypeKind.POINTER}).isdisjoint({TypeKind.POINTER}))
        self.assertFalse(TypeKindSet({TypeKind.POINTER}).isdisjoint([TypeKind.POINTER]))

    def test_sub(self):
        self.assertEqual(TypeKindSet() - TypeKindSet(), TypeKindSet())
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER}) - TypeKindSet({TypeKind.ARRAY}),
            TypeKindSet({TypeKind.POINTER}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER}) - TypeKindSet({TypeKind.POINTER}),
            TypeKindSet(),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.ARRAY})
            - TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}),
            TypeKindSet(),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY})
            - TypeKindSet({TypeKind.ARRAY}),
            TypeKindSet({TypeKind.POINTER}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}) - {TypeKind.ARRAY},
            TypeKindSet({TypeKind.POINTER}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}) - {TypeKind.ARRAY, "asdf"},
            TypeKindSet({TypeKind.POINTER}),
        )

    def test_and(self):
        self.assertEqual(TypeKindSet() & TypeKindSet(), TypeKindSet())
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER}) & TypeKindSet({TypeKind.ARRAY}),
            TypeKindSet(),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER}) & TypeKindSet({TypeKind.POINTER}),
            TypeKindSet({TypeKind.POINTER}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.ARRAY})
            & TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}),
            TypeKindSet({TypeKind.ARRAY}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY})
            & TypeKindSet({TypeKind.ARRAY}),
            TypeKindSet({TypeKind.ARRAY}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}) & {TypeKind.ARRAY},
            TypeKindSet({TypeKind.ARRAY}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY})
            & {TypeKind.POINTER, "asdf"},
            TypeKindSet({TypeKind.POINTER}),
        )

    def test_xor(self):
        self.assertEqual(TypeKindSet() ^ TypeKindSet(), TypeKindSet())
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER}) ^ TypeKindSet({TypeKind.ARRAY}),
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER}) ^ TypeKindSet({TypeKind.POINTER}),
            TypeKindSet(),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.ARRAY})
            ^ TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}),
            TypeKindSet({TypeKind.POINTER}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY})
            ^ TypeKindSet({TypeKind.ARRAY}),
            TypeKindSet({TypeKind.POINTER}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}) ^ {TypeKind.ARRAY},
            TypeKindSet({TypeKind.POINTER}),
        )
        with self.assertRaises(TypeError):
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}) ^ {TypeKind.ARRAY, "asdf"}

    def test_or(self):
        self.assertEqual(TypeKindSet() | TypeKindSet(), TypeKindSet())
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER}) | TypeKindSet({TypeKind.ARRAY}),
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER}) | TypeKindSet({TypeKind.POINTER}),
            TypeKindSet({TypeKind.POINTER}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.ARRAY})
            | TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}),
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY})
            | TypeKindSet({TypeKind.ARRAY}),
            TypeKindSet({TypeKind.POINTER, TypeKind.ARRAY}),
        )
        self.assertEqual(
            TypeKindSet({TypeKind.POINTER}) | {TypeKind.ARRAY},
            {TypeKind.POINTER, TypeKind.ARRAY},
        )
        with self.assertRaises(TypeError):
            TypeKindSet({TypeKind.POINTER}) | {TypeKind.ARRAY, "asdf"}

    def test_all_kinds(self):
        self.assertEqual(set(TypeKindSet(TypeKind)), set(TypeKind))
