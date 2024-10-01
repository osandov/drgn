# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import Language, Qualifiers, TypeEnumerator, TypeMember
from tests import MockProgramTestCase


class TestFormatTypeName(MockProgramTestCase):
    def setUp(self):
        super().setUp()
        self.prog.language = Language.CPP

    def test_tagged(self):
        for keyword in ("struct", "union", "class"):
            with self.subTest(keyword=keyword):
                constructor = getattr(self.prog, keyword + "_type")
                self.assertEqual(
                    constructor(
                        "foo",
                        4,
                        (TypeMember(self.prog.int_type("int", 4, True), "foo", 0),),
                    ).type_name(),
                    "foo",
                )
        with self.subTest(keyword="enum"):
            self.assertEqual(
                self.prog.enum_type(
                    "foo",
                    self.prog.int_type("int", 4, True),
                    (TypeEnumerator("FOO", 1),),
                ).type_name(),
                "foo",
            )

    def test_qualified_tagged(self):
        for keyword in ("struct", "union", "class"):
            with self.subTest(keyword=keyword):
                constructor = getattr(self.prog, keyword + "_type")
                self.assertEqual(
                    constructor(
                        "foo",
                        4,
                        (TypeMember(self.prog.int_type("int", 4, True), "foo", 0),),
                        qualifiers=Qualifiers.CONST,
                    ).type_name(),
                    "const foo",
                )
        with self.subTest(keyword="enum"):
            self.assertEqual(
                self.prog.enum_type(
                    "foo",
                    self.prog.int_type("int", 4, True),
                    (TypeEnumerator("FOO", 1),),
                    qualifiers=Qualifiers.CONST,
                ).type_name(),
                "const foo",
            )

    def test_anonymous_tagged(self):
        for keyword in ("struct", "union", "class"):
            with self.subTest(keyword=keyword):
                constructor = getattr(self.prog, keyword + "_type")
                self.assertEqual(
                    constructor(
                        None,
                        4,
                        (TypeMember(self.prog.int_type("int", 4, True), "foo", 0),),
                    ).type_name(),
                    keyword + " <anonymous>",
                )
        with self.subTest(keyword="enum"):
            self.assertEqual(
                self.prog.enum_type(
                    None,
                    self.prog.int_type("int", 4, True),
                    (TypeEnumerator("FOO", 1),),
                ).type_name(),
                "enum <anonymous>",
            )

    def test_qualified_anonymous_tagged(self):
        for keyword in ("struct", "union", "class"):
            with self.subTest(keyword=keyword):
                constructor = getattr(self.prog, keyword + "_type")
                self.assertEqual(
                    constructor(
                        None,
                        4,
                        (TypeMember(self.prog.int_type("int", 4, True), "foo", 0),),
                        qualifiers=Qualifiers.CONST,
                    ).type_name(),
                    "const " + keyword + " <anonymous>",
                )
        with self.subTest(keyword="enum"):
            self.assertEqual(
                self.prog.enum_type(
                    None,
                    self.prog.int_type("int", 4, True),
                    (TypeEnumerator("FOO", 1),),
                    qualifiers=Qualifiers.CONST,
                ).type_name(),
                "const enum <anonymous>",
            )


class TestFormatType(MockProgramTestCase):
    def setUp(self):
        super().setUp()
        self.prog.language = Language.CPP

    def test_tagged(self):
        for keyword in ("struct", "union", "class"):
            with self.subTest(keyword=keyword):
                constructor = getattr(self.prog, keyword + "_type")
                self.assertEqual(
                    str(
                        constructor(
                            "foo",
                            4,
                            (TypeMember(self.prog.int_type("int", 4, True), "foo", 0),),
                        )
                    ),
                    f"""\
{keyword} foo {{
	int foo;
}}""",
                )
        with self.subTest(keyword="enum"):
            self.assertEqual(
                str(
                    self.prog.enum_type(
                        "foo",
                        self.prog.int_type("int", 4, True),
                        (TypeEnumerator("FOO", 1),),
                    )
                ),
                """\
enum foo {
	FOO = 1,
}""",
            )

    def test_anonymous_tagged(self):
        for keyword in ("struct", "union", "class"):
            with self.subTest(keyword=keyword):
                constructor = getattr(self.prog, keyword + "_type")
                self.assertEqual(
                    str(
                        constructor(
                            None,
                            4,
                            (TypeMember(self.prog.int_type("int", 4, True), "foo", 0),),
                        )
                    ),
                    f"""\
{keyword} {{
	int foo;
}}""",
                )
        with self.subTest(keyword="enum"):
            self.assertEqual(
                str(
                    self.prog.enum_type(
                        None,
                        self.prog.int_type("int", 4, True),
                        (TypeEnumerator("FOO", 1),),
                    )
                ),
                """\
enum {
	FOO = 1,
}""",
            )
