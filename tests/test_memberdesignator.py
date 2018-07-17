import unittest

from drgn.internal.memberdesignator import parse_member_designator


class TestParseMemberDesignator(unittest.TestCase):
    def test_member(self):
        self.assertEqual(parse_member_designator('foo'), [('.', 'foo')])

    def test_multiple_members(self):
        self.assertEqual(parse_member_designator('foo.bar'),
                         [('.', 'foo'), ('.', 'bar')])
        self.assertEqual(parse_member_designator('foo.bar.baz'),
                         [('.', 'foo'), ('.', 'bar'), ('.', 'baz')])

    def test_subscript(self):
        self.assertEqual(parse_member_designator('foo[0]'),
                         [('.', 'foo'), ('[]', 0)])

    def test_subscript_member(self):
        self.assertEqual(parse_member_designator('foo[0].bar'),
                         [('.', 'foo'), ('[]', 0), ('.', 'bar')])

    def test_blank(self):
        self.assertRaisesRegex(ValueError, r'^expected identifier$',
                               parse_member_designator, '')

    def test_start_number(self):
        self.assertRaisesRegex(ValueError, r'^expected identifier$',
                               parse_member_designator, '3')

    def test_trailing_dot(self):
        self.assertRaisesRegex(ValueError, r"^expected identifier after '\.'$",
                               parse_member_designator, 'foo.')

    def test_double_dot(self):
        self.assertRaisesRegex(ValueError, r"^expected identifier after '\.'$",
                               parse_member_designator, 'foo..')

    def test_trailing_lbracket(self):
        self.assertRaisesRegex(ValueError, r"^expected number after '\['$",
                               parse_member_designator, 'foo[')

    def test_no_subscript(self):
        self.assertRaisesRegex(ValueError, r"^expected number after '\['$",
                               parse_member_designator, 'foo[]')

    def test_extra_rbracket(self):
        self.assertRaisesRegex(ValueError, r"^expected '\.' or '\[' after identifier$",
                               parse_member_designator, 'foo]')

    def test_double_rbracket(self):
        self.assertRaisesRegex(ValueError, r"^expected '\.' or '\[' after ']'$",
                               parse_member_designator, 'foo[0]]')

    def test_missing_rbracket(self):
        self.assertRaisesRegex(ValueError, r"^expected ']' after number$",
                               parse_member_designator, 'foo[0')
