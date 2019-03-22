import itertools
import os.path
import unittest

from tests.libdrgn import PathIterator, normalized_path_eq


# normpath("//") returns "//". See https://bugs.python.org/issue26329.
def my_normpath(path):
    path = os.path.normpath(path)
    if path[:2] == '//':
        return path[1:]
    else:
        return path


class TestPathIterator(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(list(PathIterator('')), [])

    def test_simple(self):
        self.assertEqual(list(PathIterator('a')), ['a'])
        self.assertEqual(list(PathIterator('abc/def')), ['def', 'abc'])

    def test_root(self):
        self.assertEqual(list(PathIterator('/')), [''])

    def test_absolute(self):
        self.assertEqual(list(PathIterator('/root')), ['root', ''])
        self.assertEqual(list(PathIterator('/home/user')), ['user', 'home', ''])

    def test_redundant_slash(self):
        self.assertEqual(list(PathIterator('a/')), ['a'])
        self.assertEqual(list(PathIterator('a//')), ['a'])
        self.assertEqual(list(PathIterator('//')), [''])
        self.assertEqual(list(PathIterator('//a')), ['a', ''])
        self.assertEqual(list(PathIterator('///a')), ['a', ''])

    def test_dot(self):
        self.assertEqual(list(PathIterator('a/.')), ['a'])
        self.assertEqual(list(PathIterator('a/./')), ['a'])
        self.assertEqual(list(PathIterator('./a')), ['a'])
        self.assertEqual(list(PathIterator('./a/./')), ['a'])

    def test_dot_dot(self):
        self.assertEqual(list(PathIterator('a/b/..')), ['a'])
        self.assertEqual(list(PathIterator('a/../b')), ['b'])

    def test_dot_dot_above_current_directory(self):
        self.assertEqual(list(PathIterator('../one/two')), ['two', 'one', '..'])
        self.assertEqual(list(PathIterator('one/../../two')), ['two', '..'])
        self.assertEqual(list(PathIterator('one/two/../../..')), ['..'])

    def test_dot_dot_above_root(self):
        self.assertEqual(list(PathIterator('/../one/two')), ['two', 'one', ''])
        self.assertEqual(list(PathIterator('/one/../../two')), ['two', ''])
        self.assertEqual(list(PathIterator('/one/two/../../..')), [''])

    def test_current_directory(self):
        self.assertEqual(list(PathIterator('.')), [])
        self.assertEqual(list(PathIterator('./')), [])
        self.assertEqual(list(PathIterator('./.')), [])
        self.assertEqual(list(PathIterator('foo/..')), [])
        self.assertEqual(list(PathIterator('a/b/../..')), [])

    def test_normalized_path_eq(self):
        paths = [
            'a', 'abc/def', '/', '/root', '/home/user', 'a/', 'a//', '//',
            '//a', '///a', 'a/.', 'a/./', './a', './a/./', 'a/b/..', 'a/../b',
            '../one/two', 'one/../../two', 'one/two/../../..', '/../one/two',
            '/one/../../two', '/one/two/../../..', '.', './', './.', 'foo/..',
            'a/b/../..',
        ]
        for a, b in itertools.product(paths, paths):
            with self.subTest(a=a, b=b):
                self.assertEqual(normalized_path_eq(a, b),
                                 my_normpath(a) == my_normpath(b))
