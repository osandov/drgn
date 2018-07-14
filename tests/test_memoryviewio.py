import unittest

from drgn.internal.memoryviewio import MemoryViewIO


class TestCoreReader(unittest.TestCase):
    def test_empty(self):
        f = MemoryViewIO(memoryview(b''))
        self.assertEqual(f.read(4), b'')
        self.assertEqual(f.tell(), 0)

    def test_read(self):
        f = MemoryViewIO(memoryview(b'hello, world!'))
        self.assertEqual(f.read(5), b'hello')
        self.assertEqual(f.read(5), b', wor')
        self.assertEqual(f.read(100), b'ld!')

    def test_seek(self):
        f = MemoryViewIO(memoryview(b'hello, world!'))
        self.assertEqual(f.seek(7), 7)
        self.assertEqual(f.read(5), b'world')
        self.assertEqual(f.seek(0, whence=1), 12)

        self.assertEqual(f.seek(-8, whence=1), 4)
        self.assertEqual(f.read(3), b'o, ')

        self.assertEqual(f.seek(-3, whence=2), 10)
        self.assertEqual(f.read(4), b'ld!')

    def test_close(self):
        f = MemoryViewIO(memoryview(b'hello, world!'))
        f.close()
        self.assertTrue(f.closed)
