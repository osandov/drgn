import contextlib
import tempfile
import unittest

from drgn.internal.corereader import CoreReader


@contextlib.contextmanager
def tmpfile(data):
    file = tempfile.TemporaryFile()
    try:
        file.write(data)
        file.flush()
        yield file
    finally:
        file.close()


class TestCoreReader(unittest.TestCase):
    def test_bad_segments(self):
        with tmpfile(b'') as file:
            self.assertRaises(TypeError, CoreReader, file, 0)
            self.assertRaises(TypeError, CoreReader, file, [0])
            self.assertRaises(ValueError, CoreReader, file, [()])
            self.assertRaises(OverflowError, CoreReader, file,
                              [(2**64, 0, 0, 0, 0)])

    def test_simple_read(self):
        data = b'hello, world!'
        segments = [(0, 0xffff0000, 0x0, len(data), len(data))]
        with tmpfile(data) as file:
            core_reader = CoreReader(file, segments)
            self.assertEqual(core_reader.read(0xffff0000, len(data)), data)

    def test_c_string(self):
        data = b'hello\0world!'
        segments = [(0, 0xffff0000, 0x0, len(data), len(data))]
        with tmpfile(data) as file:
            core_reader = CoreReader(file, segments)
            self.assertEqual(core_reader.read_c_string(0xffff0000), b'hello')

            self.assertEqual(core_reader.read_c_string(0xffff0000, 4), b'hell')
            self.assertEqual(core_reader.read_c_string(0xffff0000, 5), b'hello')
            self.assertEqual(core_reader.read_c_string(0xffff0000, 6), b'hello')
            self.assertEqual(core_reader.read_c_string(0xffff0000, 7), b'hello')

            self.assertEqual(core_reader.read_c_string(0x0, 0), b'')
            self.assertEqual(core_reader.read_c_string(0xffff0000, 0), b'')

            self.assertEqual(core_reader.read_c_string(0xffff0008, 2), b'rl')
            self.assertRaisesRegex(ValueError, 'could not find memory segment',
                                   core_reader.read_c_string, 0xffff0008)
            self.assertRaisesRegex(ValueError, 'could not find memory segment',
                                   core_reader.read_c_string, 0xffff0008, 8)

    def test_bad_address(self):
        data = b'hello, world!'
        segments = [(0, 0xffff0000, 0x0, len(data), len(data))]
        with tmpfile(data) as file:
            core_reader = CoreReader(file, segments)
            self.assertRaisesRegex(ValueError, 'could not find memory segment',
                                   core_reader.read, 0xdeadbeef, 4)

    def test_segment_overflow(self):
        data = b'hello, world!'
        segments = [(0, 0xffff0000, 0x0, len(data), len(data))]
        with tmpfile(data) as file:
            core_reader = CoreReader(file, segments)
            self.assertRaisesRegex(ValueError, 'could not find memory segment',
                                   core_reader.read, 0xffff0000, len(data) + 1)

    def test_contiguous_segments(self):
        data = b'hello, world!\0foobar'
        segments = [
            (0, 0xffff0000, 0x0, 4, 4),
            (14, 0xfffff000, 0x0, 6, 6),
            (4, 0xffff0004, 0x0, 10, 10),
        ]
        with tmpfile(data) as file:
            core_reader = CoreReader(file, segments)
            self.assertEqual(core_reader.read(0xffff0000, 14), data[:14])

    def test_zero_filled_segment(self):
        data = b'hello, world!'
        segments = [
            (0, 0xffff0000, 0x0, 13, 17),
        ]
        with tmpfile(data) as file:
            core_reader = CoreReader(file, segments)
            self.assertEqual(core_reader.read(0xffff0000, len(data) + 4),
                             data + bytes(4))
            self.assertEqual(core_reader.read(0xffff0000 + len(data), 4),
                             bytes(4))
