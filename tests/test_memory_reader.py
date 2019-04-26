import functools
import unittest

from drgn import FaultError
from _drgn import MemoryReader


def mock_read(data, address, count, physical, offset):
    return data[offset:offset + count]


class TestMemoryReader(unittest.TestCase):
    def test_simple_read(self):
        data = b'hello, world'
        reader = MemoryReader()
        reader.add_segment(0xffff0000, 0xa0, len(data),
                           functools.partial(mock_read, data))
        self.assertEqual(reader.read(0xffff0000, len(data)), data)
        self.assertEqual(reader.read(0xa0, len(data), True), data)

    def test_bad_address(self):
        data = b'hello, world!'
        reader = MemoryReader()
        reader.add_segment(0xffff0000, None, len(data),
                           functools.partial(mock_read, data))
        self.assertRaisesRegex(FaultError, 'could not find memory segment',
                               reader.read, 0xdeadbeef, 4)
        self.assertRaisesRegex(FaultError, 'could not find memory segment',
                               reader.read, 0xffff0000, 4, True)

    def test_segment_overflow(self):
        data = b'hello, world!'
        reader = MemoryReader()
        reader.add_segment(0xffff0000, None, len(data),
                           functools.partial(mock_read, data))
        self.assertRaisesRegex(FaultError, 'could not find memory segment',
                               reader.read, 0xffff0000, len(data) + 1)

    def test_adjacent_segments(self):
        data = b'hello, world!\0foobar'
        reader = MemoryReader()
        reader.add_segment(0xffff0000, None, len(data[:4]),
                           functools.partial(mock_read, data[:4]))
        reader.add_segment(0xffff0004, None, len(data[4:14]),
                           functools.partial(mock_read, data[4:14]))
        reader.add_segment(0xfffff000, None, len(data[14:]),
                           functools.partial(mock_read, data[14:]))
        self.assertEqual(reader.read(0xffff0000, 14), data[:14])

    def test_invalid_read_fn(self):
        reader = MemoryReader()

        self.assertRaises(TypeError, reader.add_segment, 0xffff0000, None, 8,
                          b'foo')

        reader.add_segment(0xffff0000, None, 8, lambda: None)
        self.assertRaises(TypeError, reader.read, 0xffff0000, 8)

        reader.add_segment(0xffff0000, None, 8,
                           lambda address, count, physical, offset: None)
        self.assertRaises(TypeError, reader.read, 0xffff0000, 8)

        reader.add_segment(0xffff0000, None, 8,
                           lambda address, count, physical, offset: 'asdf')
        self.assertRaises(TypeError, reader.read, 0xffff0000, 8)

        reader.add_segment(0xffff0000, None, 8,
                           lambda address, count, physical, offset: b'')
        self.assertRaisesRegex(
            ValueError,
            'memory read callback returned buffer of length 0 \(expected 8\)',
            reader.read, 0xffff0000, 8)
