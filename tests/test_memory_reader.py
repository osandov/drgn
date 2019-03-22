import contextlib
import tempfile
import unittest

from drgn import FaultError
from tests.libdrgn import MemoryFileReader, MemoryFileSegment


@contextlib.contextmanager
def tmpfile(data):
    file = tempfile.TemporaryFile()
    try:
        file.write(data)
        file.flush()
        yield file
    finally:
        file.close()


class TestMemoryFileReader(unittest.TestCase):
    def test_simple_read(self):
        data = b'hello, world!'
        segments = [
            MemoryFileSegment(0, len(data), len(data), virt_addr=0xffff0000,
                              phys_addr=0xa0),
        ]
        with tmpfile(data) as file:
            reader = MemoryFileReader(segments, file)
            self.assertEqual(reader.read(0xffff0000, len(data)), data)
            self.assertEqual(reader.read(0xa0, len(data), True), data)

    def test_bad_address(self):
        data = b'hello, world!'
        segments = [
            MemoryFileSegment(0, len(data), len(data), virt_addr=0xffff0000),
        ]
        with tmpfile(data) as file:
            reader = MemoryFileReader(segments, file)
            self.assertRaisesRegex(FaultError, 'could not find memory segment',
                                   reader.read, 0xdeadbeef, 4)
            self.assertRaisesRegex(FaultError, 'could not find memory segment',
                                   reader.read, 0xffff0000, 4, True)

    def test_segment_overflow(self):
        data = b'hello, world!'
        segments = [
            MemoryFileSegment(0, len(data), len(data), virt_addr=0xffff0000),
        ]
        with tmpfile(data) as file:
            reader = MemoryFileReader(segments, file)
            self.assertRaisesRegex(FaultError, 'could not find memory segment',
                                   reader.read, 0xffff0000, len(data) + 1)

    def test_adjacent_segments(self):
        data = b'hello, world!\0foobar'
        segments = [
            MemoryFileSegment(0, 4, 4, virt_addr=0xffff0000),
            MemoryFileSegment(14, 6, 6, virt_addr=0xfffff000),
            MemoryFileSegment(4, 10, 10, virt_addr=0xffff0004),
        ]
        with tmpfile(data) as file:
            reader = MemoryFileReader(segments, file)
            self.assertEqual(reader.read(0xffff0000, 14), data[:14])

    def test_zero_filled_segment(self):
        data = b'hello, world!'
        segments = [
            MemoryFileSegment(0, 13, 17, virt_addr=0xffff0000),
        ]
        with tmpfile(data) as file:
            reader = MemoryFileReader(segments, file)
            self.assertEqual(reader.read(0xffff0000, len(data) + 4),
                             data + bytes(4))
            self.assertEqual(reader.read(0xffff0000 + len(data), 4), bytes(4))
