from collections import OrderedDict
import ctypes
import unittest
try:
    from drgn.lldwarf import _TestObject
except ImportError:
    pass

ARGS = OrderedDict([
    ('m_short', -16),
    ('m_int', -32),
    ('m_long', -48),
    # ('m_float', 4.0),
    # ('m_double', 8.0),
    # ('m_string', 'asdf'),
    ('m_object', []),
    ('m_object_ex', {}),
    ('m_char', '@'),
    ('m_byte', -8),
    ('m_ubyte', 8),
    ('m_uint', 32),
    ('m_ushort', 16),
    ('m_ulong', 48),
    ('m_bool', True),
    ('m_longlong', -64),
    ('m_ulonglong', 64),
    ('m_pyssizet', -63),
])


@unittest.skipIf('_TestObject' not in globals(), '_TestObject not enabled')
class TestLLDwarfObject(unittest.TestCase):
    def test_args(self):
        obj = _TestObject(*ARGS.values())
        for attr, val in ARGS.items():
            self.assertEqual(getattr(obj, attr), val)

    def test_kwargs(self):
        obj = _TestObject(**ARGS)
        for attr, val in ARGS.items():
            self.assertEqual(getattr(obj, attr), val)

    def test_mixed(self):
        args = []
        kwds = {}
        for i, (key, value) in enumerate(ARGS.items()):
            if i < len(ARGS) // 2:
                args.append(value)
            else:
                kwds[key] = value
        obj = _TestObject(*args, **kwds)
        for attr, val in ARGS.items():
            self.assertEqual(getattr(obj, attr), val)

    def test_extra_args(self):
        args = ARGS.copy()
        args['m_foo'] = 5
        with self.assertRaises(TypeError):
            _TestObject(*args.values())
        with self.assertRaises(TypeError):
            _TestObject(**args)

    def test_missing_args(self):
        args = ARGS.copy()
        del args['m_pyssizet']
        with self.assertRaises(TypeError):
            _TestObject(*args.values())
        with self.assertRaises(TypeError):
            _TestObject(**args)

    def test_cmp(self):
        obj1 = _TestObject(**ARGS)
        obj2 = _TestObject(**ARGS)
        self.assertEqual(obj1, obj2)
        self.assertTrue(obj1 == obj2)
        self.assertFalse(obj1 != obj2)
        with self.assertRaises(TypeError):
            obj1 < obj2

    def _test_int(self, attr, min, max):
        args = ARGS.copy()
        args[attr] = min
        self.assertEqual(getattr(_TestObject(**args), attr), min)

        args = ARGS.copy()
        args[attr] = max
        self.assertEqual(getattr(_TestObject(**args), attr), max)

        args = ARGS.copy()
        args[attr] = min - 1
        with self.assertRaises(OverflowError):
            _TestObject(**args)

        args = ARGS.copy()
        args[attr] = max + 1
        with self.assertRaises(OverflowError):
            _TestObject(**args)

        args = ARGS.copy()
        args[attr] = min
        obj1 = _TestObject(**args)
        args = ARGS.copy()
        args[attr] = max
        obj2 = _TestObject(**args)
        self.assertNotEqual(obj1, obj2)

    def test_short(self):
        self._test_int('m_short', -2**15, 2**15 - 1)

    def test_int(self):
        self._test_int('m_int', -2**31, 2**31 - 1)

    def test_long(self):
        bits = 8 * ctypes.sizeof(ctypes.c_long) - 1
        self._test_int('m_long', -2**bits, 2**bits - 1)

    # test_object

    def test_char(self):
        args = ARGS.copy()
        args['m_char'] = 'ab'
        with self.assertRaisesRegex(ValueError, 'expected a character'):
            _TestObject(**args)

        args = ARGS.copy()
        args['m_char'] = '\x80'
        with self.assertRaisesRegex(ValueError, 'character out of range'):
            _TestObject(**args)

    def test_byte(self):
        self._test_int('m_byte', -2**7, 2**7 - 1)

    def test_ubyte(self):
        self._test_int('m_ubyte', 0, 2**8 - 1)

    def test_uint(self):
        self._test_int('m_uint', 0, 2**32 - 1)

    def test_ushort(self):
        self._test_int('m_ushort', 0, 2**16 - 1)

    def test_ulong(self):
        bits = 8 * ctypes.sizeof(ctypes.c_long)
        self._test_int('m_ulong', 0, 2**bits - 1)

    def test_bool(self):
        args = ARGS.copy()
        args['m_bool'] = True
        self.assertEqual(_TestObject(**args).m_bool, True)

        args = ARGS.copy()
        args['m_bool'] = False
        self.assertEqual(_TestObject(**args).m_bool, False)

    def test_longlong(self):
        self._test_int('m_longlong', -2**63, 2**63 - 1)

    def test_ulonglong(self):
        self._test_int('m_ulonglong', 0, 2**64 - 1)

    def test_pyssizet(self):
        self._test_int('m_pyssizet', -2**63, 2**63 - 1)

    def test_repr(self):
        args_repr = ', '.join(f'{key}={value!r}' for key, value in ARGS.items())
        obj = _TestObject(*ARGS.values())
        self.assertEqual(repr(obj), f'_TestObject({args_repr})')

    def test_recursive_repr(self):
        args_repr = ', '.join(f'{key}={value!r}' for key, value in ARGS.items())
        args_repr = args_repr.replace('[]', '[_TestObject(...)]')
        obj = _TestObject(*ARGS.values())
        obj.m_object.append(obj)
        self.assertEqual(repr(obj), f'_TestObject({args_repr})')
