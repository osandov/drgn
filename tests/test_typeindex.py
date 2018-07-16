from drgn.type import (
    BitFieldType,
    BoolType,
    EnumType,
    FloatType,
    IntType,
    TypedefType,
    VoidType,
)
from drgn.typeindex import TypeIndex
from drgn.typename import BasicTypeName, TypedefTypeName
from tests.test_type import TypeTestCase


TYPES = {
    'void': VoidType(),
    '_Bool': BoolType('_Bool', 1),
    'char': IntType('char', 1, True),
    'signed char': IntType('signed char', 1, True),
    'unsigned char': IntType('unsigned char', 1, False),
    'short': IntType('short', 2, True),
    'unsigned short': IntType('unsigned short', 2, False),
    'int': IntType('int', 4, True),
    'unsigned int': IntType('unsigned int', 4, False),
    'long': IntType('long', 8, True),
    'unsigned long': IntType('unsigned long', 8, False),
    'long long': IntType('long long', 8, True),
    'unsigned long long': IntType('unsigned long long', 8, False),
    'float': FloatType('float', 4),
    'double': FloatType('double', 8),
    'long double': FloatType('long double', 16),
}
TYPES['ptrdiff_t'] = TypedefType('ptrdiff_t', TYPES['long'])


class MockTypeIndex(TypeIndex):
    def __init__(self):
        super().__init__(8)

    def _find_type(self, type_name, filename=None):
        if isinstance(type_name, (BasicTypeName, TypedefTypeName)):
            try:
                return TYPES[type_name.name]
            except KeyError:
                pass
        raise ValueError('type not found')


class TypeIndexTestCase(TypeTestCase):
    def setUp(self):
        super().setUp()
        self.type_index = MockTypeIndex()


class TestTypeIndexLiteralType(TypeIndexTestCase):
    def test_bool(self):
        self.assertEqual(self.type_index._literal_type(True), TYPES['_Bool'])
        self.assertEqual(self.type_index._literal_type(False), TYPES['_Bool'])

    def test_int(self):
        self.assertEqual(self.type_index._literal_type(0), TYPES['int'])
        self.assertEqual(self.type_index._literal_type(-2**31), TYPES['int'])
        self.assertEqual(self.type_index._literal_type(2**31 - 1), TYPES['int'])

        self.assertEqual(self.type_index._literal_type(2**31),
                         TYPES['unsigned int'])
        self.assertEqual(self.type_index._literal_type(2**32 - 1),
                         TYPES['unsigned int'])

        self.assertEqual(self.type_index._literal_type(-2**31 - 1),
                         TYPES['long'])
        self.assertEqual(self.type_index._literal_type(-2**63), TYPES['long'])
        self.assertEqual(self.type_index._literal_type(2**32), TYPES['long'])
        self.assertEqual(self.type_index._literal_type(2**63 - 1),
                         TYPES['long'])

        self.assertEqual(self.type_index._literal_type(2**63),
                         TYPES['unsigned long'])
        self.assertEqual(self.type_index._literal_type(2**64 - 1),
                         TYPES['unsigned long'])

    def test_float(self):
        self.assertEqual(self.type_index._literal_type(0.0), TYPES['double'])
        self.assertEqual(self.type_index._literal_type(float('inf')),
                         TYPES['double'])
        self.assertEqual(self.type_index._literal_type(float('nan')),
                         TYPES['double'])

    def test_error(self):
        self.assertRaises(TypeError, self.type_index._literal_type, None)
        self.assertRaises(TypeError, self.type_index._literal_type, 2**128)


class TestTypeIndexIntegerPromotions(TypeIndexTestCase):
    def assertPromotes(self, type, expected_type):
        self.assertEqual(self.type_index._integer_promotions(type),
                         expected_type)

    def test_char(self):
        self.assertPromotes(TYPES['char'], TYPES['int'])
        self.assertPromotes(TYPES['signed char'], TYPES['int'])
        self.assertPromotes(TYPES['unsigned char'], TYPES['int'])

    def test_short(self):
        self.assertPromotes(TYPES['short'], TYPES['int'])
        self.assertPromotes(TYPES['unsigned short'], TYPES['int'])

    def test_bool(self):
        self.assertPromotes(TYPES['_Bool'], TYPES['int'])

    def test_enum(self):
        type_ = EnumType('color', IntType('int', 4, True), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
        self.assertPromotes(type_, TYPES['int'])

        type_ = EnumType('color', IntType('unsigned int', 4, False), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
        self.assertPromotes(type_, TYPES['unsigned int'])

        type_ = EnumType('color', IntType('unsigned long', 8, False), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
        self.assertPromotes(type_, TYPES['unsigned long'])

    def test_int(self):
        self.assertPromotes(TYPES['int'], TYPES['int'])
        self.assertPromotes(TYPES['unsigned int'], TYPES['unsigned int'])

    def test_long(self):
        self.assertPromotes(TYPES['long'], TYPES['long'])
        self.assertPromotes(TYPES['unsigned long'], TYPES['unsigned long'])

    def test_long_long(self):
        self.assertPromotes(TYPES['long long'], TYPES['long long'])
        self.assertPromotes(TYPES['unsigned long long'],
                            TYPES['unsigned long long'])

    def test_bit_field(self):
        self.assertPromotes(BitFieldType(TYPES['int'], 0, 4), TYPES['int'])
        self.assertPromotes(BitFieldType(TYPES['long'], 0, 4),
                            TYPES['int'])

        self.assertPromotes(BitFieldType(TYPES['int'], 0, 32), TYPES['int'])
        self.assertPromotes(BitFieldType(TYPES['long'], 0, 32), TYPES['int'])

        self.assertPromotes(BitFieldType(TYPES['unsigned int'], 0, 4),
                            TYPES['int'])
        self.assertPromotes(BitFieldType(TYPES['unsigned long'], 0, 4),
                            TYPES['int'])

        self.assertPromotes(BitFieldType(TYPES['unsigned int'], 0, 32),
                            TYPES['unsigned int'])
        self.assertPromotes(BitFieldType(TYPES['unsigned long'], 0, 32),
                            TYPES['unsigned int'])

        self.assertPromotes(BitFieldType(TYPES['long'], 0, 40),
                            BitFieldType(TYPES['long'], None, 40))
        self.assertPromotes(BitFieldType(TYPES['unsigned long'], 0, 40),
                            BitFieldType(TYPES['unsigned long'], None, 40))

    def test_typedef(self):
        type_ = TypedefType('SHORT', TYPES['short'])
        self.assertPromotes(type_, TYPES['int'])

        type_ = TypedefType('INT', TYPES['int'])
        self.assertPromotes(type_, type_)

        type_ = TypedefType('LONG', TYPES['long'])
        self.assertPromotes(type_, type_)

    def test_other(self):
        self.assertPromotes(TYPES['float'], TYPES['float'])
        self.assertPromotes(TYPES['double'], TYPES['double'])


class TestTypeIndexCommonRealType(TypeIndexTestCase):
    def assertCommon(self, type1, type2, expected_type):
        self.assertEqual(self.type_index._common_real_type(type1, type2),
                         expected_type)
        self.assertEqual(self.type_index._common_real_type(type2, type1),
                         expected_type)

    def test_long_double(self):
        self.assertCommon(TYPES['long double'], TYPES['double'],
                          TYPES['long double'])
        self.assertCommon(TYPES['int'], TYPES['long double'],
                          TYPES['long double'])

    def test_double(self):
        self.assertCommon(TYPES['double'], TYPES['float'], TYPES['double'])
        self.assertCommon(TYPES['long'], TYPES['double'], TYPES['double'])

    def test_float(self):
        self.assertCommon(TYPES['int'], TYPES['float'], TYPES['float'])
        self.assertCommon(TYPES['float'], TYPES['long long'], TYPES['float'])

    def test_same(self):
        self.assertCommon(TYPES['int'], TYPES['int'], TYPES['int'])

    def test_same_sign(self):
        self.assertCommon(TYPES['long'], TYPES['long long'],
                          TYPES['long long'])

        self.assertCommon(IntType('unsigned long', 4, False),
                          TYPES['unsigned int'],
                          IntType('unsigned long', 4, False))

    def test_unsigned_rank(self):
        self.assertCommon(TYPES['long'], TYPES['unsigned long long'],
                          TYPES['unsigned long long'])
        self.assertCommon(TYPES['unsigned int'], TYPES['int'],
                          TYPES['unsigned int'])

    def test_signed_range(self):
        self.assertCommon(TYPES['long'], TYPES['unsigned int'], TYPES['long'])
        self.assertCommon(IntType('unsigned long', 4, False),
                          TYPES['long long'], TYPES['long long'])

    def test_corresponding_unsigned(self):
        self.assertCommon(IntType('long', 4, True), TYPES['unsigned int'],
                          IntType('unsigned long', 4, False))
        self.assertCommon(TYPES['long long'], TYPES['unsigned long'],
                          TYPES['unsigned long long'])

    def test_typedef(self):
        typedef_type = TypedefType('u32', TYPES['unsigned int'])
        self.assertCommon(typedef_type, typedef_type, typedef_type)

    def test_bool(self):
        self.assertCommon(BoolType('_Bool', 1), TYPES['int'], TYPES['int'])

    def test_bit_field(self):
        self.assertCommon(BitFieldType(TYPES['int'], None, 4),
                          BitFieldType(TYPES['int'], None, 4), TYPES['int'])

        self.assertCommon(BitFieldType(TYPES['long'], None, 4),
                          BitFieldType(TYPES['long'], None, 4), TYPES['int'])

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['long'], None, 33),
                          BitFieldType(TYPES['long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['long long'], None, 33),
                          BitFieldType(TYPES['long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['long long'], None, 40),
                          BitFieldType(TYPES['long long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['unsigned long'], None, 33),
                          BitFieldType(TYPES['long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40),
                          BitFieldType(TYPES['unsigned long'], None, 40),
                          BitFieldType(TYPES['unsigned long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40), TYPES['int'],
                          BitFieldType(TYPES['long'], None, 40))

        self.assertCommon(BitFieldType(TYPES['long'], None, 40), TYPES['long'],
                          TYPES['long'])

    def test_enum(self):
        type_ = EnumType('color', IntType('int', 4, True), [
            ('RED', 0),
            ('GREEN', 1),
            ('BLUE', 2)
        ])
        self.assertCommon(type_, TYPES['int'], TYPES['int'])

        type_ = TypedefType('COLOR', type_)
        self.assertCommon(type_, TYPES['int'], TYPES['int'])
