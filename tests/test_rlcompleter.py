import itertools
from types import SimpleNamespace
import unittest

from drgn.rlcompleter import Completer


class TestRlCompleter(unittest.TestCase):
    def setUp(self):
        self.namespace = {}

    def assertCompletes(self, text, expected):
        completer = Completer(self.namespace)
        actual = []
        for i in itertools.count():
            word = completer.complete(text, i)
            if word is None:
                break
            actual.append(word)
        self.assertEqual(actual, expected)

    def test_global(self):
        self.namespace['ZZZ_foo'] = None
        self.namespace['ZZZ_bar'] = lambda: None
        self.assertCompletes('ZZZ', ['ZZZ_bar(', 'ZZZ_foo'])
        self.assertCompletes('ZZZ_b', ['ZZZ_bar('])
        self.assertCompletes('ZZZ_f', ['ZZZ_foo'])

        self.assertCompletes('.', [])

    def test_attr(self):
        self.namespace['foo'] = SimpleNamespace(bar=None, _baz=None)
        self.assertCompletes('foo.', ['foo.bar'])
        self.assertCompletes('foo.b', ['foo.bar'])
        self.assertCompletes('foo._', ['foo._baz'])

    def test_two_attrs(self):
        self.namespace['foo'] = SimpleNamespace(bar=SimpleNamespace(baz=None))
        self.assertCompletes('foo.bar.', ['foo.bar.baz'])

    def test_list(self):
        self.namespace['foo'] = [SimpleNamespace(bar=None)]
        self.assertCompletes('foo[0].', ['foo[0].bar'])

    def test_nested_list(self):
        self.namespace['foo'] = [[SimpleNamespace(bar=None)]]
        self.assertCompletes('foo[0][0].', ['foo[0][0].bar'])

    def test_second_list(self):
        self.namespace['foo'] = SimpleNamespace(bar=[SimpleNamespace(baz=None)])
        self.assertCompletes('foo.bar[0].', ['foo.bar[0].baz'])

    def test_dict(self):
        self.namespace['foo'] = {
            'bar': SimpleNamespace(baz=None),
        }
        self.assertCompletes("foo['bar'].", ["foo['bar'].baz"])

    def test_dict_escaped(self):
        self.namespace['foo'] = {
            '\'': SimpleNamespace(baz=None),
        }
        self.assertCompletes(r"foo['\''].", [r"foo['\''].baz"])
