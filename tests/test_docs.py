import pydoc
import unittest

import drgn


class TestDocs(unittest.TestCase):
    def test_render(self):
        pydoc.render_doc(drgn)
