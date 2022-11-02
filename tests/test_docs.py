# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
import pydoc

import drgn
from tests import TestCase


class TestDocs(TestCase):
    def test_render(self):
        pydoc.render_doc(drgn)
