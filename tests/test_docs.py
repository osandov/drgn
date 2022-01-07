# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later
import pydoc

import drgn
from tests import TestCase


class TestDocs(TestCase):
    def test_render(self):
        pydoc.render_doc(drgn)
