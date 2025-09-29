# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import importlib
import pkgutil
import pydoc
import types

import drgn
import drgn.helpers.common
import drgn.helpers.linux
from tests import TestCase


class TestDocs(TestCase):
    def test_render(self):
        pydoc.render_doc(drgn)

    def test_helper_exports(self):
        for package in (drgn.helpers.common, drgn.helpers.linux):
            for module_info in pkgutil.iter_modules(
                package.__path__, prefix=package.__name__ + "."
            ):
                with self.subTest(module=module_info.name):
                    submodule = importlib.import_module(module_info.name)
                    expected = set()
                    for name in dir(submodule):
                        attr = getattr(submodule, name)
                        # Documented functions defined in the given module
                        # should be in __all__. This won't catch non-function
                        # callables or re-exports, but it's close enough.
                        if (
                            isinstance(
                                attr, (types.FunctionType, types.BuiltinFunctionType)
                            )
                            and getattr(attr, "__module__", None) == module_info.name
                            and getattr(attr, "__doc__", None)
                        ):
                            expected.add(name)
                    missing = expected - set(getattr(submodule, "__all__", ()))
                    if missing:
                        self.fail(
                            f"{module_info.name}.__all__ is missing {sorted(missing)}"
                        )
