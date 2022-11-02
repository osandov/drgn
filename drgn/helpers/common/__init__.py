# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Common
------

The ``drgn.helpers.common`` package provides helpers that can be used with any
program. The helpers are available from the individual modules in which they
are defined and from this top-level package. E.g., the following are both
valid:

>>> from drgn.helpers.common.memory import identify_address
>>> from drgn.helpers.common import identify_address

Some of these helpers may have additional program-specific behavior but are
otherwise generic.
"""

import importlib
import pkgutil
from typing import List

__all__: List[str] = []
for _module_info in pkgutil.iter_modules(__path__, prefix=__name__ + "."):
    _submodule = importlib.import_module(_module_info.name)
    _submodule_all = getattr(_submodule, "__all__", ())
    __all__.extend(_submodule_all)
    for _name in _submodule_all:
        globals()[_name] = getattr(_submodule, _name)
