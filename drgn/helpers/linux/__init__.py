# Copyright 2018-2019 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux Kernel
------------

The ``drgn.helpers.linux`` package contains several modules for working with
data structures and subsystems in the Linux kernel. The helpers are available
from the individual modules in which they are defined and from this top-level
package. E.g., the following are both valid:

>>> from drgn.helpers.linux.list import list_for_each_entry
>>> from drgn.helpers.linux import list_for_each_entry

Iterator macros (``for_each_foo``) are a common idiom in the Linux kernel. The
equivalent drgn helpers are implemented as Python :ref:`generators
<python:tut-generators>`. For example, the following code in C:

.. code-block:: c

    list_for_each(pos, head)
            do_something_with(pos);

Translates to the following code in Python:

.. code-block:: python3

    for pos in list_for_each(head):
        do_something_with(pos)
"""

import importlib
import pkgutil


__all__ = []
for _module_info in pkgutil.iter_modules(__path__, prefix=__name__ + "."):
    _submodule = importlib.import_module(_module_info.name)
    __all__.extend(_submodule.__all__)
    for _name in _submodule.__all__:
        globals()[_name] = getattr(_submodule, _name)
