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

from drgn.helpers.linux.block import *
from drgn.helpers.linux.cpumask import *
from drgn.helpers.linux.device import *
from drgn.helpers.linux.fs import *
from drgn.helpers.linux.idr import *
from drgn.helpers.linux.list import *
from drgn.helpers.linux.mm import *
from drgn.helpers.linux.percpu import *
from drgn.helpers.linux.pid import *
from drgn.helpers.linux.radixtree import *
from drgn.helpers.linux.rbtree import *


__all__ = (
    block.__all__ +
    cpumask.__all__ +
    device.__all__ +
    fs.__all__ +
    idr.__all__ +
    list.__all__ +
    mm.__all__ +
    percpu.__all__ +
    pid.__all__ +
    radixtree.__all__ +
    rbtree.__all__
)
