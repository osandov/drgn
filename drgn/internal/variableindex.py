# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""Index of variables in a program"""

from typing import Any, Optional, Tuple

from drgn.type import Type
from drgn.typeindex import TypeIndex


class VariableIndex:
    """
    A VariableIndex provides lookups of all of the variables and enumerators in
    a program (i.e., all of the identifiers which are expressions).

    This is an abstract base class which is implemented by an internal class
    depending on the format of the debugging information available; it should
    not be created directly. It is used internally by drgn.Program.
    """

    def __init__(self, type_index: TypeIndex) -> None:
        self._type_index = type_index

    def find(self, name: str,
             filename: Optional[str] = None) -> Tuple[Type, Any, Optional[int]]:
        """
        Return a representation of the given identifier as a tuple of its type,
        its value, and its address. If the identifier is a variable, the value
        will be None and the address will be an int. If the identifier is a
        constant (e.g., an enumerator), the value will have the appropriate
        type and the address will be None.
        """
        raise NotImplementedError()
