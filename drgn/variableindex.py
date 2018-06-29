# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

from typing import Any, Optional, Tuple

from drgn.type import Type
from drgn.typeindex import DwarfTypeIndex, TypeIndex


class VariableIndex:
    def __init__(self, type_index: TypeIndex) -> None:
        self._type_index = type_index

    def find(self, name: str,
             filename: Optional[str] = None) -> Tuple[Type, Any, Optional[int]]:
        raise NotImplementedError()
