# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

from typing import Tuple

from drgn.type import Type
from drgn.typeindex import TypeIndex


class VariableIndex:
    def __init__(self, type_index: TypeIndex) -> None:
        self._type_index = type_index

    def find(self, name: str) -> Tuple[int, Type]:
        raise NotImplementedError()
