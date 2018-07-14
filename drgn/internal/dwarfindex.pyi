from typing import List

from drgn.internal.dwarf import Die


class DwarfIndex:
    address_size: int
    files: List[str]
    def __init__(self, *paths: str) -> None: ...
    def add(self, *paths: str) -> None: ...
    def find(self, name: str, tag: int = ...) -> List[Die]: ...
