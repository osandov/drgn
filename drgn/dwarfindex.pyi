from drgn.dwarf import Die
from typing import List


class DwarfIndex:
    address_size: int
    def __init__(self, paths: List[str]) -> None: ...
    def find(self, name: str, tag: int = ...) -> List[Die]: ...
