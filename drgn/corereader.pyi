from os import PathLike
from typing import Union


class CoreReader:
    def __init__(self, path: Union[str, bytes, PathLike]) -> None: ...
    def read(self, address: int, size: int) -> bytes: ...
