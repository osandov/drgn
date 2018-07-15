from typing import Any, Callable, TypeVar


T = TypeVar('T')
def thunk(func: Callable[..., T], *args: Any, **kwds: Any) -> Callable[[], T]: ...
