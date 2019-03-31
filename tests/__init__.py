import ctypes

import _drgn


_drgn_pydll = ctypes.PyDLL(_drgn.__file__)
_drgn_cdll = ctypes.CDLL(_drgn.__file__)
