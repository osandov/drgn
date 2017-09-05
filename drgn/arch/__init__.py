import importlib
import platform

arch = importlib.import_module(f'drgn.arch.{platform.machine()}')
DWARF_REG_TO_AS = arch.DWARF_REG_TO_AS
DWARF_REG_TO_FETCHARG = arch.DWARF_REG_TO_FETCHARG
