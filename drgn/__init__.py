# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Scriptable debugger library

drgn is a scriptable debugger. It is built on top of Python, so if you don't
know at least a little bit of Python, go learn it first.

drgn supports an interactive mode and a script mode. Both are simply a Python
interpreter initialized with a special drgn.program.Program object named "prog"
that represents the program which is being debugged.

In interactive mode, try

>>> help(prog)

or

>>> import drgn.program
>>> help(drgn.program.Program)

to learn more about how to use it.

Variables are represented by drgn.program.Object objects. Try

>>> import drgn.program
>>> help(drgn.program.Object)

Types are represented by drgn.type.Type objects. Try

>>> import drgn.type
>>> help(drgn.type)

Various helpers are provided for particular types of programs. Try

>>> import drgn.helpers
>>> help(drgn.helpers)

The drgn.internal package contains the drgn internals. Everything in that
package should be considered implementation details and should not be used.
"""

__version__ = '0.1.0'
