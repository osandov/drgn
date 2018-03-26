#!/usr/bin/env python3

from setuptools import setup
from setuptools.extension import Extension
from Cython.Build import cythonize


extensions = [
    Extension(
        name='drgn.dwarfindex',
        sources=[
            'drgn/dwarfindex.c',
        ],
    ),
]

setup(
    name='drgn',
    ext_modules=extensions,
)
