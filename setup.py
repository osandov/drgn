#!/usr/bin/env python3

from drgn import __version__
from setuptools import setup, find_packages
from setuptools.extension import Extension


extensions = [
    Extension(
        name='drgn.dwarfindex',
        sources=[
            'drgn/dwarfindex.c',
        ],
        extra_compile_args=['-fopenmp'],
        extra_link_args=['-fopenmp'],
    ),
    Extension(
        name='drgn.corereader',
        sources=[
            'drgn/corereader.c',
        ],
    ),
]

setup(
    name='drgn',
    version=__version__,
    packages=find_packages(exclude=['scripts', 'tests']),
    ext_modules=extensions,
    entry_points={
        'console_scripts': ['drgn=drgn.cli.main'],
    },
    author='Omar Sandoval',
    author_email='osandov@osandov.com',
    license='GPL-3.0+',
    description='Scriptable debugger',
)
