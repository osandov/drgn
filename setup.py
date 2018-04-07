#!/usr/bin/env python3

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
]

setup(
    name='drgn',
    packages=find_packages(exclude=['scripts', 'tests']),
    ext_modules=extensions,
    entry_points={
        'console_scripts': ['drgn=drgn.cli.main'],
    },
    author='Omar Sandoval',
    author_email='osandov@osandov.com',
    description='Scriptable debugger',
)
