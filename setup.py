#!/usr/bin/env python3

import re
from setuptools import setup, find_packages
from setuptools.extension import Extension


extensions = [
    Extension(
        name='drgn.internal.corereader',
        sources=[
            'drgn/internal/corereader.c',
        ],
    ),
    Extension(
        name='drgn.internal.dwarfindex',
        sources=[
            'drgn/internal/dwarfindex.c',
        ],
        extra_compile_args=['-fopenmp'],
        extra_link_args=['-fopenmp'],
    ),
    Extension(
        name='drgn.internal.thunk',
        sources=[
            'drgn/internal/thunk.c',
        ],
    ),
]


with open('drgn/__init__.py', 'r') as f:
    version = re.search(r"__version__\s*=\s*'([^']+)'", f.read()).group(1)


setup(
    name='drgn',
    version=version,
    packages=find_packages(exclude=['examples', 'scripts', 'tests']),
    ext_modules=extensions,
    entry_points={
        'console_scripts': ['drgn=drgn.internal.cli:main'],
    },
    author='Omar Sandoval',
    author_email='osandov@osandov.com',
    license='GPL-3.0+',
    description='Scriptable debugger library',
)
