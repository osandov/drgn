#!/usr/bin/env python3

import re
import os.path
from distutils.dir_util import mkpath
from distutils.errors import DistutilsSetupError
from distutils.file_util import copy_file
from setuptools import setup, find_packages
from setuptools.extension import Extension
from setuptools.command.build_ext import build_ext
from setuptools.command.sdist import sdist
import subprocess
import sys


class my_build_ext(build_ext):
    user_options = [
        ('inplace', 'i', 'put compiled extension into the source directory'),
        ('parallel=', 'j', 'number of parallel build jobs'),
    ]

    boolean_options = ['inplace']

    help_options = []

    def _run_autotools(self):
        if not os.path.exists('libdrgn/configure'):
            subprocess.check_call(['autoreconf', '-i', 'libdrgn'])
        mkpath(self.build_temp)
        if not os.path.exists(os.path.join(self.build_temp, 'Makefile')):
            args = [
                os.path.relpath('libdrgn/configure', self.build_temp),
                '--disable-static', '--with-python=' + sys.executable,
            ]
            subprocess.check_call(args, cwd=self.build_temp)

    def get_source_files(self):
        self._run_autotools()
        args = ['make', '-C', self.build_temp, 'distfiles', '-s']
        return [
            os.path.normpath(os.path.join(self.build_temp, path)) for path in
            subprocess.check_output(args, universal_newlines=True).splitlines()
        ]

    def run(self):
        self._run_autotools()
        args = ['make', '-C', self.build_temp, '_drgn.la']
        if self.parallel:
            args.append(f'-j{self.parallel}')
        subprocess.check_call(args)

        so = os.path.join(self.build_temp, '.libs/_drgn.so')
        if self.inplace:
            copy_file(so, self.get_ext_fullpath('_drgn'))
        self.inplace = 0
        build_path = self.get_ext_fullpath('_drgn')
        mkpath(os.path.dirname(build_path))
        copy_file(so, build_path)


class my_sdist(sdist):
    user_options = sdist.user_options + [
        ('force', 'f',
         'create the source distribution even if the repository is unclean'),
    ]

    boolean_options = sdist.boolean_options + ['force']

    def initialize_options(self):
        super().initialize_options()
        self.force = 0

    def run(self):
        # In order to avoid shipping a stale source distribution (e.g., due to
        # pypa/setuptools#436 or the autotools output being out of date),
        # require the repository to be clean (no unknown or ignored files).
        # This check can be disabled with --force.
        if not self.force and subprocess.check_output(['git', 'clean', '-dnx']):
            raise DistutilsSetupError('repository has untracked or ignored files; '
                                      'please run git clean -dfx or use --force')
        super().run()


with open('libdrgn/drgn.h', 'r') as f:
    drgn_h = f.read()
version_major = re.search('^#define DRGN_VERSION_MAJOR ([0-9])+$', drgn_h,
                          re.MULTILINE).group(1)
version_minor = re.search('^#define DRGN_VERSION_MINOR ([0-9])+$', drgn_h,
                          re.MULTILINE).group(1)
version_patch = re.search('^#define DRGN_VERSION_PATCH ([0-9])+$', drgn_h,
                          re.MULTILINE).group(1)
version = f'{version_major}.{version_minor}.{version_patch}'

setup(
    name='drgn',
    version=version,
    packages=find_packages(exclude=['examples', 'scripts', 'tests']),
    # This is here so that setuptools knows that we have an extension; it's
    # actually built using autotools/make.
    ext_modules=[Extension(name='_drgn', sources=[])],
    cmdclass={
        'build_ext': my_build_ext,
        'sdist': my_sdist,
    },
    entry_points={
        'console_scripts': ['drgn=drgn.internal.cli:main'],
    },
    author='Omar Sandoval',
    author_email='osandov@osandov.com',
    description='Scriptable debugger library',
    license='GPL-3.0+',
    url='https://github.com/osandov/drgn',
)
