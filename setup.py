#!/usr/bin/env python3

import contextlib
from distutils import log
from distutils.dir_util import mkpath
from distutils.file_util import copy_file
import os
import os.path
import re
import pkg_resources
from setuptools import setup, find_packages
from setuptools.command.build_ext import build_ext
from setuptools.command.egg_info import egg_info
from setuptools.extension import Extension
import subprocess
import sys


class my_build_ext(build_ext):
    user_options = [
        ("inplace", "i", "put compiled extension into the source directory"),
        ("parallel=", "j", "number of parallel build jobs"),
    ]

    boolean_options = ["inplace"]

    help_options = []

    def _run_autoreconf(self, dir):
        makefile_in = os.path.join(dir, "Makefile.in")
        if not os.path.exists(makefile_in):
            try:
                subprocess.check_call(["autoreconf", "-i", dir])
            except Exception:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(makefile_in)
                raise

    def _run_configure(self):
        mkpath(self.build_temp)
        makefile = os.path.join(self.build_temp, "Makefile")
        if not os.path.exists(makefile):
            args = [
                os.path.relpath("libdrgn/configure", self.build_temp),
                "--disable-static",
                "--with-python=" + sys.executable,
            ]
            try:
                subprocess.check_call(args, cwd=self.build_temp)
            except Exception:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(makefile)
                raise

    def _run_make(self):
        args = ["make", "-C", self.build_temp]
        if self.parallel:
            args.append(f"-j{self.parallel}")
        subprocess.check_call(args)

    def run(self):
        self._run_autoreconf("libdrgn")
        self._run_autoreconf("libdrgn/elfutils")
        self._run_configure()
        self._run_make()

        so = os.path.join(self.build_temp, ".libs/_drgn.so")
        if self.inplace:
            copy_file(so, self.get_ext_fullpath("_drgn"), update=True)
        old_inplace, self.inplace = self.inplace, 0
        build_path = self.get_ext_fullpath("_drgn")
        mkpath(os.path.dirname(build_path))
        copy_file(so, build_path, update=True)
        self.inplace = old_inplace

    def get_source_files(self):
        if os.path.exists(".git"):
            args = ["git", "ls-files", "-z", "libdrgn"]
            return [
                os.fsdecode(path)
                for path in subprocess.check_output(args).split(b"\0")
                if path
            ]
        else:
            # If this is a source distribution, then setuptools will get the
            # list of sources that was included in the tarball.
            return []


# Work around pypa/setuptools#436.
class my_egg_info(egg_info):
    def run(self):
        if os.path.exists(".git"):
            try:
                os.remove(os.path.join(self.egg_info, "SOURCES.txt"))
            except FileNotFoundError:
                pass
        super().run()


def get_version():
    if not os.path.exists(".git"):
        # If this is a source distribution, get the version from the egg
        # metadata.
        return pkg_resources.get_distribution("drgn").version

    with open("libdrgn/configure.ac", "r") as f:
        version = re.search(r"AC_INIT\(\[drgn\], \[([^]]*)\]", f.read()).group(1)

    dirty = bool(
        subprocess.check_output(
            ["git", "status", "-uno", "--porcelain"],
            # Use the environment variable instead of --no-optional-locks to
            # support Git < 2.14.
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        )
    )

    try:
        count = int(
            subprocess.check_output(
                ["git", "rev-list", "--count", f"v{version}.."],
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
            )
        )
    except subprocess.CalledProcessError:
        log.warn("warning: v%s tag not found", version)
        count = 0

    if count == 0:
        if dirty:
            version += "+dirty"
        return version

    commit = subprocess.check_output(
        ["git", "rev-parse", "--short", "HEAD"], universal_newlines=True
    ).strip()
    version += f".dev{count}+{commit}"
    if dirty:
        version += ".dirty"
    return version


with open("README.rst", "r") as f:
    long_description = f.read()


setup(
    name="drgn",
    version=get_version(),
    packages=find_packages(exclude=["examples", "scripts", "tests"]),
    # This is here so that setuptools knows that we have an extension; it's
    # actually built using autotools/make.
    ext_modules=[Extension(name="_drgn", sources=[])],
    cmdclass={"build_ext": my_build_ext, "egg_info": my_egg_info,},
    entry_points={"console_scripts": ["drgn=drgn.internal.cli:main"],},
    python_requires=">=3.6",
    author="Omar Sandoval",
    author_email="osandov@osandov.com",
    description="Scriptable debugger library",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/osandov/drgn",
    project_urls={
        "Bug Tracker": "https://github.com/osandov/drgn/issues",
        "Documentation": "https://drgn.readthedocs.io",
    },
    license="GPL-3.0+",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Debuggers",
    ],
)
