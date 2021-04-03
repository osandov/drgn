#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

# setuptools must be imported before distutils (see pypa/setuptools#2230).
import setuptools  # isort: skip

import contextlib
from distutils import log
from distutils.command.build import build as _build
from distutils.dir_util import mkpath
from distutils.errors import DistutilsError
from distutils.file_util import copy_file
import os
import os.path
import re
import shlex
import subprocess
import sys

from setuptools import Command, find_packages, setup
from setuptools.command.build_ext import build_ext as _build_ext
from setuptools.command.egg_info import egg_info as _egg_info
from setuptools.command.sdist import sdist as _sdist
from setuptools.extension import Extension

from util import nproc, out_of_date


class build(_build):
    def finalize_options(self):
        super().finalize_options()
        if self.parallel is None:
            self.parallel = nproc() + 1


class build_ext(_build_ext):
    user_options = [
        ("inplace", "i", "put compiled extension into the source directory"),
        ("parallel=", "j", "number of parallel build jobs"),
    ]

    boolean_options = ["inplace"]

    help_options = []

    def _run_autoreconf(self):
        if out_of_date(
            "libdrgn/Makefile.in", "libdrgn/Makefile.am", "libdrgn/configure.ac"
        ) or out_of_date("libdrgn/configure", "libdrgn/configure.ac"):
            try:
                subprocess.check_call(["autoreconf", "-i", "libdrgn"])
            except Exception:
                with contextlib.suppress(FileNotFoundError):
                    os.remove("libdrgn/configure")
                with contextlib.suppress(FileNotFoundError):
                    os.remove("libdrgn/Makefile.in")
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
                args.extend(shlex.split(os.environ["CONFIGURE_FLAGS"]))
            except KeyError:
                pass
            try:
                subprocess.check_call(args, cwd=self.build_temp)
            except Exception:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(makefile)
                raise

    def _run_make(self, *make_args):
        args = ["make", "-C", self.build_temp]
        if self.parallel:
            args.append(f"-j{self.parallel}")
        args.extend(make_args)
        subprocess.check_call(args)

    def make(self, *make_args):
        self._run_autoreconf()
        self._run_configure()
        self._run_make(*make_args)

    def run(self):
        self.make()
        so = os.path.join(self.build_temp, ".libs/_drgn.so")
        if self.inplace:
            copy_file(so, self.get_ext_fullpath("_drgn"), update=True)
        old_inplace, self.inplace = self.inplace, 0
        build_path = self.get_ext_fullpath("_drgn")
        mkpath(os.path.dirname(build_path))
        copy_file(so, build_path, update=True)
        self.inplace = old_inplace


# Work around pypa/setuptools#436.
class egg_info(_egg_info):
    def run(self):
        if os.path.exists(".git"):
            with contextlib.suppress(FileNotFoundError):
                os.remove(os.path.join(self.egg_info, "SOURCES.txt"))
        super().run()


class sdist(_sdist):
    def make_release_tree(self, base_dir, files):
        super().make_release_tree(base_dir, files)
        # Add the libdrgn distribution tree. This won't add the file names to
        # .egg-info/SOURCES.txt, but as far as I can tell that doesn't matter.
        build_ext = self.get_finalized_command("build_ext")
        distdir = os.path.join(
            os.path.relpath(base_dir, build_ext.build_temp), "libdrgn"
        )
        build_ext.make("distdir", "distdir=" + distdir)


class test(Command):
    description = "run unit tests after in-place build"

    KERNELS = [
        "5.12",
        "5.11",
        "5.10",
        "5.9",
        "5.8",
        "5.7",
        "5.6",
        "5.4",
        "4.19",
        "4.14",
        "4.9",
        "4.4",
    ]

    user_options = [
        (
            "kernel",
            "K",
            "run Linux kernel helper tests in a virtual machine on all supported kernels "
            f"({', '.join(KERNELS)})",
        ),
        (
            "extra-kernels=",
            "k",
            "additional kernels to run Linux kernel helper tests on in a virtual machine "
            "(comma-separated list of wildcard patterns matching uploaded kernel releases)",
        ),
        (
            "vmtest-dir=",
            "d",
            "directory for built artifacts and downloaded kernels for virtual machine tests (default: 'build/vmtest')",
        ),
    ]

    def initialize_options(self):
        self.kernel = False
        self.extra_kernels = ""
        self.vmtest_dir = None

    def finalize_options(self):
        self.kernels = [kernel for kernel in self.extra_kernels.split(",") if kernel]
        if self.kernel:
            self.kernels.extend(kernel + ".*" for kernel in test.KERNELS)
        if self.vmtest_dir is None:
            build_base = self.get_finalized_command("build").build_base
            self.vmtest_dir = os.path.join(build_base, "vmtest")

    def _run_local(self):
        import unittest

        argv = ["discover"]
        if self.verbose:
            argv.append("-v")
        test = unittest.main(module=None, argv=argv, exit=False)
        return test.result.wasSuccessful()

    def _run_vm(self, kernel_dir):
        from pathlib import Path

        import vmtest.vm

        command = fr"""cd {shlex.quote(os.getcwd())} &&
	DRGN_RUN_LINUX_HELPER_TESTS=1 {shlex.quote(sys.executable)} -Bm \
		unittest discover -t . -s tests/helpers/linux {"-v" if self.verbose else ""}"""
        try:
            returncode = vmtest.vm.run_in_vm(
                command, Path(kernel_dir), Path(self.vmtest_dir)
            )
        except vmtest.vm.LostVMError as e:
            self.announce(f"error: {e}", log.ERROR)
            return False
        self.announce(f"Tests in VM returned {returncode}", log.INFO)
        return returncode == 0

    def run(self):
        from pathlib import Path

        from vmtest.download import KernelDownloader

        # Start downloads ASAP so that they're hopefully done by the time we
        # need them.
        with KernelDownloader(self.kernels, Path(self.vmtest_dir)) as downloader:
            if self.kernels:
                self.announce("downloading kernels in the background", log.INFO)
            self.run_command("egg_info")
            self.reinitialize_command("build_ext", inplace=1)
            self.run_command("build_ext")

            passed = []
            failed = []

            if self.kernels:
                self.announce("running tests locally", log.INFO)
            if self._run_local():
                passed.append("local")
            else:
                failed.append("local")

            if self.kernels:
                for kernel in downloader:
                    self.announce(
                        f"running tests in VM on Linux {kernel.name}", log.INFO
                    )
                    if self._run_vm(kernel):
                        passed.append(kernel.name)
                    else:
                        failed.append(kernel.name)

                if passed:
                    self.announce(f'Passed: {", ".join(passed)}', log.INFO)
                if failed:
                    self.announce(f'Failed: {", ".join(failed)}', log.ERROR)

        if failed:
            raise DistutilsError("some tests failed")
        else:
            self.announce("all tests passed", log.INFO)


def get_version():
    try:
        with open("drgn/internal/version.py", "r") as f:
            version_py = f.read()
    except FileNotFoundError:
        version_py = None

    # The public version always comes from configure.ac.
    with open("libdrgn/configure.ac", "r") as f:
        public_version = re.search(
            r"AC_INIT\(\[libdrgn\], \[([^]]*)\]", f.read()
        ).group(1)
    # Default local version if we fail.
    local_version = "+unknown"

    # If this is a git repository, use a git-describe(1)-esque local version.
    # Otherwise, get the local version saved in the sdist.
    if os.path.exists(".git"):
        # Read the Docs modifies the working tree (namely, docs/conf.py). We
        # don't want the documentation to display a dirty version, so ignore
        # modifications for RTD builds.
        dirty = os.getenv("READTHEDOCS") != "True" and bool(
            subprocess.check_output(
                ["git", "status", "-uno", "--porcelain"],
                # Use the environment variable instead of --no-optional-locks
                # to support Git < 2.14.
                env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
            )
        )

        try:
            count = int(
                subprocess.check_output(
                    ["git", "rev-list", "--count", f"v{public_version}.."],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                )
            )
        except subprocess.CalledProcessError:
            log.warn("warning: v%s tag not found", public_version)
        else:
            if count == 0:
                local_version = "+dirty" if dirty else ""
            else:
                commit = subprocess.check_output(
                    ["git", "rev-parse", "--short", "HEAD"], universal_newlines=True
                ).strip()
                local_version = f"+{count}.g{commit}"
                if dirty:
                    local_version += ".dirty"
    else:
        if version_py is None:
            # This isn't a proper sdist (maybe a git archive).
            log.warn("warning: drgn/internal/version.py not found")
        else:
            # The saved version must start with the public version.
            match = re.search(
                fr'^__version__ = "{re.escape(public_version)}([^"]*)"$',
                version_py,
                re.M,
            )
            if match:
                local_version = match.group(1)
            else:
                log.warn("warning: drgn/internal/version.py is invalid")

    version = public_version + local_version
    # Update version.py if necessary.
    new_version_py = f'__version__ = "{version}"\n'
    if new_version_py != version_py:
        with open("drgn/internal/version.py", "w") as f:
            f.write(new_version_py)
    return version


with open("README.rst", "r") as f:
    long_description = f.read()


setup(
    name="drgn",
    version=get_version(),
    packages=find_packages(include=["drgn", "drgn.*"]),
    package_data={"drgn": ["../_drgn.pyi", "py.typed"]},
    # This is here so that setuptools knows that we have an extension; it's
    # actually built using autotools/make.
    ext_modules=[Extension(name="_drgn", sources=[])],
    cmdclass={
        "build": build,
        "build_ext": build_ext,
        "egg_info": egg_info,
        "sdist": sdist,
        "test": test,
    },
    entry_points={"console_scripts": ["drgn=drgn.internal.cli:main"]},
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
    license="GPL-3.0-or-later",
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
