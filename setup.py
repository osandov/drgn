#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

# setuptools must be imported before distutils (see pypa/setuptools#2230).
from setuptools import setup, find_packages, Command

import contextlib
from distutils import log
from distutils.command.build import build as _build
from distutils.dir_util import mkpath
from distutils.errors import DistutilsError
from distutils.file_util import copy_file
import os
import os.path
import re
import pkg_resources
from setuptools.command.build_ext import build_ext as _build_ext
from setuptools.command.egg_info import egg_info as _egg_info
from setuptools.extension import Extension
import shlex
import subprocess
import sys

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

    def _run_autoreconf(self, dir):
        configure = os.path.join(dir, "configure")
        configure_ac = os.path.join(dir, "configure.ac")
        makefile_am = os.path.join(dir, "Makefile.am")
        makefile_in = os.path.join(dir, "Makefile.in")
        if out_of_date(makefile_in, makefile_am, configure_ac) or out_of_date(
            configure, configure_ac
        ):
            try:
                subprocess.check_call(["autoreconf", "-i", dir])
            except Exception:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(configure)
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
                args.extend(shlex.split(os.environ["CONFIGURE_FLAGS"]))
            except KeyError:
                pass
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
class egg_info(_egg_info):
    def run(self):
        if os.path.exists(".git"):
            with contextlib.suppress(FileNotFoundError):
                os.remove(os.path.join(self.egg_info, "SOURCES.txt"))
        super().run()


class test(Command):
    description = "run unit tests after in-place build"

    KERNELS = ["5.8", "5.7", "5.6", "5.5", "5.4", "4.19", "4.14", "4.9", "4.4"]

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
            "(comma-separated list of kernel build directory path or "
            "wildcard pattern matching uploaded kernel release strings)",
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

    def _run_vm(self, *, vmlinux, vmlinuz, build_dir):
        import vmtest.vm

        command = fr"""cd {shlex.quote(os.getcwd())} &&
	DRGN_RUN_LINUX_HELPER_TESTS=1 {shlex.quote(sys.executable)} -Bm \
		unittest discover -t . -s tests/helpers/linux {"-v" if self.verbose else ""}"""
        command = vmtest.vm.install_vmlinux_precommand(command, vmlinux)
        try:
            returncode = vmtest.vm.run_in_vm(
                command, vmlinuz=vmlinuz, build_dir=build_dir
            )
        except vmtest.vm.LostVMError as e:
            self.announce(f"error: {e}", log.ERROR)
            return False
        self.announce(f"Tests in VM returned {returncode}", log.INFO)
        return returncode == 0

    def run(self):
        import vmtest.resolver

        # Start downloads ASAP so that they're hopefully done by the time we
        # need them.
        with vmtest.resolver.KernelResolver(self.kernels, self.vmtest_dir) as resolver:
            if self.kernels:
                self.announce(
                    "downloading/preparing kernels in the background", log.INFO
                )
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
                for kernel in resolver:
                    self.announce(
                        f"running tests in VM on Linux {kernel.release}", log.INFO
                    )
                    if self._run_vm(
                        vmlinux=kernel.vmlinux,
                        vmlinuz=kernel.vmlinuz,
                        build_dir=self.vmtest_dir,
                    ):
                        passed.append(kernel.release)
                    else:
                        failed.append(kernel.release)

                if passed:
                    self.announce(f'Passed: {", ".join(passed)}', log.INFO)
                if failed:
                    self.announce(f'Failed: {", ".join(failed)}', log.ERROR)

        if failed:
            raise DistutilsError("some tests failed")
        else:
            self.announce("all tests passed", log.INFO)


def get_version():
    if not os.path.exists(".git"):
        # If this is a source distribution, get the version from the egg
        # metadata.
        return pkg_resources.get_distribution("drgn").version

    with open("libdrgn/configure.ac", "r") as f:
        version = re.search(r"AC_INIT\(\[drgn\], \[([^]]*)\]", f.read()).group(1)

    # Read the Docs modifies the working tree (namely, docs/conf.py). We don't
    # want the documentation to display a dirty version, so ignore
    # modifications for RTD builds.
    dirty = os.getenv("READTHEDOCS") != "True" and bool(
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
    version += f"+{count}.g{commit}"
    if dirty:
        version += ".dirty"
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
        "test": test,
    },
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
