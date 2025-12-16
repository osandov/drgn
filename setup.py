#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import logging
import os
import os.path
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import sysconfig

from setuptools import Command, find_packages, setup
from setuptools.command.build_ext import build_ext as _build_ext
from setuptools.command.egg_info import egg_info as _egg_info
from setuptools.command.sdist import sdist as _sdist
from setuptools.extension import Extension

# setuptools must be imported before distutils (see pypa/setuptools#2230), so
# make sure to keep these fallbacks after the other setuptools imports.
try:
    # This was added in setuptools 62.4.0 (released June 13th, 2022).
    from setuptools.command.build import build as _build
except ImportError:
    from distutils.command.build import build as _build
try:
    # This was added in setuptools 59.0.0 (released November 12th, 2021).
    from setuptools.errors import BaseError
except ImportError:
    from distutils.errors import DistutilsError as BaseError

from util import nproc, out_of_date
from vmtest.config import KERNEL_FLAVORS, SUPPORTED_KERNEL_VERSIONS

logger = logging.getLogger(__name__)


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

    def finalize_options(self):
        default_build_temp = self.build_temp is None
        super().finalize_options()
        if default_build_temp and sysconfig.get_config_var("Py_GIL_DISABLED"):
            # Python 3.13's free-threading builds are not ABI compatible with
            # the standard ones, but sys.implementation.cache_tag, which
            # distutils uses to set the default temporary directory, is not
            # different. This means that the build_temp directory is shared
            # between these two builds. Since drgn's build_ext allows
            # incremental builds, this means that build artifacts can be
            # mistakenly shared between builds, causing runtime errors. To avoid
            # this, add a "t" suffix for free-threading builds. This isn't
            # necessary for the build_lib directory, since the final build
            # product does include the "t" in its filename.
            self.build_temp += "t"

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
        self.mkpath(self.build_temp)
        makefile = os.path.join(self.build_temp, "Makefile")
        if not os.path.exists(makefile):
            args = [
                os.path.relpath("libdrgn/configure", self.build_temp),
                "--disable-static",
                "--disable-libdrgn",
                "--enable-python-extension",
            ]
            try:
                args.extend(shlex.split(os.environ["CONFIGURE_FLAGS"]))
            except KeyError:
                pass
            try:
                subprocess.check_call(
                    args,
                    cwd=self.build_temp,
                    env={**os.environ, "PYTHON": sys.executable},
                )
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
            self.copy_file(so, self.get_ext_fullpath("_drgn"))
        old_inplace, self.inplace = self.inplace, 0
        build_path = self.get_ext_fullpath("_drgn")
        self.mkpath(os.path.dirname(build_path))
        self.copy_file(so, build_path)
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

    user_options = [
        (
            "kernel",
            "K",
            "run Linux kernel tests in a virtual machine on all supported kernels "
            f"({', '.join(SUPPORTED_KERNEL_VERSIONS)})",
        ),
        (
            "flavor=",
            "f",
            "when combined with -K, run Linux kernel tests on a specific flavor "
            f"({', '.join(KERNEL_FLAVORS)}) instead of the default flavor",
        ),
        (
            "all-kernel-flavors",
            "F",
            "when combined with -K, run Linux kernel tests on all supported flavors "
            f"({', '.join(KERNEL_FLAVORS)}) instead of just the default flavor",
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
        self.flavor = "default"
        self.all_kernel_flavors = False
        self.extra_kernels = ""
        self.vmtest_dir = None

    def finalize_options(self):
        self.kernels = [kernel for kernel in self.extra_kernels.split(",") if kernel]
        if self.kernel:
            flavors = KERNEL_FLAVORS if self.all_kernel_flavors else [self.flavor]
            self.kernels.extend(
                kernel + ".*" + flavor
                for kernel in SUPPORTED_KERNEL_VERSIONS
                for flavor in flavors
            )
        if self.vmtest_dir is None:
            build_base = self.get_finalized_command("build").build_base
            self.vmtest_dir = os.path.join(build_base, "vmtest")

    def _run_local(self):
        import unittest

        try:
            self.get_finalized_command("build_ext").make("check")
            make_check_success = True
        except subprocess.CalledProcessError:
            make_check_success = False

        argv = ["discover"]
        if self.verbose:
            argv.append("-v")
        test = unittest.main(module=None, argv=argv, exit=False)
        return make_check_success and test.result.wasSuccessful()

    def _run_vm(self, kernel):
        import vmtest.vm

        logger.info("running tests in VM on Linux %s", kernel.release)

        command = rf"""
set -e

export PYTHON={shlex.quote(sys.executable)}
if [ -e /proc/vmcore ]; then
    "$PYTHON" -Bm unittest discover -t . -s tests/linux_kernel/vmcore {"-v" if self.verbose else ""}
else
    insmod "$DRGN_TEST_KMOD"
    DRGN_RUN_LINUX_KERNEL_TESTS=1 "$PYTHON" -Bm \
        unittest discover -t . -s tests/linux_kernel {"-v" if self.verbose else ""}
    "$PYTHON" -Bm vmtest.enter_kdump
    # We should crash and not reach this.
    exit 1
fi
"""
        try:
            returncode = vmtest.vm.run_in_vm(
                command,
                kernel,
                Path("/"),
                Path(self.vmtest_dir),
                test_kmod=vmtest.vm.TestKmodMode.BUILD,
            )
        except vmtest.vm.LostVMError:
            logger.exception("error on Linux %s", kernel.release)
            return False
        logger.info("Tests in VM on Linux %s returned %d", kernel.release, returncode)
        return returncode == 0

    def run(self):
        import urllib.error

        from vmtest.config import ARCHITECTURES, Kernel, local_kernel
        from vmtest.download import DownloadCompiler, DownloadKernel, download_in_thread

        in_github_actions = os.getenv("GITHUB_ACTIONS") == "true"

        if in_github_actions:

            @contextlib.contextmanager
            def github_workflow_group(title):
                sys.stdout.flush()
                print("::group::" + title, file=sys.stderr, flush=True)
                try:
                    yield
                finally:
                    sys.stdout.flush()
                    print("::endgroup::", file=sys.stderr, flush=True)

        else:

            @contextlib.contextmanager
            def github_workflow_group(title):
                yield

        # Start downloads ASAP so that they're hopefully done by the time we
        # need them.
        try:
            to_download = []
            if self.kernels:
                to_download.append(DownloadCompiler(ARCHITECTURES["x86_64"]))
                for pattern in self.kernels:
                    if not pattern.startswith(".") and not pattern.startswith("/"):
                        to_download.append(
                            DownloadKernel(ARCHITECTURES["x86_64"], pattern)
                        )

            # Downloading too many files before they can be used for testing runs the
            # risk of filling up the limited disk space is Github Actions. Set a limit
            # of no more than 5 files which can be downloaded ahead of time. This is a
            # magic number which is inexact, but works well enough.
            max_pending_kernels = 5 if in_github_actions else 0

            with download_in_thread(
                Path(self.vmtest_dir), to_download, max_pending_kernels
            ) as downloads:
                downloads_it = iter(downloads)

                if to_download:
                    logger.info("downloading kernels in the background")

                with github_workflow_group("Build extension"):
                    self.run_command("egg_info")
                    self.reinitialize_command("build_ext", inplace=1)
                    self.run_command("build_ext")

                passed = []
                failed = []

                with github_workflow_group("Run unit tests"):
                    if self.kernels:
                        logger.info("running tests locally")
                    if self._run_local():
                        passed.append("local")
                    else:
                        failed.append("local")

                for pattern in self.kernels:
                    if pattern.startswith(".") or pattern.startswith("/"):
                        kernel = local_kernel(ARCHITECTURES["x86_64"], Path(pattern))
                    else:
                        while True:
                            kernel = next(downloads_it)
                            if isinstance(kernel, Kernel):
                                break
                    with github_workflow_group(
                        f"Run integration tests on Linux {kernel.release}"
                    ):
                        if self._run_vm(kernel):
                            passed.append(kernel.release)
                        else:
                            failed.append(kernel.release)

                    if passed:
                        logger.info("Passed: %s", ", ".join(passed))
                    if failed:
                        logger.error("Failed: %s", ", ".join(failed))

                    # Github Actions has limited disk space. Once tested, we
                    # will not use the kernel again, so delete it.
                    if in_github_actions:
                        logger.info("Deleting kernel %s", kernel.release)
                        shutil.rmtree(kernel.path)
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(e, file=sys.stderr)
                print("Headers:", e.headers, file=sys.stderr)
                print("Body:", e.read().decode(), file=sys.stderr)
            raise

        if failed:
            raise BaseError("some tests failed")
        else:
            logger.info("all tests passed")


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
    if os.path.exists(".git") and (
        subprocess.call(
            ["git", "--git-dir=.git", "rev-parse"], stderr=subprocess.DEVNULL
        )
        == 0
    ):
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
            logger.warning("warning: v%s tag not found", public_version)
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
            logger.warning("warning: drgn/internal/version.py not found")
        else:
            # The saved version must start with the public version.
            match = re.search(
                rf'^__version__ = "{re.escape(public_version)}([^"]*)"$',
                version_py,
                re.M,
            )
            if match:
                local_version = match.group(1)
            else:
                logger.warning("warning: drgn/internal/version.py is invalid")

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
    packages=find_packages(include=["drgn", "drgn.*", "_drgn_util", "_drgn_util.*"]),
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
    entry_points={
        "console_scripts": [
            "drgn=drgn.cli:_main",
            "drgn-crash=drgn.internal.crashcli:_main",
        ],
        "drgn.plugins": ["builtin_commands=drgn.commands._builtin"],
    },
    python_requires=">=3.8",
    author="Omar Sandoval",
    author_email="osandov@osandov.com",
    description="Programmable debugger",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/osandov/drgn",
    project_urls={
        "Bug Tracker": "https://github.com/osandov/drgn/issues",
        "Documentation": "https://drgn.readthedocs.io",
    },
    license="LGPL-2.1-or-later",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Debuggers",
        "Topic :: System :: Operating System Kernels :: Linux",
    ],
)
