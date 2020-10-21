#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import base64
import contextlib
import hashlib
import io
import itertools
import os
import os.path
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import sysconfig
import tarfile
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import zipfile

from util import nproc, out_of_date


# TODO: might be better way to represent these.
_SOURCES = (
    (Path("_drgn.pyi"), None),
    (Path("drgn"), r".*\.py"),
    (Path("drgn", "py.typed"), None),
)

_DIST = (
    (Path("build.py"), None),
    (Path("docs"), r".*\.(py|rst)"),
    (Path("examples"), r".*\.py"),
    (Path("pyproject.toml"), None),
    (Path("tests"), r".*\.py"),
    (Path("tools"), r".*\.py"),
    (Path("vmtest"), r".*\.(c|py|rst)"),
    (Path("vmtest", "config"), None),
)


def _get_version() -> Tuple[str, str]:
    version_py: Optional[str]
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
            print(f"warning: v{public_version} tag not found", file=sys.stderr)
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
            print("warning: drgn/internal/version.py not found", file=sys.stderr)
        else:
            # The saved version must start with the public version.
            match = re.search(
                fr'^version = "{re.escape(public_version)}([^"]*)"$', version_py, re.M
            )
            if match:
                local_version = match.group(1)
            else:
                print("warning: drgn/internal/version.py is invalid", file=sys.stderr)

    # Update version.py if necessary.
    new_version_py = f'version = "{public_version}{local_version}"\n'
    if new_version_py != version_py:
        with open("drgn/internal/version.py", "w") as f:
            f.write(new_version_py)
    return public_version, local_version


class _Config:
    def __init__(self, config_settings: Optional[Dict[str, str]] = None) -> None:
        # TODO: temp. for consistency with setuptools?
        self.build_dir = Path(
            "build", f"{sysconfig.get_platform()}-{sysconfig.get_python_version()}"
        )
        self.jobs = nproc() + 1

    def wheel_tag(self) -> str:
        python_tag = "cp" + sysconfig.get_config_var("py_version_nodot")
        abi_tag = python_tag + sysconfig.get_config_var("abiflags")
        platform_tag = sysconfig.get_platform()
        return "-".join(
            [
                re.sub(r"[^\w\d.]+", "_", s, re.UNICODE)
                for s in (python_tag, abi_tag, platform_tag)
            ]
        )

    def ext_name(self, name: str) -> str:
        return name + sysconfig.get_config_var("EXT_SUFFIX")


def _run_autoreconf(dir: Path) -> None:
    configure = dir / "configure"
    configure_ac = dir / "configure.ac"
    makefile_am = dir / "Makefile.am"
    makefile_in = dir / "Makefile.in"
    if out_of_date(makefile_in, makefile_am, configure_ac) or out_of_date(
        configure, configure_ac
    ):
        try:
            subprocess.check_call(["autoreconf", "-i", dir])
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                configure.unlink()
            with contextlib.suppress(FileNotFoundError):
                makefile_in.unlink()
            raise


def _run_configure(source_dir: Path, build_dir: Path) -> None:
    makefile = build_dir / "Makefile"
    if not makefile.exists():
        args = [
            # Path.relative_to() only works for subpaths.
            os.path.relpath(source_dir / "configure", build_dir),
            "--disable-static",
            "--with-python=" + sys.executable,
        ]
        try:
            args.extend(shlex.split(os.environ["CONFIGURE_FLAGS"]))
        except KeyError:
            pass
        try:
            subprocess.check_call(args, cwd=build_dir)
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                makefile.unlink()
            raise


def _build(config: _Config) -> None:
    libdrgn_dir = Path("libdrgn")
    _run_autoreconf(libdrgn_dir)
    _run_autoreconf(libdrgn_dir / "elfutils")
    config.build_dir.mkdir(parents=True, exist_ok=True)
    _run_configure(libdrgn_dir, config.build_dir)
    subprocess.check_call(["make", "-C", config.build_dir, "-j", str(config.jobs)])


class _ArchiveWriter:
    def __init__(self, path: Path, format: str) -> None:
        if format == "tar.gz":
            self._tar = tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT)
            self._is_tar = True
        elif format == "zip":
            self._zip = zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED)
            self._is_tar = False
        else:
            raise ValueError("format must be tar.gz or zip")
        self.record: List[Tuple[Path, bytes, int]] = []

    def close(self) -> None:
        if self._is_tar:
            self._tar.close()
        else:
            self._zip.close()

    def __enter__(self) -> "_ArchiveWriter":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()

    def writepath(
        self,
        path: Path,
        arcpath: Optional[Path] = None,
        pattern: Optional[str] = None,
        *,
        record: bool = False,
    ) -> None:
        members = []

        def visit(subpath: str, is_file: bool, recurse: bool) -> bool:
            include = pattern is None or bool(re.fullmatch(pattern, subpath))
            if recurse:
                for entry in os.scandir(path / subpath):
                    if (
                        visit(
                            os.path.join(subpath, entry.name),
                            entry.is_file(follow_symlinks=False),
                            entry.is_dir(follow_symlinks=False),
                        )
                        and self._is_tar
                    ):
                        include = True
            if include:
                members.append((subpath, is_file))
            return include

        st = path.lstat()
        visit(
            "",
            stat.S_ISREG(st.st_mode),
            (pattern is not None) and stat.S_ISDIR(st.st_mode),
        )
        members.sort()

        if arcpath is None:
            arcpath = path
        for subpath, is_file in members:
            file_path = path / subpath
            if self._is_tar:
                self._tar.add(file_path, arcpath / subpath, recursive=False)
            else:
                self._zip.write(file_path, arcpath / subpath)
            # TODO: what about directories?
            if is_file and record:
                h = hashlib.sha256()
                n = 0
                with open(file_path, "rb") as f:
                    while True:
                        data = f.read(131072)
                        if not data:
                            break
                        h.update(data)
                        n += len(data)
                self.record.append((file_path, h.digest(), n))

    def writestr(
        self, arcpath: Path, data: Union[bytes, str], *, record: bool = False
    ) -> None:
        if isinstance(data, str):
            data = data.encode()
        if self._is_tar:
            tarinfo = tarfile.TarInfo(str(arcpath))
            tarinfo.size = len(data)
            tarinfo.mtime = time.time()
            tarinfo.mode = 0o644
            tarinfo.type = tarfile.REGTYPE
            tarinfo.uid = os.geteuid()
            tarinfo.gid = os.getegid()
            self._tar.addfile(tarinfo, io.BytesIO(data))
        else:
            self._zip.writestr(str(arcpath), data)
        if record:
            h = hashlib.sha256()
            h.update(data)
            self.record.append((arcpath, h.digest(), len(data)))


def _pkg_info(version: str) -> str:
    with open("README.rst", "r") as f:
        readme = f.read()
    return f"""Metadata-Version: 2.1
Name: drgn
Version: {version}
Summary: Scriptable debugger library
Home-page: https://github.com/osandov/drgn
Author: Omar Sandoval
Author-email: osandov@osandov.com
License: GPL-3.0+
Project-URL: Bug Tracker, https://github.com/osandov/drgn/issues
Project-URL: Documentation, https://drgn.readthedocs.io
Platform: UNKNOWN
Classifier: Development Status :: 3 - Alpha
Classifier: Environment :: Console
Classifier: Intended Audience :: Developers
Classifier: License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)
Classifier: Operating System :: POSIX :: Linux
Classifier: Programming Language :: Python :: 3
Classifier: Topic :: Software Development :: Debuggers
Requires-Python: >=3.6
Description-Content-Type: text/x-rst

{readme}"""


# TODO: raise UnsupportedOperation exception when appropriate.
def build_sdist(
    sdist_directory: str, config_settings: Optional[Dict[str, str]] = None
) -> str:
    config = _Config(config_settings)
    # elfutils needs to be built before it can be packaged >:(
    _build(config)

    public_version, local_version = _get_version()
    version = public_version + local_version
    dist_version = f"drgn-{version}"

    sdist = Path(sdist_directory) / (dist_version + ".tar.gz")
    # TODO: am I supposed to do this?
    sdist.parent.mkdir(parents=True, exist_ok=True)
    success = False
    try:
        with _ArchiveWriter(sdist, "tar.gz") as archive:
            for path, pattern in itertools.chain(_SOURCES, _DIST):
                archive.writepath(path, dist_version / path, pattern)

            libdrgn_dist = config.build_dir / f"libdrgn-{public_version}.tar.gz"
            try:
                subprocess.check_call(
                    ["make", "-C", config.build_dir, "-j", str(config.jobs), "dist"]
                )
                with tarfile.open(libdrgn_dist, "r") as libdrgn_tar:
                    for member in libdrgn_tar:
                        f = libdrgn_tar.extractfile(member) if member.isreg() else None
                        try:
                            member.name = os.path.join(
                                dist_version,
                                "libdrgn",
                                member.name[member.name.index("/") + 1 :],
                            )
                        except ValueError:
                            member.name = os.path.join(dist_version, "libdrgn")
                        # TODO: add a proper method for this?
                        archive._tar.addfile(member, f)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    libdrgn_dist.unlink()

            archive.writestr(Path(dist_version) / "PKG-INFO", _pkg_info(version))
        success = True
    finally:
        if not success:
            with contextlib.suppress(FileNotFoundError):
                sdist.unlink()
    return str(sdist)


def build_wheel(
    wheel_directory: str,
    config_settings: Optional[Dict[str, str]] = None,
    metadata_directory: Optional[str] = None,
) -> str:
    config = _Config(config_settings)
    _build(config)

    public_version, local_version = _get_version()
    version = public_version + local_version
    dist_version = f"drgn-{version}"

    tag = config.wheel_tag()
    wheel = Path(wheel_directory) / f"{dist_version}-{tag}.whl"
    success = False
    try:
        # TODO: am I supposed to do this?
        wheel.parent.mkdir(parents=True, exist_ok=True)
        with _ArchiveWriter(wheel, "zip") as archive:
            archive.writepath(
                config.build_dir / ".libs" / "_drgn.so",
                Path(config.ext_name("_drgn")),
                record=True,
            )
            for path, pattern in _SOURCES:
                archive.writepath(path, None, pattern, record=True)

            dist_info = Path(dist_version + ".dist-info")
            archive.writepath(Path("COPYING"), dist_info / "COPYING", record=True)
            archive.writestr(dist_info / "METADATA", _pkg_info(version), record=True)
            archive.writestr(
                dist_info / "WHEEL",
                f"""Wheel-Version: 1.0
Generator: drgn
Root-Is-Purelib: false
Tag: {tag}

""",
                record=True,
            )
            archive.writestr(
                dist_info / "entry_points.txt",
                """[console_scripts]
drgn = drgn.internal.cli:main

""",
                record=True,
            )
            archive.writestr(dist_info / "top_level.txt", "_drgn\ndrgn\n", record=True)

            record_path = dist_info / "RECORD"
            record_lines = []
            for path, digest, size in archive.record:
                encoded_digest = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                record_lines.append(f"{path},sha256={encoded_digest},{size}\n")
            record_lines.append(f"{record_path},,")
            archive.writestr(record_path, "".join(record_lines))
            success = True
    finally:
        if not success:
            with contextlib.suppress(FileNotFoundError):
                wheel.unlink()
    return str(wheel)


def build_local() -> None:
    config = _Config()
    _build(config)
    shutil.copy(config.build_dir / ".libs" / "_drgn.so", config.ext_name("_drgn"))


if __name__ == "__main__":
    # TODO: proper CLI with commands like:
    # ./build.py local
    # ./build.py sdist
    # ./build.py wheel
    # ./build.py manylinux
    build_local()
