# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import ctypes
import errno
import io
import mmap
import os
from pathlib import Path
import re
import sys
import tempfile

from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import (
    CLONE_NEWNS,
    CLONE_NEWUSER,
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    LinuxKernelTestCase,
    fork_and_call,
    fork_and_sigwait,
    iter_mounts,
    mount,
    umount,
    unshare,
)
from tools.fsrefs import main


class TestFsRefs(LinuxKernelTestCase):
    def setUp(self):
        super().setUp()
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)

    def tearDown(self):
        try:
            tmpdir = self._tmpdir
        except AttributeError:
            pass
        else:
            tmpdir.cleanup()
        super().tearDown()

    def run_and_capture(self, *args):
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            main(self.prog, args)
        return f.getvalue()

    def test_fd(self):
        path = self._tmp / "file"
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            self.assertRegex(
                self.run_and_capture("--check", "tasks", "--inode", str(path)),
                rf"pid {os.getpid()} \(.*\) fd {fd} ",
            )
        finally:
            os.close(fd)

    def test_dereference(self):
        file = self._tmp / "file"
        link = self._tmp / "link"
        file.touch()
        link.symlink_to("file")

        file_fd = os.open(file, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            link_fd = os.open(link, os.O_PATH | os.O_NOFOLLOW)
            try:
                output = self.run_and_capture("--check", "tasks", "--inode", str(link))
                self.assertNotRegex(
                    output,
                    rf"pid {os.getpid()} \(.*\) fd {file_fd} ",
                )
                self.assertRegex(
                    output,
                    rf"pid {os.getpid()} \(.*\) fd {link_fd} ",
                )

                output = self.run_and_capture(
                    "--check", "tasks", "--inode", str(link), "--dereference"
                )
                self.assertRegex(
                    output,
                    rf"pid {os.getpid()} \(.*\) fd {file_fd} ",
                )
                self.assertNotRegex(
                    output,
                    rf"pid {os.getpid()} \(.*\) fd {link_fd} ",
                )
            finally:
                os.close(link_fd)
        finally:
            os.close(file_fd)

    def test_cwd(self):
        def mkdir_and_chdir(path, mode):
            os.mkdir(path, mode)
            os.chdir(path)

        path = self._tmp / "dir"
        with fork_and_sigwait(mkdir_and_chdir, path, 0o600) as pid:
            self.assertRegex(
                self.run_and_capture("--check", "tasks", "--inode", str(path)),
                rf"pid {pid} \(.*\) cwd ",
            )

    def test_root(self):
        def mkdir_and_chroot(path, mode):
            os.mkdir(path, mode)
            os.chroot(path)

        path = self._tmp / "dir"
        with fork_and_sigwait(mkdir_and_chroot, path, 0o600) as pid:
            self.assertRegex(
                self.run_and_capture("--check", "tasks", "--inode", str(path)),
                rf"pid {pid} \(.*\) root ",
            )

    def test_exe(self):
        self.assertRegex(
            self.run_and_capture(
                "--check", "tasks", "--inode", sys.executable, "--dereference"
            ),
            rf"pid {os.getpid()} \(.*\) exe ",
        )

    def test_vma(self):
        path = self._tmp / "file"
        with open(path, "w+b") as f:
            os.ftruncate(f.fileno(), mmap.PAGESIZE)
            # Note: this dups the file descriptor internally.
            with mmap.mmap(f.fileno(), mmap.PAGESIZE) as map:
                f.close()
                start = ctypes.addressof(ctypes.c_char.from_buffer(map))
                end = start + mmap.PAGESIZE
                self.assertRegex(
                    self.run_and_capture("--check", "tasks", "--inode", str(path)),
                    rf"pid {os.getpid()} \(.*\) vma {hex(start)}-{hex(end)} ",
                )

    def test_inode_pointer(self):
        self.assertRegex(
            self.run_and_capture(
                "--check",
                "tasks",
                "--inode-pointer",
                hex(find_task(self.prog, os.getpid()).mm.exe_file.f_inode),
                "--dereference",
            ),
            rf"pid {os.getpid()} \(.*\) exe ",
        )

    def test_super_block(self):
        with contextlib.ExitStack() as exit_stack:
            mount("tmpfs", self._tmp, "tmpfs")
            exit_stack.callback(umount, self._tmp)

            pid = exit_stack.enter_context(fork_and_sigwait(unshare, CLONE_NEWNS))

            path1 = self._tmp / "file1"
            fd1 = os.open(path1, os.O_CREAT | os.O_WRONLY, 0o600)
            exit_stack.callback(os.close, fd1)

            path2 = self._tmp / "file2"
            fd2 = os.open(path2, os.O_CREAT | os.O_WRONLY, 0o600)
            exit_stack.callback(os.close, fd2)

            output = self.run_and_capture(
                "--check", "mounts", "--check", "tasks", "--super-block", str(self._tmp)
            )

            with self.subTest("mount"):
                self.assertIn(f"mount {self._tmp} (struct mount", output)

            with self.subTest("mount in namespace"):
                ino = Path(f"/proc/{pid}/ns/mnt").stat().st_ino
                self.assertIn(f"mount {self._tmp} (mount namespace {ino}) ", output)

            with self.subTest("fd"):
                self.assertRegex(
                    output,
                    rf"pid {os.getpid()} \(.*\) fd {fd1} \(struct file \*\)0x[0-9a-f]+ {re.escape(str(path1))}",
                )
                self.assertRegex(
                    output,
                    rf"pid {os.getpid()} \(.*\) fd {fd2} \(struct file \*\)0x[0-9a-f]+ {re.escape(str(path2))}",
                )

            with self.subTest("super_block_pointer"):
                self.assertIn(
                    f"mount {self._tmp} ",
                    self.run_and_capture(
                        "--check",
                        "mounts",
                        "--super-block-pointer",
                        hex(fget(find_task(self.prog, os.getpid()), fd1).f_inode.i_sb),
                    ),
                )

    def test_binfmt_misc(self):
        for mnt in iter_mounts():
            if mnt.fstype == "binfmt_misc":
                break
        else:
            self.skipTest("binfmt_misc not mounted")

        path = self._tmp / "file"
        path.touch()
        path.chmod(0o700)
        try:
            id = os.urandom(20)
            name = f"drgntest_{id.hex()}"
            encoded_id = "".join([f"\\x{byte:02x}" for byte in id])
            (mnt.mount_point / "register").write_text(
                f":{name}:M::{encoded_id}::{path}:F"
            )

            self.assertIn(
                f"binfmt_misc {name} ",
                self.run_and_capture("--check", "binfmt_misc", "--inode", str(path)),
            )
        finally:
            try:
                with open(mnt.mount_point / name, "r+") as f:
                    f.write("-1")
            except FileNotFoundError:
                pass

    def test_binfmt_misc_in_user_ns(self):
        id = os.urandom(20)
        name = f"drgntest_{id.hex()}"

        def setup_binfmt_misc_in_userns(path):
            try:
                unshare(CLONE_NEWUSER | CLONE_NEWNS)
            except OSError as e:
                if e.errno == errno.EINVAL:
                    return "kernel does not support user namespaces"
                else:
                    raise
            Path("/proc/self/uid_map").write_text("0 0 1")
            Path("/proc/self/setgroups").write_text("deny")
            Path("/proc/self/gid_map").write_text("0 0 1")

            mount_point = path.parent / "binfmt_misc"
            mount_point.mkdir()
            try:
                mount(
                    "binfmt_misc",
                    mount_point,
                    "binfmt_misc",
                    MS_NOSUID | MS_NODEV | MS_NOEXEC,
                )
            except OSError as e:
                if e.errno == errno.ENODEV:
                    return "kernel does not support binfmt_misc"
                elif e.errno == errno.EPERM:
                    return "kernel does not support sandboxed binfmt_misc mounts"
                else:
                    raise

            path.touch()
            path.chmod(0o700)
            encoded_id = "".join([f"\\x{byte:02x}" for byte in id])
            (mount_point / "register").write_text(f":{name}:M::{encoded_id}::{path}:F")

        path = self._tmp / "file"
        with fork_and_call(setup_binfmt_misc_in_userns, path) as (pid, skip):
            if skip:
                self.skipTest(skip)
            ino = Path(f"/proc/{pid}/ns/user").stat().st_ino
            self.assertIn(
                f"binfmt_misc (user namespace {ino}) {name} ",
                self.run_and_capture("--check", "binfmt_misc", "--inode", str(path)),
            )
