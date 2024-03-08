# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import array
import contextlib
import ctypes
import errno
import io
import mmap
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest

from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import (
    CLONE_NEWNS,
    CLONE_NEWUSER,
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    LinuxKernelTestCase,
    fork_and_stop,
    iter_mounts,
    losetup,
    mkswap,
    mount,
    perf_event_attr,
    perf_event_open,
    skip_unless_have_test_disk,
    swapoff,
    swapon,
    umount,
    unshare,
)
from tools.fsrefs import main

UPROBE_TYPE_PATH = Path("/sys/bus/event_source/devices/uprobe/type")


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
        with fork_and_stop(mkdir_and_chdir, path, 0o600) as (pid, _):
            self.assertRegex(
                self.run_and_capture("--check", "tasks", "--inode", str(path)),
                rf"pid {pid} \(.*\) cwd ",
            )

    def test_root(self):
        def mkdir_and_chroot(path, mode):
            os.mkdir(path, mode)
            os.chroot(path)

        path = self._tmp / "dir"
        with fork_and_stop(mkdir_and_chroot, path, 0o600) as (pid, _):
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

            pid, _ = exit_stack.enter_context(fork_and_stop(unshare, CLONE_NEWNS))

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
                    return "kernel does not support user namespaces (CONFIG_USER_NS)"
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
                    return "kernel does not support binfmt_misc (CONFIG_BINFMT_MISC)"
                elif e.errno == errno.EPERM:
                    return "kernel does not support sandboxed binfmt_misc mounts"
                else:
                    raise

            path.touch()
            path.chmod(0o700)
            encoded_id = "".join([f"\\x{byte:02x}" for byte in id])
            (mount_point / "register").write_text(f":{name}:M::{encoded_id}::{path}:F")

        path = self._tmp / "file"
        with fork_and_stop(setup_binfmt_misc_in_userns, path) as (pid, skip):
            if skip:
                self.skipTest(skip)
            ino = Path(f"/proc/{pid}/ns/user").stat().st_ino
            self.assertIn(
                f"binfmt_misc (user namespace {ino}) {name} ",
                self.run_and_capture("--check", "binfmt_misc", "--inode", str(path)),
            )

    def test_loop_device(self):
        path = self._tmp / "file"
        with open(path, "wb") as f:
            os.ftruncate(f.fileno(), 1024 * 1024)
            with losetup(f.fileno()) as loop_file:
                f.close()
                number = int(loop_file.name.replace("/dev/loop", ""))
                self.assertIn(
                    f"loop device {number} ",
                    self.run_and_capture("--check", "loop", "--inode", str(path)),
                )

    @skip_unless_have_test_disk
    def test_swap_file(self):
        disk = os.environ["DRGN_TEST_DISK"]
        subprocess.check_call(["mke2fs", "-qF", disk])

        with contextlib.ExitStack() as exit_stack:
            mount(disk, self._tmp, "ext2")
            exit_stack.callback(umount, self._tmp)

            path = self._tmp / "swap_file"
            mkswap(path, 1024 * 1024)
            swapon(path)
            exit_stack.callback(swapoff, path)

            self.assertIn(
                "swap file (struct swap_info_struct *)",
                self.run_and_capture("--check", "swap", "--inode", str(path)),
            )

    def test_uprobe_event(self):
        for mnt in iter_mounts():
            if mnt.fstype == "tracefs":
                break
        else:
            self.skipTest("tracefs not mounted")
        uprobe_events = mnt.mount_point / "uprobe_events"
        if not uprobe_events.exists():
            self.skipTest(
                "kernel does not support uprobe events (CONFIG_UPROBE_EVENTS)"
            )

        def uprobe_events_append(s):
            # open(..., "a") tries lseek(..., SEEK_END), which fails with
            # EINVAL.
            with open(os.open(uprobe_events, os.O_WRONLY | os.O_APPEND), "w") as f:
                f.write(s)

        path = self._tmp / "file"
        path.touch()

        probe_name = f"drgntest_{os.urandom(20).hex()}"
        retprobe_name = f"drgntest_{os.urandom(20).hex()}"
        with contextlib.ExitStack() as exit_stack:
            uprobe_events_append(f"p:{probe_name} {path}:0\n")
            exit_stack.callback(uprobe_events_append, f"-:{probe_name}\n")
            uprobe_events_append(f"r:{retprobe_name} {path}:0\n")
            exit_stack.callback(uprobe_events_append, f"-:{retprobe_name}\n")

            instance = Path(tempfile.mkdtemp(dir=mnt.mount_point / "instances"))
            exit_stack.callback(instance.rmdir)

            (instance / "events/uprobes" / probe_name / "enable").write_text("1")
            (instance / "events/uprobes" / retprobe_name / "enable").write_text("1")

            output = self.run_and_capture("--check", "uprobes", "--inode", str(path))
            self.assertIn(f"uprobe event p:uprobes/{probe_name} ", output)
            self.assertIn(f"uprobe event r:uprobes/{retprobe_name} ", output)

    @unittest.skipUnless(
        UPROBE_TYPE_PATH.exists(), "kernel does not support perf_uprobe"
    )
    def test_perf_uprobe(self):
        path = self._tmp / "file"
        path.touch()

        attr = perf_event_attr()
        attr.type = int(UPROBE_TYPE_PATH.read_text())
        ctypes_path = ctypes.c_char_p(os.fsencode(path))
        attr.uprobe_path = ctypes.cast(ctypes_path, ctypes.c_void_p).value
        fd = perf_event_open(attr, -1, min(os.sched_getaffinity(0)))
        try:
            self.assertIn(
                f"perf uprobe (owned by pid {os.getpid()}",
                self.run_and_capture("--check", "uprobes", "--inode", str(path)),
            )
        finally:
            os.close(fd)

    @unittest.skipUnless(
        UPROBE_TYPE_PATH.exists(), "kernel does not support perf_uprobe"
    )
    def test_perf_uprobe_no_owner(self):
        path = self._tmp / "file"
        path.touch()

        sock1, sock2 = socket.socketpair()
        try:
            # Create a perf event in a process, send it over a Unix socket to
            # keep it alive, then die.
            pid = os.fork()
            if pid == 0:
                try:
                    attr = perf_event_attr()
                    attr.type = int(UPROBE_TYPE_PATH.read_text())
                    ctypes_path = ctypes.c_char_p(os.fsencode(path))
                    attr.uprobe_path = ctypes.cast(ctypes_path, ctypes.c_void_p).value
                    fd = perf_event_open(attr, -1, min(os.sched_getaffinity(0)))
                    sock2.sendmsg(
                        [b"\0"],
                        [
                            (
                                socket.SOL_SOCKET,
                                socket.SCM_RIGHTS,
                                array.array("i", [fd]),
                            )
                        ],
                    )
                finally:
                    os._exit(0)

            os.waitpid(pid, 0)
            self.assertIn(
                "perf uprobe (no owner)",
                self.run_and_capture("--check", "uprobes", "--inode", str(path)),
            )
        finally:
            sock1.close()
            sock2.close()
