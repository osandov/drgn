import ctypes
import errno
import os
import re
import signal
import socket
import time
import unittest

import drgn


class LinuxHelperTestCase(unittest.TestCase):
    prog = None
    skip_reason = None

    def setUp(self):
        # We only want to create the Program once, so it's cached as a class
        # variable. If we can't run these tests for whatever reason, we also
        # cache that.
        if LinuxHelperTestCase.prog is not None:
            return
        if LinuxHelperTestCase.skip_reason is None:
            try:
                run_tests = int(os.environ['DRGN_RUN_LINUX_HELPER_TESTS']) != 0
            except (KeyError, ValueError):
                run_tests = True
                force_run = False
            else:
                force_run = run_tests
            if not run_tests:
                LinuxHelperTestCase.skip_reason = 'env DRGN_RUN_LINUX_HELPER_TESTS=0'
            elif not force_run and os.geteuid() != 0:
                LinuxHelperTestCase.skip_reason = (
                    'Linux helper tests must be run as root '
                    '(run with env DRGN_RUN_LINUX_HELPER_TESTS=1 to force')
            else:
                prog = drgn.Program()
                prog.set_kernel()
                try:
                    prog.load_debug_info(main=True)
                    LinuxHelperTestCase.prog = prog
                    return
                except drgn.MissingDebugInfoError:
                    if force_run:
                        raise
                    LinuxHelperTestCase.skip_reason = str(e)
        self.skipTest(LinuxHelperTestCase.skip_reason)


def wait_until(fn, *args, **kwds):
    TIMEOUT = 5
    deadline = time.monotonic() + TIMEOUT
    sleep = 1e-6
    while True:
        if fn(*args, **kwds):
            break
        now = time.monotonic()
        if now >= deadline:
            raise Exception(f'condition was not met in {TIMEOUT} seconds')
        time.sleep(min(deadline - now, sleep))
        sleep *= 2


def fork_and_pause():
    pid = os.fork()
    if pid == 0:
        try:
            while True:
                signal.pause()
        finally:
            os._exit(1)
    return pid


def proc_state(pid):
    with open(f'/proc/{pid}/status', 'r') as f:
        return re.search(r'State:\s*(\S)', f.read(), re.M).group(1)


_c = ctypes.CDLL(None, use_errno=True)

_mount = _c.mount
_mount.restype = ctypes.c_int
_mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                   ctypes.c_ulong, ctypes.c_void_p]
MS_BIND = 4096
def mount(source, target, fstype, flags, data):
    if _mount(os.fsencode(source), os.fsencode(target), fstype.encode(), flags,
              data.encode()) == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), source, None, target)


_umount2 = _c.umount2
_umount2.restype = ctypes.c_int
_umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
def umount(target, flags=0):
    if _umount2(os.fsencode(target), flags) == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), target)


def create_socket(*args, **kwds):
    try:
        return socket.socket(*args, **kwds)
    except OSError as e:
        if e.errno in (errno.ENOSYS, errno.EAFNOSUPPORT,
                       errno.ESOCKTNOSUPPORT):
            raise unittest.SkipTest('kernel does not support TCP')
        else:
            raise
