# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# TODO: move it all here

import ctypes
import math
import os

from tests.linux_kernel import _c, _check_ctypes_syscall

try:
    _time_t = ctypes.c_time_t
except AttributeError:
    _time_t = ctypes.c_long  # TODO


_timerfd_create = _c.timerfd_create
_timerfd_create.argtypes = [ctypes.c_int, ctypes.c_int]
_timerfd_create.restype = ctypes.c_int


TFD_TIMER_ABSTIME = 1 << 0
TFD_TIMER_CANCEL_ON_SET = 1 << 1
TFD_CLOEXEC = os.O_CLOEXEC
TFD_NONBLOCK = os.O_NONBLOCK


def timerfd_create(clockid, /, *, flags=0):
    flags |= TFD_CLOEXEC
    return _check_ctypes_syscall(_timerfd_create(clockid, flags))


class _timespec(ctypes.Structure):
    _fields_ = (
        ("tv_sec", _time_t),
        ("tv_nsec", ctypes.c_long),
    )


class _itimerspec(ctypes.Structure):
    _fields_ = (
        ("it_interval", _timespec),
        ("it_value", _timespec),
    )


_timerfd_settime = _c.timerfd_settime
_timerfd_settime.argtypes = [
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(_itimerspec),
    ctypes.POINTER(_itimerspec),
]
_timerfd_settime.restype = ctypes.c_int


def _float_to_timespec(x):
    frac, i = math.modf(x)
    return int(i), int(frac * 1e9)


def _timespec_to_float(t):
    return t.tv_sec + t.tv_nsec / 1e9


def timerfd_settime(fd, /, *, flags=0, initial=0.0, interval=0.0):
    new = _itimerspec()
    new.it_interval.tv_sec, new.it_interval.tv_nsec = _float_to_timespec(interval)
    new.it_value.tv_sec, new.it_value.tv_nsec = _float_to_timespec(initial)
    old = _itimerspec()
    _check_ctypes_syscall(
        _timerfd_settime(fd, flags, ctypes.byref(new), ctypes.byref(old))
    )
    return _timespec_to_float(old.it_value), _timespec_to_float(old.it_interval)
