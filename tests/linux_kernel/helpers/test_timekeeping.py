# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path
import time
import unittest

from drgn import cast
from drgn.helpers.linux.timekeeping import (
    ktime_get_boottime_seconds,
    ktime_get_clocktai_seconds,
    ktime_get_coarse_boottime_ns,
    ktime_get_coarse_clocktai_ns,
    ktime_get_coarse_ns,
    ktime_get_coarse_real_ns,
    ktime_get_real_seconds,
    ktime_get_seconds,
    uptime,
    uptime_pretty,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod

# These aren't available in the time module as of Python 3.14.
CLOCK_REALTIME_COARSE = getattr(time, "CLOCK_REALTIME_COARSE", 5)
CLOCK_MONOTONIC_COARSE = getattr(time, "CLOCK_MONOTONIC_COARSE", 6)


class TestTimekeeping(LinuxKernelTestCase):
    def assert_in_range(self, a, b, c):
        self.assertTrue(a <= b <= c, f"{b} is not in range [{a}, {c}]")

    def test_ktime_get_seconds(self):
        t1 = int(time.clock_gettime(CLOCK_MONOTONIC_COARSE))
        t2 = ktime_get_seconds(self.prog)
        t3 = int(time.clock_gettime(CLOCK_MONOTONIC_COARSE))

        self.assert_in_range(t1, t2.value_(), t3)
        self.assertIdentical(t2, cast("time64_t", t2))

    @unittest.skipUnless(
        hasattr(time, "clock_gettime_ns"), "no time.clock_gettime_ns in Python < 3.7"
    )
    def test_ktime_get_coarse_ns(self):
        t1 = time.clock_gettime_ns(CLOCK_MONOTONIC_COARSE)
        t2 = ktime_get_coarse_ns(self.prog)
        t3 = time.clock_gettime_ns(CLOCK_MONOTONIC_COARSE)

        self.assert_in_range(t1, t2.value_(), t3)
        self.assertIdentical(t2, cast("u64", t2))

    def test_ktime_get_real_seconds(self):
        t1 = int(time.clock_gettime(CLOCK_REALTIME_COARSE))
        t2 = ktime_get_real_seconds(self.prog)
        t3 = int(time.clock_gettime(CLOCK_REALTIME_COARSE))

        self.assert_in_range(t1, t2.value_(), t3)
        self.assertIdentical(t2, cast("time64_t", t2))

    @unittest.skipUnless(
        hasattr(time, "clock_gettime_ns"), "no time.clock_gettime_ns in Python < 3.7"
    )
    def test_ktime_get_coarse_real_ns(self):
        t1 = time.clock_gettime_ns(CLOCK_REALTIME_COARSE)
        t2 = ktime_get_coarse_real_ns(self.prog)
        t3 = time.clock_gettime_ns(CLOCK_REALTIME_COARSE)

        self.assert_in_range(t1, t2.value_(), t3)
        self.assertIdentical(t2, cast("u64", t2))

    @skip_unless_have_test_kmod
    def test_ktime_get_boottime_seconds(self):
        # There is no CLOCK_BOOTTIME_COARSE, so the test module exposes it in
        # sysfs.
        path = Path("/sys/kernel/drgn_test/boottime_seconds")

        t1 = int(path.read_text())
        t2 = ktime_get_boottime_seconds(self.prog)
        t3 = int(path.read_text())

        self.assert_in_range(t1, t2.value_(), t3)
        self.assertIdentical(t2, cast("time64_t", t2))

    @skip_unless_have_test_kmod
    def test_ktime_get_coarse_boottime_ns(self):
        # There is no CLOCK_BOOTTIME_COARSE, so the test module exposes it in
        # sysfs.
        path = Path("/sys/kernel/drgn_test/coarse_boottime_ns")

        t1 = int(path.read_text())
        t2 = ktime_get_coarse_boottime_ns(self.prog)
        t3 = int(path.read_text())

        self.assert_in_range(t1, t2.value_(), t3)
        self.assertIdentical(t2, cast("u64", t2))

    @skip_unless_have_test_kmod
    def test_ktime_get_clocktai_seconds(self):
        # There is no CLOCK_TAI_COARSE, so the test module exposes it in sysfs.
        path = Path("/sys/kernel/drgn_test/clocktai_seconds")

        t1 = int(path.read_text())
        t2 = ktime_get_clocktai_seconds(self.prog)
        t3 = int(path.read_text())

        self.assert_in_range(t1, t2.value_(), t3)
        self.assertIdentical(t2, cast("time64_t", t2))

    @skip_unless_have_test_kmod
    def test_ktime_get_coarse_clocktai_ns(self):
        # There is no CLOCK_TAI_COARSE, so the test module exposes it in sysfs.
        path = Path("/sys/kernel/drgn_test/coarse_clocktai_ns")

        t1 = int(path.read_text())
        t2 = ktime_get_coarse_clocktai_ns(self.prog)
        t3 = int(path.read_text())

        self.assert_in_range(t1, t2.value_(), t3)
        self.assertIdentical(t2, cast("u64", t2))

    @skip_unless_have_test_kmod
    def test_uptime(self):
        # There is no CLOCK_BOOTTIME_COARSE, so the test module exposes it in
        # sysfs.
        path = Path("/sys/kernel/drgn_test/coarse_boottime_ns")

        t1 = int(path.read_text())
        t2 = uptime(self.prog)
        t3 = int(path.read_text())

        self.assert_in_range(t1 / 1e9, t2, t3 / 1e9)
        self.assertIsInstance(t2, float)

    def test_uptime_pretty(self):
        # Just test that it succeeds.
        uptime_pretty(self.prog)
