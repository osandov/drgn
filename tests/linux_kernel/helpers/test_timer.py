# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.timer import hrtimer_clock_base_for_each, timer_base_for_each
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


@skip_unless_have_test_kmod
class TestTimer(LinuxKernelTestCase):
    def test_timer_base_for_each_timer(self):
        timer = self.prog["drgn_test_timer"].address_of_()
        for cpu in for_each_online_cpu(self.prog):
            for base in per_cpu(self.prog["timer_bases"], cpu):
                if timer in timer_base_for_each(base):
                    return
        self.fail("timer not found")

    def test_hrtimer_clock_base_for_each_hrtimer(self):
        hrtimer = self.prog["drgn_test_hrtimer"].address_of_()
        for cpu in for_each_online_cpu(self.prog):
            for clock_base in per_cpu(self.prog["hrtimer_bases"], cpu).clock_base:
                if hrtimer in hrtimer_clock_base_for_each(clock_base.address_of_()):
                    return
        self.fail("hrtimer not found")
