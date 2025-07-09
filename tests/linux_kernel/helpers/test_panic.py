# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.panic import _panic_message
from tests import TestCase


class TestPanicMessage(TestCase):
    def test_basic(self):
        self.assertEqual(
            _panic_message(
                b"""\
Freeing unused kernel image (text/rodata gap) memory: 1748K
Freeing unused kernel image (rodata/data gap) memory: 1300K
Run /tmp/drgn-vmtest-bwe4pfi5/init as init process
sysrq: Trigger a crash
Kernel panic - not syncing: sysrq triggered crash
CPU: 6 UID: 0 PID: 127 Comm: selfdestruct Kdump: loaded Not tainted 6.16.0-rc5-vmtest35.1default #1 PREEMPT(none)
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.17.0-4.fc42 04/01/2014
"""
            ),
            b"Kernel panic - not syncing: sysrq triggered crash",
        )

    def test_preference(self):
        # We should prefer BUG over Oops.
        self.assertEqual(
            _panic_message(
                b"""\
Run /tmp/drgn-vmtest-50jcxww4/init as init process
drgn_test: loading out-of-tree module taints kernel.
stackdepot: allocating hash table of 131072 entries via kvcalloc
BUG: kernel NULL pointer dereference, address: 000000000000071c
#PF: supervisor write access in kernel mode
#PF: error_code(0x0002) - not-present page
PGD 0 P4D 0
Oops: Oops: 0002 [#1] SMP NOPTI
"""
            ),
            b"BUG: kernel NULL pointer dereference, address: 000000000000071c",
        )
