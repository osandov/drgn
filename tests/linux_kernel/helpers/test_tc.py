# Copyright (c) ByteDance, Inc. and its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os

from drgn.helpers.linux.fs import path_lookup
from drgn.helpers.linux.net import get_net_ns_by_inode, netdev_get_by_name
from drgn.helpers.linux.tc import qdisc_lookup
from tests.linux_kernel import (
    LinuxKernelTestCase,
    skip_unless_have_pyroute2_del,
    temp_netns,
)


@skip_unless_have_pyroute2_del
class TestTc(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.name, cls.ns = cls.enterClassContext(temp_netns())

    def test_qdisc_lookup(self):
        import pyroute2

        try:
            self.ns.link("add", ifname="dummy0", kind="dummy")
        except pyroute2.NetlinkError:
            self.skipTest("kernel does not support dummy interface (CONFIG_DUMMY)")

        dummy = self.ns.link_lookup(ifname="dummy0")[0]

        # tc qdisc add dev dummy0 root handle 1: prio
        try:
            self.ns.tc(
                "add",
                kind="prio",
                index=dummy,
                handle="1:",
                # default TCA_OPTIONS for sch_prio, see [iproute2] tc/q_prio.c:prio_parse_opt()
                bands=3,
                priomap=[1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
            )
        except pyroute2.NetlinkError:
            self.ns.link("delete", ifname="dummy0")
            self.skipTest(
                "kernel does not support Multi Band Priority Queueing (CONFIG_NET_SCH_PRIO)"
            )
        # tc qdisc add dev dummy0 parent 1:1 handle 10: sfq
        try:
            self.ns.tc("add", kind="sfq", index=dummy, parent="1:1", handle="10:")
        except pyroute2.NetlinkError:
            self.ns.link("delete", ifname="dummy0")
            self.skipTest(
                "kernel does not support Stochastic Fairness Queueing (CONFIG_NET_SCH_SFQ)"
            )
        # tc qdisc add dev dummy0 parent 1:2 handle 20: tbf rate 20kbit buffer 1600 limit 3000
        try:
            self.ns.tc(
                "add",
                kind="tbf",
                index=dummy,
                parent="1:2",
                handle="20:",
                rate=2500,
                burst=1600,
                limit=3000,
            )
        except pyroute2.NetlinkError:
            self.ns.link("delete", ifname="dummy0")
            self.skipTest(
                "kernel does not support Token Bucket Filter (CONFIG_NET_SCH_TBF)"
            )
        # tc qdisc add dev dummy0 parent 1:3 handle 30: sfq
        self.ns.tc("add", kind="sfq", index=dummy, parent="1:3", handle="30:")
        # tc qdisc add dev dummy0 ingress
        try:
            self.ns.tc("add", kind="ingress", index=dummy)
        except pyroute2.NetlinkError:
            self.ns.link("delete", ifname="dummy0")
            self.skipTest(
                "kernel does not support ingress Qdisc (CONFIG_NET_SCH_INGRESS)"
            )

        inode = path_lookup(
            self.prog, os.path.realpath(f"/var/run/netns/{self.name}")
        ).dentry.d_inode
        netdev = netdev_get_by_name(get_net_ns_by_inode(inode), "dummy0")

        self.assertEqual(qdisc_lookup(netdev, 0x1).ops.id.string_(), b"prio")
        self.assertEqual(qdisc_lookup(netdev, 0x10).ops.id.string_(), b"sfq")
        self.assertEqual(qdisc_lookup(netdev, 0x20).ops.id.string_(), b"tbf")
        self.assertEqual(qdisc_lookup(netdev, 0x30).ops.id.string_(), b"sfq")
        self.assertEqual(qdisc_lookup(netdev, 0xFFFF).ops.id.string_(), b"ingress")

        self.ns.link("delete", ifname="dummy0")
