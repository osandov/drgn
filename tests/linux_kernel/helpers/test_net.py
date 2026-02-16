# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import ipaddress
import os
import socket
import tempfile

from drgn import cast
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.net import (
    _S_IFMT,
    _S_IFSOCK,
    SOCK_INODE,
    SOCKET_I,
    for_each_net,
    for_each_netdev,
    get_net_ns_by_fd,
    is_pp_page,
    neigh_table_for_each_neighbor,
    netdev_for_each_tx_queue,
    netdev_get_by_index,
    netdev_get_by_name,
    netdev_ipv4_addrs,
    netdev_ipv6_addrs,
    netdev_name,
    netdev_priv,
    sk_fullsock,
    skb_shinfo,
)
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import (
    LinuxKernelTestCase,
    create_socket,
    skip_unless_have_pyroute2,
    skip_unless_have_pyroute2_del,
    skip_unless_have_test_kmod,
    temp_netns,
)
from util import KernelVersion


class TestNet(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pid = os.getpid()
        cls.task = find_task(cls.prog, cls.pid)
        with open(f"/proc/{cls.pid}/ns/net") as file:
            cls.net = get_net_ns_by_fd(cls.task, file.fileno())

    def test_sk_fullsock(self):
        with create_socket() as skt:
            file = fget(self.task, skt.fileno())
            sk = cast("struct socket *", file.private_data).sk.read_()
            self.assertTrue(sk_fullsock(sk))

    def test_for_each_netdev(self):
        self.assertCountEqual(
            [netdev_name(dev) for dev in for_each_netdev(self.net)],
            [name.encode() for _, name in socket.if_nameindex()],
        )

    @skip_unless_have_test_kmod
    def test_for_each_netdev_init_net(self):
        self.assertIn(self.prog["drgn_test_netdev"], for_each_netdev(self.prog))

    @skip_unless_have_test_kmod
    def test_netdev_name(self):
        self.assertEqual(netdev_name(self.prog["drgn_test_netdev"]), b"lo")

    def test_netdev_get_by_index(self):
        for index, name in socket.if_nameindex():
            netdev = netdev_get_by_index(self.net, index)
            self.assertEqual(netdev.name.string_().decode(), name)

    def test_netdev_get_by_name(self):
        for index, name in socket.if_nameindex():
            netdev = netdev_get_by_name(self.net, name)
            self.assertEqual(netdev.ifindex, index)

    @skip_unless_have_test_kmod
    def test_netdev_get_by_name_init_net(self):
        self.assertEqual(
            netdev_get_by_name(self.prog, "lo"), self.prog["drgn_test_netdev"]
        )

    @skip_unless_have_test_kmod
    def test_netdev_priv(self):
        self.assertEqual(
            netdev_priv(self.prog["drgn_test_netdev"]),
            self.prog["drgn_test_netdev_priv"],
        )

    def test_for_each_net(self):
        self.assertIn(self.prog["init_net"].address_of_(), for_each_net(self.prog))

    def test_get_net_ns_by_fd(self):
        for index, name in socket.if_nameindex():
            netdev = netdev_get_by_index(self.net, index)
            self.assertEqual(netdev.name.string_().decode(), name)

        with tempfile.TemporaryFile("rb") as file:
            self.assertRaisesRegex(
                ValueError,
                "not a namespace inode",
                get_net_ns_by_fd,
                self.task,
                file.fileno(),
            )

        with open(f"/proc/{self.pid}/ns/mnt") as file:
            self.assertRaisesRegex(
                ValueError,
                "not a network namespace inode",
                get_net_ns_by_fd,
                self.task,
                file.fileno(),
            )

    def test_netdev_for_each_tx_queue(self):
        for index, _ in socket.if_nameindex():
            netdev = netdev_get_by_index(self.net, index)
            for queue in netdev_for_each_tx_queue(netdev):
                self.assertEqual(queue.dev, netdev)

    def test_SOCKET_I(self):
        with create_socket(type=socket.SOCK_DGRAM) as skt:
            sock = SOCKET_I(fget(self.task, skt.fileno()).f_inode)
            self.assertEqual(sock.type, socket.SOCK_DGRAM)

        with open("/dev/null") as null:
            file = fget(self.task, null.fileno())
            self.assertRaisesRegex(
                ValueError, "not a socket inode", SOCKET_I, file.f_inode
            )

    def test_SOCK_INODE(self):
        with create_socket() as skt:
            sock = SOCKET_I(fget(self.task, skt.fileno()).f_inode)
            inode = SOCK_INODE(sock)
            self.assertEqual(inode.i_mode & _S_IFMT, _S_IFSOCK)

    @skip_unless_have_test_kmod
    def test_skb_shinfo(self):
        self.assertEqual(
            skb_shinfo(self.prog["drgn_test_skb"]), self.prog["drgn_test_skb_shinfo"]
        )

    @skip_unless_have_test_kmod
    def test_is_pp_page(self):
        if not self.prog["drgn_test_have_page_pool"]:
            self.skipTest("kernel does not support page pools")
        if KernelVersion(os.uname().release) < KernelVersion("5.14"):
            self.skipTest("kernel does not support identifying page_pool pages")
        self.assertTrue(is_pp_page(self.prog["drgn_test_page_pool_page"]))
        self.assertFalse(is_pp_page(self.prog["drgn_test_page"]))

    @skip_unless_have_pyroute2
    def test_netdev_ipv4_addrs(self):
        import pyroute2

        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="lo")[0]
            addrs = ipr.get_addr(index=idx, family=socket.AF_INET)
            expected = [
                ipaddress.IPv4Address(addr.get_attr("IFA_ADDRESS")) for addr in addrs
            ]
        self.assertCountEqual(
            netdev_ipv4_addrs(netdev_get_by_name(self.prog, "lo")),
            expected,
        )

    @skip_unless_have_pyroute2
    def test_netdev_ipv6_addrs(self):
        import pyroute2

        with pyroute2.IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="lo")[0]
            addrs = ipr.get_addr(index=idx, family=socket.AF_INET6)
            expected = [
                ipaddress.IPv6Address(addr.get_attr("IFA_ADDRESS")) for addr in addrs
            ]
        self.assertCountEqual(
            netdev_ipv6_addrs(netdev_get_by_name(self.prog, "lo")),
            expected,
        )

    @skip_unless_have_pyroute2_del
    def test_neigh_table_for_each_neighbor(self):
        import pyroute2
        import pyroute2.netlink.rtnl.ndmsg

        with temp_netns() as (_, ns):
            try:
                ns.link("add", ifname="dummy0", kind="dummy")
            except pyroute2.NetlinkError:
                self.skipTest("kernel does not support dummy interface (CONFIG_DUMMY)")

            try:
                idx = ns.link_lookup(ifname="dummy0")[0]
                # Add a permanent neighbor entry so there's something to find
                ns.neigh(
                    "add",
                    dst="192.0.2.1",
                    lladdr="00:11:22:33:44:55",
                    ifindex=idx,
                    state=pyroute2.netlink.rtnl.ndmsg.states["permanent"],
                )
                nht = self.prog["arp_tbl"].nht.read_()
                neighbor_addrs = [
                    ipaddress.IPv4Address(self.prog.read(n.primary_key.address_, 4))
                    for n in neigh_table_for_each_neighbor(nht)
                ]
                self.assertIn(ipaddress.IPv4Address("192.0.2.1"), neighbor_addrs)
            finally:
                ns.link("delete", ifname="dummy0")
