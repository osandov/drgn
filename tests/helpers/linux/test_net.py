# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import socket
import tempfile

from drgn import cast
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.net import (
    for_each_net,
    get_net_ns_by_fd,
    netdev_get_by_index,
    netdev_get_by_name,
    sk_fullsock,
)
from drgn.helpers.linux.pid import find_task
from tests.helpers.linux import LinuxHelperTestCase, create_socket


class TestNet(LinuxHelperTestCase):
    def test_sk_fullsock(self):
        with create_socket() as sock:
            file = fget(find_task(self.prog, os.getpid()), sock.fileno())
            sk = cast("struct socket *", file.private_data).sk.read_()
            self.assertTrue(sk_fullsock(sk))

    def test_netdev_get_by_index(self):
        for index, name in socket.if_nameindex():
            netdev = netdev_get_by_index(self.prog, index)
            self.assertEqual(netdev.name.string_().decode(), name)

    def test_netdev_get_by_name(self):
        for index, name in socket.if_nameindex():
            netdev = netdev_get_by_name(self.prog, name)
            self.assertEqual(netdev.ifindex, index)

    def test_for_each_net(self):
        self.assertIn(self.prog["init_net"].address_of_(), for_each_net(self.prog))

    def test_get_net_ns_by_fd(self):
        pid = os.getpid()
        task = find_task(self.prog, pid)
        with open(f"/proc/{pid}/ns/net") as file:
            net = get_net_ns_by_fd(task, file.fileno())
            for index, name in socket.if_nameindex():
                netdev = netdev_get_by_index(net, index)
                self.assertEqual(netdev.name.string_().decode(), name)

        with tempfile.TemporaryFile("rb") as file:
            self.assertRaisesRegex(
                ValueError,
                "not a namespace inode",
                get_net_ns_by_fd,
                task,
                file.fileno(),
            )

        with open(f"/proc/{pid}/ns/mnt") as file:
            self.assertRaisesRegex(
                ValueError,
                "not a network namespace inode",
                get_net_ns_by_fd,
                task,
                file.fileno(),
            )
