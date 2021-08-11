# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import socket

from drgn import cast
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.net import netdev_get_by_index, netdev_get_by_name, sk_fullsock
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
