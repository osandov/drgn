import os
import socket

from drgn import cast
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.tcp import get_tcp_states, sk_tcpstate
from tests.helpers.linux import LinuxHelperTestCase, create_socket


class TestTcp(LinuxHelperTestCase):
    def test_tcp_states(self):
        with create_socket() as sock:
            task = find_task(self.prog, os.getpid())
            file = fget(task, sock.fileno())
            sk = cast('struct socket *', file.private_data).sk
            TcpStates = get_tcp_states(self.prog)
            self.assertEqual(sk_tcpstate(sk), TcpStates.CLOSE)

            sock.bind(('localhost', 0))
            sock.listen()
            self.assertEqual(sk_tcpstate(sk), TcpStates.LISTEN)

            with socket.create_connection(sock.getsockname()), \
                    sock.accept()[0] as sock2:
                file = fget(task, sock2.fileno())
                sk = cast('struct socket *', file.private_data).sk
                self.assertEqual(sk_tcpstate(sk), TcpStates.ESTABLISHED)
