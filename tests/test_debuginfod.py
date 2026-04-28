# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


import http.server
import os
import os.path
from pathlib import Path
import re
import shutil
import socket
import socketserver
import tempfile
import threading

from drgn import ModuleFileStatus, Program, SupplementaryFileKind
from tests import TestCase, modifyenv
from tests.test_debug_info import NamedTemporaryElfFile


class _DebuginfodHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        match = re.fullmatch(
            r"/buildid/((?:[0-9a-fA-F][0-9a-fA-F])+)/(executable|debuginfo)", self.path
        )
        if not match:
            self.send_error(http.HTTPStatus.BAD_REQUEST)
            return

        build_id = bytes.fromhex(match.group(1))
        type = match.group(2)

        try:
            file_path = self.server.build_ids[build_id][type]
        except KeyError:
            self.send_error(http.HTTPStatus.NOT_FOUND)
            return

        try:
            f = open(file_path, "rb")
        except OSError:
            self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        with f:
            self.send_response(http.HTTPStatus.OK)
            st = os.fstat(f.fileno())
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(st.st_size))
            self.send_header("X-Debuginfod-Size", str(st.st_size))
            self.send_header("Last-Modified", self.date_time_string(st.st_mtime))
            self.end_headers()
            shutil.copyfileobj(f, self.wfile)


class TestDebuginfodDebugInfoFinder(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.server = socketserver.TCPServer(("localhost", 0), _DebuginfodHTTPHandler)
        cls.server.build_ids = {}
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True
        )
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        # By default, serve_forever() only checks if it should shut down every
        # 0.5 seconds. Shutting down the socket makes it check immediately.
        cls.server.socket.shutdown(socket.SHUT_RD)
        cls.server.shutdown()
        cls.server_thread.join()
        cls.server.server_close()

    def setUp(self):
        self.prog = Program()
        try:
            self.prog.set_enabled_debug_info_finders(["debuginfod"])
        except ValueError:
            self.skipTest("no debuginfod support")

        self.server.build_ids.clear()
        self.cache_dir = Path(
            self.enterContext(tempfile.TemporaryDirectory(prefix="debuginfod-cache-"))
        )
        self.enterContext(
            modifyenv(
                {
                    "DEBUGINFOD_URLS": "http://{}:{}/".format(
                        *self.server.server_address
                    ),
                    "DEBUGINFOD_CACHE_PATH": str(self.cache_dir),
                }
            )
        )

    def test_no_build_id(self):
        module = self.prog.extra_module("foo", create=True)
        self.prog.load_module_debug_info(module)
        self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
        self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_separate(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(
            loadable=True, debug=False, build_id=build_id
        ) as loadable_file, NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=build_id
        ) as debug_file:
            self.server.build_ids[build_id] = {
                "executable": loadable_file.name,
                "debuginfo": debug_file.name,
            }

            module = self.prog.extra_module("foo", create=True)
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.loaded_file_path,
                str(self.cache_dir / build_id.hex() / "executable"),
            )
            self.assertEqual(
                module.debug_file_path,
                str(self.cache_dir / build_id.hex() / "debuginfo"),
            )

    def test_no_servers(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(
            loadable=True, debug=False, build_id=build_id
        ) as loadable_file, NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=build_id
        ) as debug_file, modifyenv(
            {"DEBUGINFOD_URLS": None}
        ):
            self.server.build_ids[build_id] = {
                "executable": loadable_file.name,
                "debuginfo": debug_file.name,
            }

            module = self.prog.extra_module("foo", create=True)
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.WANT)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.WANT)

    def test_cache_hit(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"

        with NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=build_id
        ) as debug_file:
            self.server.build_ids[build_id] = {"debuginfo": debug_file.name}

            for i in range(2):
                module = self.prog.extra_module("foo", i, create=True)
                module.build_id = build_id
                self.prog.load_module_debug_info(module)
                self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
                self.assertEqual(
                    module.debug_file_path,
                    str(self.cache_dir / build_id.hex() / "debuginfo"),
                )

    def test_gnu_debugaltlink(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with NamedTemporaryElfFile(
            loadable=True, debug=False, build_id=build_id
        ) as loadable_file, NamedTemporaryElfFile(
            loadable=False,
            debug=True,
            build_id=build_id,
            gnu_debugaltlink=("alt.debug", alt_build_id),
        ) as debug_file, NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=alt_build_id
        ) as alt_f:
            self.server.build_ids[build_id] = {
                "executable": loadable_file.name,
                "debuginfo": debug_file.name,
            }
            self.server.build_ids[alt_build_id] = {"debuginfo": alt_f.name}

            module = self.prog.extra_module("foo", create=True)
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.loaded_file_path,
                str(self.cache_dir / build_id.hex() / "executable"),
            )
            self.assertEqual(
                module.debug_file_path,
                str(self.cache_dir / build_id.hex() / "debuginfo"),
            )
            self.assertEqual(
                module.supplementary_debug_file_path,
                str(self.cache_dir / alt_build_id.hex() / "debuginfo"),
            )

    def test_gnu_debugaltlink_not_found(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with NamedTemporaryElfFile(
            loadable=True, debug=False, build_id=build_id
        ) as loadable_file, NamedTemporaryElfFile(
            loadable=False,
            debug=True,
            build_id=build_id,
            gnu_debugaltlink=("alt.debug", alt_build_id),
        ) as debug_file:
            self.server.build_ids[build_id] = {
                "executable": loadable_file.name,
                "debuginfo": debug_file.name,
            }

            module = self.prog.extra_module("foo", create=True)
            module.build_id = build_id
            self.prog.load_module_debug_info(module)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(
                module.wanted_supplementary_debug_file(),
                (
                    SupplementaryFileKind.GNU_DEBUGALTLINK,
                    str(self.cache_dir / build_id.hex() / "debuginfo"),
                    "alt.debug",
                    alt_build_id,
                ),
            )
            self.assertEqual(
                module.loaded_file_path,
                str(self.cache_dir / build_id.hex() / "executable"),
            )

    def test_only_gnu_debugaltlink(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with NamedTemporaryElfFile(
            build_id=build_id,
            gnu_debugaltlink=("alt.debug", alt_build_id),
        ) as f, NamedTemporaryElfFile(
            loadable=False, debug=True, build_id=alt_build_id
        ) as alt_f:
            self.server.build_ids[alt_build_id] = {"debuginfo": alt_f.name}

            module = self.prog.extra_module("foo", create=True)
            module.try_file(f.name)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(module.loaded_file_path, f.name)

            self.prog.load_module_debug_info(module)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(module.debug_file_path, f.name)
            self.assertEqual(
                module.supplementary_debug_file_path,
                str(self.cache_dir / alt_build_id.hex() / "debuginfo"),
            )

    def test_only_gnu_debugaltlink_not_found(self):
        build_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        alt_build_id = b"\xfe\xdc\xba\x98\x76\x54\x32\x10"

        with NamedTemporaryElfFile(
            build_id=build_id,
            gnu_debugaltlink=("alt.debug", alt_build_id),
        ) as f:
            module = self.prog.extra_module("foo", create=True)
            module.try_file(f.name)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
            self.assertEqual(
                module.wanted_supplementary_debug_file(),
                (
                    SupplementaryFileKind.GNU_DEBUGALTLINK,
                    f.name,
                    "alt.debug",
                    alt_build_id,
                ),
            )
            self.assertEqual(module.loaded_file_path, f.name)

            self.prog.load_module_debug_info(module)
            self.assertEqual(module.loaded_file_status, ModuleFileStatus.HAVE)
            self.assertEqual(
                module.debug_file_status, ModuleFileStatus.WANT_SUPPLEMENTARY
            )
