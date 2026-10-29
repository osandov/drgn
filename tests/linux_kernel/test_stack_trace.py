# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import errno
from fcntl import ioctl
import logging
import mmap
import os
from pathlib import Path
import re
import signal
import unittest

from _drgn_util.platform import _IO, NORMALIZED_MACHINE_NAME
from drgn import Object, Program, TypeMember, reinterpret
from drgn.helpers.linux import load_module_kallsyms, load_vmlinux_kallsyms
from tests import assertReprPrettyEqualsStr, drgn_log_level, modifyenv
from tests.linux_kernel import (
    LinuxKernelTestCase,
    fork_and_stop,
    proc_state,
    skip_unless_have_stack_tracing,
    skip_unless_have_test_kmod,
    wait_until,
)


class PageFaultThread:
    """
    A reusable test fixture that creates thread sleeping in a page fault on a
    kernel task thread. This allows us to test unwinding through exceptions
    without actually entering the kdump environment.

    We do this through the drgn_test_fault device. We open the file and mmap a
    page. Then we use write() to write a 1-byte pointer into the FD. Crucially,
    the pointer is a pointer into the mapped region, which we haven't faulted in
    yet. As a result, our write handler must fault the page, eventually calling
    our fault handler, which  will then go to sleep. We use ioctl() operations
    to determine when the thread is ready for unwind, and to signal it to exit.
    """

    def __init__(self):
        self.fd = os.open("/dev/drgn_test_fault", os.O_RDWR)
        self.pid = None
        # Keep these in sync with drgn_test.c.
        self._entered = _IO(ord("d"), 0)
        self._release = _IO(ord("d"), 1)

    def _child(self):
        status = 1
        try:
            with mmap.mmap(
                self.fd, mmap.PAGESIZE, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ
            ) as mapping:
                # A memoryview slice does not fault in the mapping. The first
                # access must be get_user() in the drgn_test module.
                with memoryview(mapping)[:1] as buf:
                    try:
                        os.write(self.fd, buf)
                    except OSError as e:
                        if e.errno == errno.EFAULT:
                            status = 0
        finally:
            os._exit(status)

    def _child_sleeping_in_fault(self):
        if proc_state(self.pid) == "Z":
            raise RuntimeError("faulting child exited")
        return (
            ioctl(self.fd, self._entered) == 1
            and proc_state(self.pid) == "S"
            and Path(f"/proc/{self.pid}/syscall").read_text() != "running\n"
        )

    def __enter__(self):
        self.pid = os.fork()
        if self.pid == 0:
            self._child()  # no return
        wait_until(self._child_sleeping_in_fault)
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        try:
            ioctl(self.fd, self._release)
        except Exception:
            if self.pid is not None:
                os.kill(self.pid, signal.SIGKILL)
        finally:
            os.close(self.fd)
            if self.pid is not None:
                _, status = os.waitpid(self.pid, 0)
                # Raise an error during normal exit if the child doesn't exit
                # cleanly. If we already have an exception, swallow it because it's
                # probably related.
                if exc_type is None and (
                    not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0
                ):
                    raise RuntimeError("faulting child did not exit cleanly")


@skip_unless_have_stack_tracing
class LinuxKernelStackTraceTestCase(LinuxKernelTestCase):
    def _test_drgn_test_kthread_trace(self, trace, test_source=True):
        for i, frame in enumerate(trace):
            if frame.name == "drgn_test_kthread_fn3":
                break
        else:
            self.fail("Couldn't find drgn_test_kthread_fn3 frame")
        self.assertEqual(trace[i + 1].name, "drgn_test_kthread_fn2")
        self.assertEqual(trace[i + 2].name, "drgn_test_kthread_fn")

        if test_source:
            source = frame.source()
            self.assertRegex(source.filename, r"\bdrgn_test\.c$")
            self.assertIsInstance(source.line, int)
            self.assertIsInstance(source.column, int)
            self.assertEqual(
                tuple(source), (source.filename, source.line, source.column)
            )
            self.assertEqual(source.name(), "drgn_test_kthread_fn3")


class TestStackTrace(LinuxKernelStackTraceTestCase):
    @skip_unless_have_test_kmod
    def test_unwind_through_page_fault(self):
        if not self.prog["drgn_test_have_fault_stack_trace"]:
            self.skipTest("test requires Linux 4.19 or later")

        # Full support: x86_64, aarch64, s390x
        CANNOT_UNWIND = ("arm",)
        CANNOT_RECOVER_REGS = ("ppc64",)
        if NORMALIZED_MACHINE_NAME in CANNOT_UNWIND:
            self.skipTest("reliable unwinding through exceptions not available")

        with PageFaultThread() as thread:
            trace = self.prog.stack_trace(thread.pid)
            names = [frame.name for frame in trace]
            fault_index = names.index("drgn_test_fault")
            write_index = names.index("drgn_test_fault_write")
            self.assertLess(fault_index, write_index)
            self.assertGreater(trace[write_index].sp, 0)
            if NORMALIZED_MACHINE_NAME not in CANNOT_RECOVER_REGS:
                interrupted = [
                    frame
                    for frame in list(trace)[fault_index + 1 : write_index]
                    if frame.interrupted and not frame.is_inline
                ]
                self.assertEqual(len(interrupted), 1)
                self.assertGreater(interrupted[0].sp, 0)

    @skip_unless_have_test_kmod
    def test_by_task_struct(self):
        self._test_drgn_test_kthread_trace(
            self.prog.stack_trace(self.prog["drgn_test_kthread"])
        )

    def _test_by_pid(self, orc):
        old_orc = int(os.environ.get("DRGN_PREFER_ORC_UNWINDER", "0")) != 0
        with modifyenv({"DRGN_PREFER_ORC_UNWINDER": "1" if orc else "0"}):
            if orc == old_orc:
                prog = self.prog
            else:
                prog = Program()
                prog.set_kernel()
                self._load_debug_info(prog)
            self._test_drgn_test_kthread_trace(
                prog.stack_trace(prog["drgn_test_kthread"].pid)
            )

    @skip_unless_have_test_kmod
    def test_by_pid_dwarf(self):
        self._test_by_pid(False)

    @unittest.skipUnless(
        NORMALIZED_MACHINE_NAME == "x86_64",
        f"{NORMALIZED_MACHINE_NAME} does not use ORC",
    )
    @skip_unless_have_test_kmod
    def test_by_pid_orc(self):
        self._test_by_pid(True)

    def _check_logged_orc_message(self, captured_logs, module):
        # To be sure that we actually used ORC to unwind through the drgn_test
        # stack frames, search for the log output. We don't know which ORC
        # version is used, so just ensure that we have a log line that mentions
        # loading ORC.
        expr = re.compile(
            r"DEBUG:drgn:Loaded built-in ORC \(v\d+\) for module " + module
        )
        for line in captured_logs.output:
            if expr.fullmatch(line):
                break
        else:
            self.fail(f"Did not load built-in ORC for {module}")

    @unittest.skipUnless(
        NORMALIZED_MACHINE_NAME == "x86_64",
        f"{NORMALIZED_MACHINE_NAME} does not use ORC",
    )
    @skip_unless_have_test_kmod
    def test_by_pid_builtin_orc(self):
        # ORC was introduced in kernel 4.14. Detect the presence of ORC or skip
        # the test.
        try:
            self.prog.symbol("__start_orc_unwind")
        except LookupError:
            ver = self.prog["UTS_RELEASE"].string_().decode()
            self.skipTest(f"ORC is not available for {ver}")

        with drgn_log_level(logging.DEBUG):
            # Create a program with the core kernel debuginfo loaded,
            # but without module debuginfo. Load a symbol finder using
            # kallsyms so that the module's stack traces can still have
            # usable frame names.
            prog = Program()
            prog.set_kernel()
            prog.load_debug_info(main=True)
            # Now that vmlinux is loaded, enumerate all the kernel modules so
            # that a drgn_module is created to hold the ORC data
            prog.create_loaded_modules()
            kallsyms = load_module_kallsyms(prog)
            prog.register_symbol_finder("module_kallsyms", kallsyms, enable_index=1)
            for thread in prog.threads():
                if b"drgn_test_kthread".startswith(thread.object.comm.string_()):
                    pid = thread.tid
                    break
            else:
                self.fail("couldn't find drgn_test_kthread")
            # We must set drgn's log level manually, beacuse it won't log messages
            # to the logger if it isn't enabled for them.
            with self.assertLogs("drgn", logging.DEBUG) as log:
                self._test_drgn_test_kthread_trace(
                    prog.stack_trace(pid), test_source=False
                )

            self._check_logged_orc_message(log, "drgn_test")

    @skip_unless_have_test_kmod
    def test_by_pt_regs(self):
        pt_regs = self.prog["drgn_test_kthread_pt_regs"]
        self._test_drgn_test_kthread_trace(self.prog.stack_trace(pt_regs))
        self._test_drgn_test_kthread_trace(self.prog.stack_trace(pt_regs.address_of_()))

    @skip_unless_have_test_kmod
    def test_stack_trace_from_pcs(self):
        if not self.prog["drgn_test_have_stacktrace"]:
            self.skipTest("kernel was not built with CONFIG_STACKTRACE")
        entries = self.prog["drgn_test_stack_entries"]
        self._test_drgn_test_kthread_trace(
            self.prog.stack_trace_from_pcs(
                reinterpret(
                    self.prog.array_type(
                        entries.type_.type,
                        self.prog["drgn_test_num_stack_entries"].value_(),
                    ),
                    entries,
                ).value_()
            )
        )

    @skip_unless_have_test_kmod
    def test_local_variable(self):
        for frame in self.prog.stack_trace(self.prog["drgn_test_kthread"]):
            if frame.name == "drgn_test_kthread_fn3":
                break
        else:
            self.fail("Couldn't find drgn_test_kthread_fn3 frame")
        self.assertEqual(frame["a"], 1)
        self.assertEqual(frame["b"], 2)
        self.assertEqual(frame["c"], 3)

    @skip_unless_have_test_kmod
    def test_locals(self):
        task = self.prog["drgn_test_kthread"]
        stack_trace = self.prog.stack_trace(task)
        for frame in stack_trace:
            if frame.name == "drgn_test_kthread_fn3":
                self.assertSetEqual(set(frame.locals()), {"a", "b", "c", "slab_object"})
                break
        else:
            self.fail("Couldn't find drgn_test_kthread_fn3 frame")

    @unittest.skipUnless(
        NORMALIZED_MACHINE_NAME == "x86_64",
        f"{NORMALIZED_MACHINE_NAME} does not use ORC",
    )
    def test_vmlinux_builtin_orc(self):
        # ORC was introduced in kernel 4.14. Detect the presence of ORC or skip
        # the test.
        try:
            self.prog.symbol("__start_orc_unwind")
        except LookupError:
            ver = self.prog["UTS_RELEASE"].string_().decode()
            self.skipTest(f"ORC is not available for {ver}")

        with drgn_log_level(logging.DEBUG):
            # It is difficult to test stack unwinding in a program without also
            # loading types, which necessarily will also make DWARF CFI and ORC
            # available in the debug file. The way we get around this is by creating
            # a new program with no debuginfo, getting a pt_regs from the program
            # that has debuginfo, and then using that to unwind the kernel. We still
            # need a symbol finder, and we'll need the Module API to recognize the
            # kernel address range correctly.
            prog = Program()
            prog.set_kernel()
            prog.register_symbol_finder(
                "vmlinux_kallsyms", load_vmlinux_kallsyms(prog), enable_index=0
            )
            main = prog.main_module(name="kernel", create=True)
            main.address_range = self.prog.main_module().address_range

            # Luckily, all drgn cares about for x86_64 pt_regs is that it is a
            # structure. Rather than creating a matching struct pt_regs definition,
            # we can just create a dummy one of the correct size:
            #     struct pt_regs { unsigned char[size]; };
            # Drgn will happily use that and reinterpret the bytes correctly.
            real_pt_regs_type = self.prog.type("struct pt_regs")
            fake_pt_regs_type = prog.struct_type(
                tag="pt_regs",
                size=real_pt_regs_type.size,
                members=[
                    TypeMember(
                        prog.array_type(
                            prog.int_type("unsigned char", 1, False),
                            real_pt_regs_type.size,
                        ),
                        "data",
                    ),
                ],
            )

            with fork_and_stop() as pid:
                trace = self.prog.stack_trace(pid)
                regs_dict = trace[0].registers()
                pt_regs_obj = Object(
                    self.prog,
                    real_pt_regs_type,
                    {
                        "bp": regs_dict["rbp"],
                        "sp": regs_dict["rsp"],
                        "ip": regs_dict["rip"],
                        "r15": regs_dict["r15"],
                    },
                )
                fake_pt_regs_obj = Object.from_bytes_(
                    prog, fake_pt_regs_type, pt_regs_obj.to_bytes_()
                )
                # We must set drgn's log level manually, beacuse it won't log messages
                # to the logger if it isn't enabled for them.
                with self.assertLogs("drgn", logging.DEBUG) as log:
                    no_debuginfo_trace = prog.stack_trace(fake_pt_regs_obj)

                dwarf_pcs = []
                for frame in trace:
                    if not dwarf_pcs or dwarf_pcs[-1] != frame.pc:
                        dwarf_pcs.append(frame.pc)
                orc_pcs = [frame.pc for frame in no_debuginfo_trace]
                self.assertEqual(dwarf_pcs, orc_pcs)
                self._check_logged_orc_message(log, "kernel")

    def test_registers(self):
        # Smoke test that we get at least one register and that
        # StackFrame.registers() agrees with StackFrame.register().
        with fork_and_stop() as pid:
            trace = self.prog.stack_trace(pid)
            have_registers = False
            for frame in trace:
                for name, value in frame.registers().items():
                    self.assertEqual(frame.register(name), value)
                    have_registers = True
            self.assertTrue(have_registers)

    def test_sp(self):
        # Smoke test that the stack pointer register shows up in
        # StackFrame.registers().
        with fork_and_stop() as pid:
            trace = self.prog.stack_trace(pid)
            self.assertIn(trace[0].sp, trace[0].registers().values())

    def test_prog(self):
        self.assertEqual(
            self.prog.stack_trace(Object(self.prog, "struct pt_regs", value={})).prog,
            self.prog,
        )

    def test_stack__repr_pretty_(self):
        with fork_and_stop() as pid:
            trace = self.prog.stack_trace(pid)
            assertReprPrettyEqualsStr(trace)
            for frame in trace:
                assertReprPrettyEqualsStr(frame)
