# GDB 'drgn-why-sleeping' command.
# Copyright (C) 2026 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Implementation of the GDB 'drgn-why-sleeping' command using the GDB Python API."""

import os
import subprocess
import sys

import gdb


class DrgnWhySleeping(gdb.Command):
    """Show a thread's kernel stack or selected kernel-frame variables.

    Usage: drgn-why-sleeping [FRAME_OR_INDEX [VARIABLE.FIELD ...]]

    Requires drgn and debugging information for the running kernel.
    GDB must run in the initial PID namespace.
    May prompt for sudo permission to open /proc/kcore.

    Enable non-stop mode before starting or attaching to the inferior.
    Resume the selected thread before inspecting its sleeping kernel stack:
    In non-stop mode, "continue &" resumes the selected thread in the
    background and immediately returns to the GDB prompt. This lets the
    command inspect the thread while it sleeps inside the system call,
    rather than while it is stopped by GDB.

        (gdb) set non-stop on
        (gdb) attach PID
        (gdb) info threads
        (gdb) thread THREAD_NUM
        (gdb) bt
        (gdb) continue &
        (gdb) drgn-why-sleeping

    A thread stopped by GDB may show ptrace_stop instead of its original
    blocking location. Variables may be unavailable due to optimization.

        (gdb) drgn-why-sleeping FRAME_OR_INDEX
        (gdb) drgn-why-sleeping FRAME_OR_INDEX FIELD ...

    Without arguments, print the selected thread's kernel stack.
    With FRAME_OR_INDEX, select a frame by function name or by its zero-based
    index in the printed stack, and print all available local variable names
    and values. If a function name occurs more than once, select the first
    matching frame. Use an index to select another occurrence.
    With FIELD arguments, print only the requested variables or
    dot-separated member paths.

    Example:
        (gdb) drgn-why-sleeping vfs_read file.f_op count file.f_flags

    This prints the file operations, requested read size, and file flags.
    Variables unavailable due to optimization are reported individually.

    To print the available local variables for frame 3:
        (gdb) drgn-why-sleeping 3
    """

    def __init__(self) -> None:
        super(DrgnWhySleeping, self).__init__(
            name="drgn-why-sleeping", command_class=gdb.COMMAND_STATUS, prefix=False
        )

    def invoke(self, arg_str: str, from_tty: bool) -> None:
        if not sys.platform.startswith("linux"):
            raise gdb.GdbError("This command requires a Linux host.")
        thread = gdb.selected_thread()
        if thread is None:
            raise gdb.GdbError("Select a live Linux thread first.")

        connection = gdb.selected_inferior().connection
        if connection is None or connection.type != "native":
            raise gdb.GdbError("This command supports only local native debugging.")
        if thread.is_exited():
            raise gdb.GdbError("The selected thread has exited.")
        tid = thread.ptid[1]
        if tid <= 0:
            raise gdb.GdbError("The selected thread has no valid Linux LWP ID.")

        if thread.is_stopped():
            print(
                "The selected thread is stopped by GDB and its kernel "
                "stack may show ptrace_stop. In non-stop mode, use "
                "'continue &' to resume it before inspecting its syscall stack."
            )

        try:
            import drgn
            from drgn.helpers.linux.pid import find_task
            from drgn.helpers.linux.sched import task_state_to_char
        except ImportError as error:
            raise gdb.GdbError(f"This command requires drgn: {error}") from error
        try:
            from drgn.internal.sudohelper import open_via_sudo
        except ImportError as error:
            raise gdb.GdbError(
                "This command requires a drgn version providing "
                "drgn.internal.sudohelper.open_via_sudo."
            ) from error
        args = gdb.string_to_argv(arg_str)

        try:
            prog = drgn.Program()
            try:
                prog.set_kernel()
            except PermissionError:
                fd = open_via_sudo("/proc/kcore", os.O_RDONLY)
                prog.set_core_dump(fd)

            try:
                prog.load_debug_info(default=True)
            except drgn.MissingDebugInfoError as error:
                try:
                    main_module = prog.main_module()
                    critical = (
                        main_module.wants_debug_file()
                        or main_module.wants_loaded_file()
                    )
                except LookupError:
                    critical = True

                if critical:
                    raise

                gdb.write(f"warning: {error}\n", gdb.STDERR)
        except subprocess.CalledProcessError as error:
            raise gdb.GdbError(
                f"sudo helper failed (exit status {error.returncode})"
            ) from error
        except Exception as e:
            raise gdb.GdbError(f"Could not initialize drgn: {e}") from e

        try:
            # GDB's LWP IDs are relative to its PID namespace, while find_task()
            # defaults to the kernel's initial PID namespace. Verify that they match
            # before looking up a task, since the same ID can identify different tasks
            # in different namespaces.
            namespace_inode = os.stat("/proc/self/ns/pid").st_ino
            initial_namespace_inode = prog["init_pid_ns"].ns.inum.value_()
        except (OSError, LookupError, AttributeError, drgn.FaultError) as error:
            raise gdb.GdbError(
                f"Could not verify GDB's PID namespace: {error}"
            ) from error
        if namespace_inode != initial_namespace_inode:
            raise gdb.GdbError(
                "GDB is running in a nested PID namespace, "
                "which this command does not support."
            )

        task = find_task(prog, tid)
        if not task:
            raise gdb.GdbError(
                f"Linux task with LWP ID {tid} was not found; "
                "the thread may have exited."
            )

        task_state = task_state_to_char(task)
        stack = prog.stack_trace(task)
        print(f"Task state: {task_state}")
        if not args:
            print(stack)
            return

        frame_name = args[0]
        if frame_name.isdecimal():
            index = int(frame_name)
            if index >= len(stack):
                raise gdb.GdbError(f"Frame index out of range: {index}")
            frame = stack[index]
        else:
            for frame in stack:
                if frame.name == frame_name:
                    break
            else:
                raise gdb.GdbError(f"Frame not found: {frame_name}")

        print(frame)
        fields = args[1:] or frame.locals()

        for field in fields:
            try:
                parts = field.split(".")
                value = frame[parts[0]]
                for member in parts[1:]:
                    value = value.member_(member)
                print(f"  {field} = {value.format_(dereference=False)}")
            except (
                KeyError,
                AttributeError,
                LookupError,
                TypeError,
                drgn.FaultError,
                drgn.ObjectAbsentError,
            ) as error:
                print(f"  {field}: unavailable ({error})")


DrgnWhySleeping()
