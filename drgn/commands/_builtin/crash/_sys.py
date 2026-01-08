# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Commands for getting system information."""

import argparse
import collections
import datetime
import functools
import itertools
import logging
import sys
from typing import (
    Any,
    Callable,
    Iterator,
    List,
    Literal,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from drgn import Architecture, Object, Program
from drgn.commands import (
    _repr_black,
    argument,
    argument_group,
    drgn_argument,
    mutually_exclusive_group,
)
from drgn.commands.crash import (
    Cpuspec,
    CrashDrgnCodeBuilder,
    _crash_get_panic_context,
    _format_seconds_duration,
    crash_command,
    crash_get_context,
    parse_cpuspec,
)
from drgn.helpers.common.format import (
    CellFormat,
    RowOptions,
    double_quote_ascii_string,
    escape_ascii_string,
    number_in_binary_units,
    print_table,
)
from drgn.helpers.linux.block import (
    disk_name,
    for_each_disk,
    request_queue_busy_iter,
    rq_data_dir,
)
from drgn.helpers.linux.cpumask import (
    cpumask_to_cpulist,
    num_online_cpus,
    num_present_cpus,
)
from drgn.helpers.linux.device import (
    MAJOR,
    for_each_registered_blkdev,
    for_each_registered_chrdev,
)
from drgn.helpers.linux.ioport import for_each_resource
from drgn.helpers.linux.irq import (
    for_each_irq_desc,
    gate_desc_func,
    irq_desc_action_names,
    irq_desc_affinity_mask,
    irq_desc_chip_name,
    irq_to_desc,
)
from drgn.helpers.linux.kconfig import _get_raw_kconfig
from drgn.helpers.linux.mm import totalram_pages
from drgn.helpers.linux.panic import panic_message, panic_task, tainted
from drgn.helpers.linux.pci import (
    PCI_EXP_TYPE,
    for_each_pci_root_bus,
    pci_bus_for_each_child,
    pci_bus_for_each_dev,
    pci_bus_name,
    pci_is_bridge,
    pci_name,
    pci_pcie_type,
)
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.printk import print_dmesg
from drgn.helpers.linux.sched import (
    get_task_state,
    loadavg,
    task_cpu,
    task_on_cpu,
    task_thread_info,
)
from drgn.helpers.linux.timekeeping import (
    ktime_get_boottime_seconds,
    ktime_get_real_seconds,
)

logger = logging.getLogger("drgn")


def _append_kernel(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.panic", "tainted")
    code.append(
        """\
try:
    kernel = prog.main_module().debug_file_path
except LookupError:
    kernel = None

taints = tainted()
"""
    )


def _get_kernel(prog: Program) -> Optional[str]:
    try:
        kernel = prog.main_module().debug_file_path
    except LookupError:
        kernel = None
    if tainted(prog):
        if kernel is None:
            kernel = "[TAINTED]"
        else:
            kernel += "  [TAINTED]"
    return kernel


def _append_dumpfile(code: CrashDrgnCodeBuilder) -> None:
    code.append("dumpfile = prog.core_dump_path\n")


def _get_dumpfile(prog: Program) -> Optional[str]:
    return prog.core_dump_path


def _append_cpus(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import(
        "drgn.helpers.linux.cpumask", "num_online_cpus", "num_present_cpus"
    )
    code.append(
        """\
cpus = num_present_cpus()
offline_cpus = cpus - num_online_cpus()
"""
    )


def _get_cpus(prog: Program) -> str:
    present = num_present_cpus(prog)
    online = num_online_cpus(prog)
    cpus = str(present)
    if present > online:
        cpus += f" [OFFLINE: {present - online}]"
    return cpus


def _append_date(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.timekeeping", "ktime_get_real_seconds")
    code.append("timestamp = ktime_get_real_seconds().value_()\n")


def _get_date(prog: Program) -> str:
    timestamp = ktime_get_real_seconds(prog).value_()
    dt = datetime.datetime.fromtimestamp(timestamp).astimezone()
    return dt.strftime("%a %b %e %T %Z %Y")


def _append_uptime(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.timekeeping", "uptime")
    code.append("uptime_ = uptime()\n")


def _get_uptime(prog: Program) -> str:
    return _format_seconds_duration(ktime_get_boottime_seconds(prog).value_())


def _append_load_average(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.sched", "loadavg")
    code.append("load_average = loadavg()\n")


def _get_load_average(prog: Program) -> str:
    return ", ".join([f"{v:.2f}" for v in loadavg(prog)])


def _append_tasks(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.pid", "for_each_task")
    code.append("num_tasks = sum(1 for _ in for_each_task())\n")


def _get_tasks(prog: Program) -> str:
    return str(sum(1 for _ in for_each_task(prog)))


def _append_utsname_field(code: CrashDrgnCodeBuilder, field: str) -> None:
    code.append(f'{field} = prog["init_uts_ns"].name.{field}.string_()\n')


def _get_utsname_field(prog: Program, field: str) -> str:
    return escape_ascii_string(
        getattr(prog["init_uts_ns"].name, field).string_(),
        escape_backslash=True,
    )


def _append_release(code: CrashDrgnCodeBuilder) -> None:
    code.append('release = prog["UTS_RELEASE"].string_()\n')


def _get_release(prog: Program) -> str:
    return escape_ascii_string(prog["UTS_RELEASE"].string_(), escape_backslash=True)


def _append_memory(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.mm", "totalram_pages")
    code.append('memory = totalram_pages() * prog["PAGE_SIZE"].value_()\n')


def _get_memory(prog: Program) -> str:
    return number_in_binary_units(totalram_pages(prog) * prog["PAGE_SIZE"])


def _append_panic(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.panic", "panic_message")
    code.append("panic = panic_message()\n")


def _get_panic(prog: Program) -> Optional[str]:
    message = panic_message(prog)
    if message is None:
        return message
    return double_quote_ascii_string(message)


def _append_pid(code: CrashDrgnCodeBuilder) -> None:
    code.append("pid = task.pid\n")


def _get_pid(task: Object) -> str:
    return str(task.pid.value_())


def _append_command(code: CrashDrgnCodeBuilder) -> None:
    code.append("comm = task.comm\n")


def _get_command(task: Object) -> str:
    return double_quote_ascii_string(task.comm.string_())


def _append_task(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.sched", "task_thread_info")
    code.append("thread_info = task_thread_info(task)\n")


def _get_task(task: Object) -> str:
    return f"{task.value_():x}  [THREAD_INFO: {task_thread_info(task).value_():x}]"


def _append_cpu(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.sched", "task_cpu")
    code.append("cpu = task_cpu(task)\n")


def _get_cpu(task: Object) -> str:
    return str(task_cpu(task))


def _append_state(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.panic", "panic_task")
    code.add_from_import("drgn.helpers.linux.sched", "get_task_state", "task_on_cpu")
    code.append(
        """\
state = get_task_state(task)
is_active = task_on_cpu(task)
is_panic = task == panic_task()
"""
    )


def _get_state(task: Object) -> str:
    state = get_task_state(task)
    if task == panic_task(task.prog_):
        state += " (PANIC)"
    elif task_on_cpu(task):
        state += " (ACTIVE)"
    return state


_FIELDS: List[
    Tuple[str, Callable[[CrashDrgnCodeBuilder], None], Callable[[Program], Any]]
] = [
    ("KERNEL", _append_kernel, _get_kernel),
    ("DUMPFILE", _append_dumpfile, _get_dumpfile),
    ("CPUS", _append_cpus, _get_cpus),
    ("DATE", _append_date, _get_date),
    ("UPTIME", _append_uptime, _get_uptime),
    ("LOAD AVERAGE", _append_load_average, _get_load_average),
    ("TASKS", _append_tasks, _get_tasks),
    (
        "NODENAME",
        functools.partial(_append_utsname_field, field="nodename"),
        functools.partial(_get_utsname_field, field="nodename"),
    ),
    ("RELEASE", _append_release, _get_release),
    (
        "VERSION",
        functools.partial(_append_utsname_field, field="version"),
        functools.partial(_get_utsname_field, field="version"),
    ),
    (
        "MACHINE",
        functools.partial(_append_utsname_field, field="machine"),
        functools.partial(_get_utsname_field, field="machine"),
    ),
    ("MEMORY", _append_memory, _get_memory),
    ("PANIC", _append_panic, _get_panic),
]

_TASK_FIELDS: List[
    Tuple[str, Callable[[CrashDrgnCodeBuilder], None], Callable[[Object], Any]]
] = [
    ("PID", _append_pid, _get_pid),
    ("COMMAND", _append_command, _get_command),
    ("TASK", _append_task, _get_task),
    ("CPU", _append_cpu, _get_cpu),
    ("STATE", _append_state, _get_state),
]


def _append_sys_drgn_system(code: CrashDrgnCodeBuilder) -> None:
    for _, append, _ in _FIELDS:
        append(code)


def _append_sys_drgn_task(code: CrashDrgnCodeBuilder) -> None:
    for _, append, _ in _TASK_FIELDS:
        append(code)


def _print_sys(
    prog: Program,
    system_fields: bool = True,
    context: Union[Literal["panic", "current"], Object, None] = None,
) -> Optional[Object]:
    if isinstance(context, Object) or context is None:
        task = context
    elif context == "panic":
        task = _crash_get_panic_context(prog)
    elif context == "current":
        task = crash_get_context(prog)
    else:
        raise ValueError("invalid context")

    rows = []

    if system_fields:
        for name, _, getter in _FIELDS:
            try:
                value = getter(prog)
            except Exception as e:
                logger.warning("couldn't get %s: %s", name, e)
                continue
            if value is not None:
                rows.append((CellFormat(name, ">"), value))

    if task is not None:
        for name, _, task_getter in _TASK_FIELDS:
            try:
                value = task_getter(task)
            except Exception as e:
                logger.warning("couldn't get %s: %s", name, e)
                continue
            if value is not None:
                rows.append((CellFormat(name, ">"), value))

    print_table(rows, sep=": ")
    return task


@crash_command(
    description="system information",
    arguments=(
        argument(
            "config",
            metavar="config",
            choices=("config",),
            nargs="?",
            help="print kernel configuration (requires ``CONFIG_IKCONFIG``)",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_sys(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.config:
        if args.drgn:
            sys.stdout.write(
                """\
from drgn.helpers.linux.kconfig import get_kconfig


kconfig = get_kconfig()
"""
            )
            return
        sys.stdout.write(_get_raw_kconfig(prog).decode())
        return

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        _append_sys_drgn_system(code)
        return code.print()
    _print_sys(prog)


def _print_ioports(prog: Program, drgn_arg: bool) -> None:
    if drgn_arg:
        sys.stdout.write(
            """\
from drgn.helpers.linux.ioport import for_each_resource


for resource in for_each_resource(prog["ioport_resource"].address_of_()):
    start = resource.start
    end = resource.end
    name = resource.name
"""
        )
        return

    rows: List[Sequence[Any]] = [
        (
            CellFormat("RESOURCE", "^"),
            CellFormat("RANGE", "^"),
            "NAME",
        )
    ]
    ioport_resource = prog["ioport_resource"]
    width = len(f"{ioport_resource.end.value_():x}")
    for resource in for_each_resource(ioport_resource.address_of_()):
        rows.append(
            (
                CellFormat(resource.value_(), "^x"),
                f"{resource.start.value_():0{width}x}-{resource.end.value_():0{width}x}",
                escape_ascii_string(resource.name.string_(), escape_backslash=True),
            )
        )
    print_table(rows)


def _append_pci_devs(rows: List[Sequence[Any]], bus: Object) -> None:
    first = True
    self = bus.self.read_()
    for dev in itertools.chain(((self,) if self else ()), pci_bus_for_each_dev(bus)):
        if first:
            rows.append(
                RowOptions(
                    (
                        "",
                        CellFormat("PCI DEV", "^"),
                        "DO:BU:SL.FN",
                        CellFormat("CLASS", ">"),
                        CellFormat("PCI_ID", "^"),
                        "TYPE",
                    ),
                    group=1,
                )
            )
            first = False

        type = pci_pcie_type(dev)
        type_str = type.name if isinstance(type, PCI_EXP_TYPE) else f"{type:x}"
        if pci_is_bridge(dev):
            type_str += " [BRIDGE]"
        rows.append(
            RowOptions(
                (
                    "",
                    CellFormat(dev.value_(), "^x"),
                    pci_name(dev),
                    CellFormat(f"{dev.member_('class').value_() >> 8:04x}", ">"),
                    f"{dev.vendor.value_():04x}:{dev.device.value_():04x}",
                    type_str,
                ),
                group=1,
            )
        )


def _append_pci_buses(
    rows: List[Sequence[Any]], parent_bus: Object, want_blank_line: bool
) -> None:
    for bus in pci_bus_for_each_child(parent_bus):
        if want_blank_line:
            rows.append(())
        want_blank_line = True

        rows.append(
            RowOptions(
                (
                    "",
                    CellFormat("PCI BUS", "^"),
                    CellFormat("PARENT BUS", "^"),
                ),
                group=2,
            )
        )
        rows.append(
            RowOptions(
                (
                    "",
                    CellFormat(bus.value_(), "^x"),
                    CellFormat(parent_bus.value_(), "^x"),
                ),
                group=2,
            )
        )
        _append_pci_devs(rows, bus)
        _append_pci_buses(rows, bus, True)


def _print_pci(prog: Program, drgn_arg: bool) -> None:
    if drgn_arg:
        sys.stdout.write(
            """\
from drgn.helpers.linux.pci import (
    for_each_pci_root_bus,
    pci_bus_for_each_child,
    pci_bus_for_each_dev,
    pci_bus_name,
    pci_is_bridge,
    pci_name,
    pci_pcie_type,
)


def visit_pci_dev(dev):
    do_bu_sl_fn = pci_name(dev)
    class_ = dev.member_("class") >> 8
    pci_id = f"{dev.vendor.value_():04x}:{dev.device.value_():04x}"
    type_ = pci_pcie_type(dev)
    is_bridge = pci_is_bridge(dev)


def visit_pci_bus(bus):
    for dev in pci_bus_for_each_dev(bus):
        visit_pci_dev(dev)
    for child_bus in pci_bus_for_each_child(bus):
        visit_pci_bus(child_bus)


for root_bus in for_each_pci_root_bus():
    busname = pci_bus_name(root_bus)
    visit_pci_bus(root_bus)
"""
        )
        return

    rows: List[Sequence[Any]] = []
    first = True
    for bus in for_each_pci_root_bus(prog):
        if first:
            first = False
        else:
            rows.append(())

        rows.append(
            (
                CellFormat("ROOT BUS", "^"),
                "BUSNAME",
            )
        )
        rows.append(
            (
                CellFormat(bus.value_(), "^x"),
                pci_bus_name(bus),
            )
        )
        _append_pci_devs(rows, bus)
        _append_pci_buses(rows, bus, False)
    print_table(rows)


def _print_disks(prog: Program, drgn_arg: bool, only_busy: bool) -> None:
    if drgn_arg:
        sys.stdout.write(
            """\
from drgn.helpers.linux.block import (
    disk_name,
    for_each_disk,
    request_queue_busy_iter,
    rq_data_dir,
)


for disk in for_each_disk():
    major = disk.major
    name = disk_name(disk)
    queue = disk.queue
    read = write = 0
    for rq in request_queue_busy_iter(queue):
        if rq_data_dir(rq):
            write += 1
        else:
            read += 1
    total = read + write
"""
        )
        return

    rows: List[Sequence[Any]] = [
        (
            CellFormat("MAJOR", ">"),
            "GENDISK",
            "NAME",
            "REQUEST_QUEUE",
            CellFormat("TOTAL", ">"),
            CellFormat("READ", ">"),
            CellFormat("WRITE", ">"),
        )
    ]
    for disk in for_each_disk(prog):
        queue = disk.queue.read_()
        num_ops = [0, 0]
        for rq in request_queue_busy_iter(queue):
            num_ops[rq_data_dir(rq)] += 1
        total_ops = sum(num_ops)
        if not total_ops and only_busy:
            continue

        rows.append(
            (
                disk.major.value_(),
                CellFormat(disk.value_(), "<x"),
                escape_ascii_string(disk_name(disk), escape_backslash=True),
                CellFormat(disk.queue.value_(), "<x"),
                total_ops,
                *num_ops,
            ),
        )
    print_table(rows)


@crash_command(
    description="devices",
    arguments=(
        argument_group(
            mutually_exclusive_group(
                argument(
                    "-i",
                    dest="ioport",
                    action="store_true",
                    help="display I/O port regions",
                ),
                argument(
                    "-p",
                    dest="pci",
                    action="store_true",
                    help="display PCI devices",
                ),
                argument(
                    "-d",
                    dest="disk",
                    action="store_true",
                    help="display all disks and their number of in-progress requests",
                ),
                argument(
                    "-D",
                    dest="busy_disk",
                    action="store_true",
                    help="""
                    like **-d**, but only display disks that have in-progress
                    requests
                    """,
                ),
            ),
            title="type",
            description="""
            What type of devices to display. If not given, display registered
            character and block device majors.
            """,
        ),
        drgn_argument,
    ),
)
def _crash_cmd_dev(
    prog: Program, command_name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.ioport:
        return _print_ioports(prog, args.drgn)
    elif args.pci:
        return _print_pci(prog, args.drgn)
    elif args.disk or args.busy_disk:
        return _print_disks(prog, args.drgn, args.busy_disk)

    if args.drgn:
        sys.stdout.write(
            """\
from drgn.helpers.linux.block import for_each_disk
from drgn.helpers.linux.device import (
    MAJOR,
    for_each_registered_blkdev,
    for_each_registered_chrdev,
)


for dev, _, name, cdev in for_each_registered_chrdev():
    major = MAJOR(dev)
    if cdev:
        operations = cdev.ops


for major, name, _ in for_each_registered_blkdev():
    pass


for disk in for_each_disk():
    major = disk.major
    operations = disk.fops
"""
        )
        return

    rows: List[Sequence[Any]] = [
        (
            "CHRDEV",
            "NAME",
            CellFormat("CDEV", "^"),
            "OPERATIONS",
        )
    ]
    for dev, _, name, cdev in for_each_registered_chrdev(prog):
        operations_cell: Any = ""
        if cdev:
            cdev_cell = CellFormat(cdev.value_(), "^x")
            ops = cdev.ops.value_()
            try:
                operations_cell = prog.symbol(ops).name
            except LookupError:
                operations_cell = CellFormat(ops, "x")
        else:
            cdev_cell = CellFormat("(none)", "^")
        rows.append(
            (
                MAJOR(dev),
                escape_ascii_string(name, escape_backslash=True),
                cdev_cell,
                operations_cell,
            )
        )

    rows.append(())

    major_to_gendisk = collections.defaultdict(list)
    for disk in for_each_disk(prog):
        major_to_gendisk[disk.major.value_()].append(disk)
    major_to_gendisk.default_factory = None

    rows.append(
        (
            "BLKDEV",
            "NAME",
            CellFormat("GENDISK", "^"),
            "OPERATIONS",
        )
    )

    for major, name, _ in for_each_registered_blkdev(prog):
        name_string = escape_ascii_string(name, escape_backslash=True)
        try:
            gendisks = major_to_gendisk[major]
        except KeyError:
            rows.append((major, name_string, CellFormat("(none)", "^")))
        else:
            cell0: Any = major
            cell1: Any = name_string
            # Crash only lists the first gendisk per major, but we list all of
            # them.
            for disk in gendisks:
                ops = disk.fops.value_()
                try:
                    operations_cell = prog.symbol(ops).name
                except LookupError:
                    operations_cell = CellFormat(ops, "x")
                rows.append(
                    (cell0, cell1, CellFormat(disk.value_(), "^x"), operations_cell)
                )
                cell0 = cell1 = ""

    print_table(rows)


def _print_idt(prog: Program, drgn_arg: bool) -> None:
    if prog.platform.arch != Architecture.X86_64:  # type: ignore[union-attr]  # platform can't be None.
        raise ValueError("-d is only supported on x86")

    if drgn_arg:
        sys.stdout.write(
            """\
from drgn.helpers.linux.irq import gate_desc_func


for vec, gate in enumerate(prog["idt_table"]):
    func = gate_desc_func(gate)
    try:
        sym = prog.symbol(func)
    except LookupError:
        pass
"""
        )
        return

    rows: List[Sequence[Any]] = []
    for vec, gate in enumerate(prog["idt_table"]):
        func = gate_desc_func(gate).value_()
        try:
            sym = prog.symbol(func)
        except LookupError:
            func_cell: Any = CellFormat(func, "<x")
        else:
            if sym.address == func:
                func_cell = sym.name
            else:
                func_cell = f"{sym.name}+{func - sym.address}"
        rows.append((CellFormat(f"[{vec}]", ">"), func_cell))
    print_table(rows, sep=" ")


def _print_softirqs(prog: Program, drgn_arg: bool) -> None:
    if drgn_arg:
        sys.stdout.write(
            """\
for vec, softirq_action in enumerate(prog["softirq_vec"]):
    action = softirq_action.action
    try:
        sym = prog.symbol(action)
    except LookupError:
        pass
"""
        )
        return

    rows: List[Sequence[Any]] = [
        (
            CellFormat("SOFTIRQ_VEC", "^"),
            CellFormat("ACTION", "^"),
        )
    ]
    for vec, softirq_action in enumerate(prog["softirq_vec"]):
        action = softirq_action.action.value_()
        try:
            sym = prog.symbol(action)
        except LookupError:
            func_cell = ""
        else:
            func_cell = f"<{sym.name}>"
        rows.append((CellFormat(f"[{vec}]", "^"), CellFormat(action, "^x"), func_cell))
    print_table(rows)


def _print_irq_affinity(prog: Program, drgn_arg: bool) -> None:
    if drgn_arg:
        # Normally we don't bother showing how to format output, but
        # cpumask_to_cpulist() is useful to know.
        sys.stdout.write(
            """\
from drgn.helpers.linux.cpumask import cpumask_to_cpulist
from drgn.helpers.linux.irq import (
    for_each_irq_desc,
    irq_desc_action_names,
    irq_desc_affinity_mask,
)


for irq, irq_desc in for_each_irq_desc():
    names = irq_desc_action_names(irq_desc)
    if not names:
        continue
    affinity = irq_desc_affinity_mask(irq_desc)
    affinity_list = cpumask_to_cpulist(affinity)
"""
        )
        return

    rows: List[Sequence[Any]] = [("IRQ", "NAME", "AFFINITY")]
    for irq, irq_desc in for_each_irq_desc(prog):
        action_names = irq_desc_action_names(irq_desc)
        if not action_names:
            continue
        rows.append(
            (
                irq,
                escape_ascii_string(b",".join(action_names), escape_backslash=True),
                cpumask_to_cpulist(irq_desc_affinity_mask(irq_desc)),
            )
        )
    print_table(rows)


def _print_irq_stats(prog: Program, drgn_arg: bool, cpuspec: Cpuspec) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        multiple_cpus = code.append_cpuspec_list(cpuspec)

        code.add_from_import(
            "drgn.helpers.linux.irq",
            "for_each_irq_desc",
            "irq_desc_action_names",
            "irq_desc_chip_name",
            "irq_desc_kstat_cpu",
        )
        code.append(
            """\
for irq, irq_desc in for_each_irq_desc():
    names = irq_desc_action_names(irq_desc)
    if not names:
        continue

    chip_name = irq_desc_chip_name(irq_desc)

"""
        )

        if multiple_cpus:
            code.append("    for cpu in cpus:\n    ")
        code.append("    count = irq_desc_kstat_cpu(irq_desc, cpu)\n")
        return code.print()

    cpus = cpuspec.cpus(prog)

    header: List[Any] = [""]
    for cpu in cpus:
        header.append(CellFormat(f"CPU{cpu}", ">"))
    rows: List[Sequence[Any]] = [header]

    for irq, irq_desc in for_each_irq_desc(prog):
        action_names = irq_desc_action_names(irq_desc)
        if not action_names:
            continue

        row: List[Any] = [CellFormat(f"{irq}:", ">")]
        # Open-code irq_desc_kstat_cpu() for efficiency. See the comment in
        # that function re: Linux kernel commit 86d2a2f51fba ("genirq: Convert
        # kstat_irqs to a struct") (in v6.10).
        kstat_irqs = irq_desc.kstat_irqs.read_()
        if kstat_irqs:
            try:
                kstat_irqs_cnt = kstat_irqs.cnt
            except AttributeError:
                kstat_irqs_cnt = kstat_irqs[0]
            for cpu in cpus:
                row.append(per_cpu(kstat_irqs_cnt, cpu).value_())
        else:
            row.extend([0] * len(cpus))
        chip_name = irq_desc_chip_name(irq_desc)
        row.append(
            ""
            if chip_name is None
            else escape_ascii_string(chip_name, escape_backslash=True)
        )
        row.append(escape_ascii_string(b",".join(action_names), escape_backslash=True))
        rows.append(row)

    print_table(rows)


@crash_command(
    description="interrupt requests/descriptors",
    long_description="""
    Show interrupt information. By default, display all interrupt descriptors.
    """,
    arguments=(
        mutually_exclusive_group(
            argument(
                "-u",
                dest="only_used",
                action="store_true",
                help="display only allocated interrupt descriptors",
            ),
            argument(
                "-d",
                dest="idt",
                action="store_true",
                help="display the x86 IDT (interrupt descriptor table)",
            ),
            argument(
                "-b",
                dest="bottom_half",
                action="store_true",
                help="display softirqs (a.k.a. bottom half)",
            ),
            argument(
                "-a",
                dest="affinity",
                action="store_true",
                help="display CPU affinity for in-use interrupts",
            ),
            argument(
                "-s",
                dest="stats",
                action="store_true",
                help="display statistics for in-use interrupts",
            ),
            argument(
                "number",
                type=int,
                nargs="*",
                # Work around https://github.com/python/cpython/issues/72795
                # before Python 3.13.
                default=[],
                help="""
                display the interrupt descriptor for the given IRQ number. May
                be given multiple times
                """,
            ),
        ),
        argument(
            "-c",
            dest="cpu",
            help="""
            when used with -s, restrict the output to one or more CPUs, which
            may be a comma-separated string of CPU numbers or ranges (e.g.,
            '0,3-4')
            """,
        ),
        drgn_argument,
    ),
)
def _crash_cmd_irq(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    *,
    parser: argparse.ArgumentParser,
    **kwargs: Any,
) -> None:
    if args.stats:
        if args.cpu is None:
            args.cpu = "all"
        return _print_irq_stats(prog, args.drgn, parse_cpuspec(args.cpu))
    elif args.cpu is not None:
        parser.error("-c can only be used with -s")

    if args.idt:
        return _print_idt(prog, args.drgn)
    elif args.bottom_half:
        return _print_softirqs(prog, args.drgn)
    elif args.affinity:
        return _print_irq_affinity(prog, args.drgn)

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        indent = "    "
        if args.number:
            code.add_from_import("drgn.helpers.linux.irq", "irq_to_desc")
            if len(args.number) > 1:
                code.append("for irq in (")
                code.append(", ".join([str(number) for number in args.number]))
                code.append("):\n    irq_desc = irq_to_desc(irq)\n")
            else:
                code.append(f"irq_desc = irq_to_desc({args.number[0]})\n")
                indent = ""
        else:
            # Unused descriptors aren't very interesting, so our output with
            # and without -u is the same.
            code.add_from_import("drgn.helpers.linux.irq", "for_each_irq_desc")
            code.append("for irq, irq_desc in for_each_irq_desc():\n")
        code.append(
            f"""\
{indent}action = irq_desc.action.read_()
{indent}while action:
{indent}    name = action.name
{indent}    action = action.next.read_()
"""
        )
        return code.print()

    if args.number:

        def irq_descs(prog: Program) -> Iterator[Tuple[int, Optional[Object]]]:
            nr_irqs = prog["nr_irqs"].value_()
            for number in args.number:
                if number >= nr_irqs:
                    print("irq: invalid IRQ number:", number)
                else:
                    irq_desc = irq_to_desc(prog, number)
                    yield number, irq_desc

    elif args.only_used:
        irq_descs = for_each_irq_desc
    else:

        def irq_descs(prog: Program) -> Iterator[Tuple[int, Optional[Object]]]:
            prev_irq = -1
            for irq, irq_desc in for_each_irq_desc(prog):
                for prev_irq in range(prev_irq + 1, irq):
                    yield prev_irq, None
                prev_irq = irq
                yield irq, irq_desc
            for irq in range(prev_irq + 1, prog["nr_irqs"]):
                yield irq, None

    rows: List[Sequence[Any]] = [
        (
            CellFormat("IRQ", "^"),
            # Crash calls this IRQ_DESC/_DATA, but irq_data is not at the same
            # address as irq_desc since Linux kernel commit 0d0b4c866bcc
            # ("genirq: Introduce struct irq_common_data to host shared irq
            # data") (in v4.2).
            CellFormat("IRQ_DESC", "^"),
            CellFormat("IRQACTION", "^"),
            "NAME",
        )
    ]
    for irq, irq_desc in irq_descs(prog):
        if not irq_desc:
            rows.append(
                (
                    CellFormat(irq, "^"),
                    CellFormat("(unused)", "^"),
                    CellFormat("(unused)", "^"),
                )
            )
            continue

        irq_cell: Any = CellFormat(irq, "^")
        irq_desc_cell: Any = CellFormat(irq_desc.value_(), "^x")
        action = irq_desc.action.read_()
        if action:
            while True:
                rows.append(
                    (
                        irq_cell,
                        irq_desc_cell,
                        CellFormat(action.value_(), "^x"),
                        double_quote_ascii_string(action.name.string_()),
                    )
                )
                action = action.next.read_()
                if not action:
                    break
                irq_cell = irq_desc_cell = ""
        else:
            rows.append((irq_cell, irq_desc_cell, CellFormat("(unused)", "^")))

    if len(rows) > 1:
        print_table(rows)


@crash_command(
    description="Dump kernel dmesg",
    arguments=(
        mutually_exclusive_group(
            argument(
                "-T",
                dest="timestamps",
                action="store_const",
                const="human",
                default=True,
                help="Dump kernel dmesg in human readable time",
            ),
            argument(
                "-t",
                dest="timestamps",
                action="store_false",
                default=argparse.SUPPRESS,
                help="Dump kernel dmesg without timestamp",
            ),
        ),
        drgn_argument,
    ),
)
def _crash_cmd_log(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.printk", "get_dmesg")
        code.append(
            """\
# Or print_dmesg() if you just want to print it.
dmesg = get_dmesg("""
        )
        if isinstance(args.timestamps, str):
            code.append(f"timestamps={_repr_black(args.timestamps)}")
        elif not args.timestamps:
            code.append("timestamps=False")
        code.append(")\n")
        return code.print()
    print_dmesg(prog, timestamps=args.timestamps)
