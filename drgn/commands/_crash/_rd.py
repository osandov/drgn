# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
import argparse
import operator
import string
from typing import Any, Dict, Literal, Optional

from drgn import FaultError, IntegerLike, PlatformFlags, Program
from drgn.commands import argument, drgn_argument, mutually_exclusive_group
from drgn.commands._crash.common import (
    CrashDrgnCodeBuilder,
    _resolve_addr_or_sym,
    crash_command,
    crash_get_context,
)
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.common.memory import IdentifiedSymbol, identify_address_all
from drgn.helpers.linux.common import IdentifiedSlabObject
from drgn.helpers.linux.mm import access_process_vm


def _crash_annotate(
    prog: Program,
    addr: int,
    level: Literal[None, "symbols", "slab", "verbose"],
    cache: Dict[Any, Any],
) -> Optional[str]:
    """Returns the crash-compatible annotation for a word of memory"""
    if level is None:
        return None
    for identified in identify_address_all(prog, addr, cache=cache):
        if isinstance(identified, IdentifiedSymbol):
            fmt = str if prog.cache.get("crash_radix", 10) == 10 else hex
            symbol = identified.symbol
            return f"{symbol.name}+{fmt(addr - symbol.address)}"
        elif isinstance(identified, IdentifiedSlabObject) and level in (
            "slab",
            "verbose",
        ):
            if identified.slab_object_info.address:
                cache_name = escape_ascii_string(
                    identified.slab_object_info.slab_cache.name.string_()
                )
            else:  # SLOB
                cache_name = "unknown slab object"
            if level == "slab":
                return f"[{cache_name}]"
            else:
                # Crash does not pad the address at all, which can help with
                # output alignment on some architectures.
                return f"[{addr:x}:{cache_name}]"
    return None


def _print_memory(
    prog: Program,
    address: IntegerLike,
    mem: bytes,
    unit: Literal[1, 2, 4, 8] = 1,
    show_ascii: bool = True,
    annotate: Literal[None, "symbols", "slab", "verbose"] = None,
    format: Literal["x", "d", "u"] = "x",
    endian: Literal["little", "big", None] = None,
    cache: Optional[Dict[Any, Any]] = None,
    indent: str = "",
    address_pad: str = "",
) -> None:
    """
    Read memory, format, and print output to stdout

    This function roughly mimics output formatting of crash's ``rd`` command. It
    allows printing in units of 1, 2, 4, or 8 bytes. Each line is always
    prefixed by the memory address, followed by 16 bytes of data formatted
    according to the options.

    :param address: starting address for the memory content
    :param mem: the memory contents. The length of the memory must be a
      multiple of the unit.
    :param unit: the number of bytes per integer to format (default is 1)
    :param show_ascii: show ASCII translations of bytes at the end of each line
    :param annotate: replace memory contents with annotations where applicable.
      Following crash's behaviors: "symbols" annotates with symbol + offset.
      "slab" includes slab cache names, and "verbose" will include slab cache
      address + name. This option can only be enabled when the unit matches the
      program word size, and when displaying as hexadecimal (not decimal).
    :param format: control the integer formatting. Use code "x" for hex (the
      default), "d" for signed integer, and "u" for unsigned integer.
    :param endian: control the endianness (default is platform's endianness)
    :param cache: opaque cache passed to :func:`identify_address_all()`
    """
    word_size = prog.address_size()
    assert unit in (1, 2, 4, 8)
    assert prog.platform is not None  # already verified by address_size()
    if len(mem) % unit != 0:
        raise ValueError("memory size must be an increment of unit")
    if annotate and unit != word_size:
        raise ValueError(
            "Annotations may only be printed for units of the platform word size"
        )
    if annotate and format != "x":
        raise ValueError("Annotations may only be printed with hexadecimal format")
    address = operator.index(address)

    byteorder: Literal["little", "big"]
    if endian is not None:
        byteorder = endian
    elif prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
        byteorder = "little"
    else:
        byteorder = "big"

    chars: Dict[int, str] = {}
    if show_ascii:
        chars = {
            ord(s): s
            for s in string.ascii_letters + string.digits + string.punctuation + " "
        }

    if cache is None:
        cache = {}

    # Control the field width and padding for alignmment
    signed = False
    if format == "x":
        width = unit * 2
        value_pad = "0"
    else:
        # Crash does not correctly align decimal integers in all cases. This
        # seems like a bug: let's accurately determine the max width and get
        # correct alignment.
        if format == "d":
            widest_value = -(1 << (8 * unit - 1))
            signed = True
        else:
            widest_value = (1 << (8 * unit)) - 1
            # "u" is not actually a valid format code for Python, since ints
            # encode their sign intrinsically. Now that we've detected whether
            # signed integers are intended, set the format code correctly.
            format = "d"
        width = len(str(widest_value))
        value_pad = ""

    bytes_per_line = 16
    units_per_line = bytes_per_line // unit
    for offset in range(0, len(mem), unit):
        line_index = (offset % bytes_per_line) // unit
        if line_index == 0:
            print(f"{indent}{offset + address:{address_pad}{word_size * 2}x}: ", end="")
        value = int.from_bytes(mem[offset : offset + unit], byteorder, signed=signed)
        identified = _crash_annotate(prog, value, annotate, cache)
        if identified is not None:
            print(f" {identified:{width}s}", end="")
        else:
            print(f" {value:{value_pad}{width}{format}}", end="")

        is_end = (line_index + 1 == units_per_line) or offset + unit == len(mem)
        if is_end and show_ascii:
            # In case we didn't fill the line, pad it out so the ascii encoding
            # aligns with the ones above.
            padding = (units_per_line - line_index - 1) * (1 + width)
            print(
                " " * padding
                + "   "
                + "".join(
                    chars.get(b, ".")
                    for b in mem[offset - (offset % 16) : offset + unit]
                )
            )
        elif is_end:
            print()


def _dump_printable_memory(
    prog: Program,
    address: IntegerLike,
    count: Optional[int],
    physical: bool = False,
    kernel: bool = False,
) -> None:
    """Write ASCII printable memory contents, compatible with crash rd -a."""
    printable = set(string.printable)
    # whitespace characters other than space and newline are not printed by crash
    disallowed_ws = set(string.whitespace) - set(" \n")
    address = operator.index(address)
    if count is None:
        count = 1024 * 1024  # 1 MiB is a reasonable, if arbitrary, limit

    print_newline = True
    width = prog.address_size() * 2
    line_width = 0
    task = crash_get_context(prog)
    for offset in range(count):
        if kernel:
            byte = prog.read_u8(address + offset, physical=physical)
        else:
            byte = access_process_vm(task, address + offset, 1)[0]
        # For non-ascii bytes this gives the corresponding unicode code point.
        # That's fine because none of those characters will be present in
        # string.printable, by definition
        char = chr(byte)
        if char not in printable:
            break
        if print_newline:
            print(f"{address + offset:{width}x}:  ", end="")
            print_newline = False
            line_width = width + 3

        if char not in disallowed_ws:
            print(char, end="")
            line_width += 1
        if char == "\n":
            print_newline = True
        if line_width >= 79:
            print()
            print_newline = True

    # Print a \n to flush stdout, if we didn't just do so
    if not print_newline:
        print()


@crash_command(
    description="read memory",
    long_description="""
    This command displays the contents of memory, formatted in several different
    ways.
    """,
    arguments=(
        argument(
            "start",
            metavar="address|symbol",
            type="addr_or_sym",
            help="starting hexadecimal address, or symbol of starting address",
        ),
        argument(
            "count",
            type=int,
            help="decimal number of memory locations to display (default: 1)",
            nargs="?",
        ),
        mutually_exclusive_group(
            argument(
                "-p",
                dest="physical",
                action="store_true",
                help="address argument is a physical address",
            ),
            argument(
                "-u",
                dest="user",
                action="store_true",
                help="address argument is a user virtual address; this is only "
                "required on processors or configurations where user and kernel "
                "virtual address spaces overlap, such as s390x, or 32-bit "
                "processors with 4G:4G kernel configurations. In other cases, "
                "this can still be used as a hint.",
            ),
        ),
        mutually_exclusive_group(
            argument(
                "-d",
                dest="format",
                action="store_const",
                const="d",
                default="x",
                help="display output in signed decimal format (default is hexadecimal)",
            ),
            argument(
                "-D",
                dest="format",
                action="store_const",
                const="u",
                help="display output in unsigned decimal format (default is hexadecimal)",
            ),
        ),
        argument(
            "-s",
            dest="annotate",
            action="store_const",
            const="symbols",
            help="displays output symbolically where appropriate",
        ),
        argument(
            "-S",
            dest="annotate_extra",
            action="count",
            default=0,
            help="displays output symbolically where appropriate; if the "
            "memory contents reference a slab cache object, the name of "
            "the slab cache will be displayed in brackets. If -S is entered "
            "twice, and the memory contents reference a slab cache object, "
            "both the memory contents and the name of the slab cache will "
            "be displayed in brackets",
        ),
        argument(
            "-x",
            dest="show_ascii",
            action="store_false",
            help="do not display ASCII translation at the end of each line",
        ),
        mutually_exclusive_group(
            argument(
                "-8",
                dest="unit",
                action="store_const",
                const=1,
                help="display output in 8-bit values",
            ),
            argument(
                "-16",
                dest="unit",
                action="store_const",
                const=2,
                help="display output in 16-bit values",
            ),
            argument(
                "-32",
                dest="unit",
                action="store_const",
                const=4,
                help="display output in 32-bit values (default on 32-bit machines)",
            ),
            argument(
                "-64",
                dest="unit",
                action="store_const",
                const=8,
                help="display output in 64-bit values (default on 64-bit machines)",
            ),
            argument(
                "-a",
                dest="ascii",
                action="store_true",
                help="display output in ASCII characters if it contains printable "
                "ASCII characters",
            ),
        ),
        argument(
            "-N",
            dest="endian",
            action="store_const",
            const="big",
            help="display output in network byte order",
        ),
        argument(
            "-R",
            dest="reverse",
            action="store_true",
            help="display memory in reverse order; memory will be displayed up to and "
            "including the address argument, requiring the count argument to be greater "
            "than 1 to display memory before the specified address. Conflicts with -e.",
        ),
        argument(
            "-o",
            dest="offset",
            default=0,
            type="decimal_or_hexadecimal",
            help="offset applied to the starting address",
        ),
        argument(
            "-e",
            dest="end",
            type="hexadecimal",
            help="display memory until reaching this hexadecimal address",
        ),
        argument(
            "-r",
            dest="raw",
            type=str,
            help="dumps raw data to the specified output file; the number of bytes that "
            "are copied to the file must be specified either by a count argument or by "
            "the -e option",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_rd(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.reverse and args.end:
        raise ValueError("both -R and -e cannot be specified together")
    if args.physical and args.start[0] == "sym":
        raise ValueError("physical addresses cannot be specified by symbol")
    if args.raw and args.unit not in (None, 1):
        raise ValueError("cannot specify -r and a unit size other than 1 byte")
    if args.end is not None and args.count is not None:
        raise ValueError("only one of count and -e may be specified")
    # The -S argument can be repeated, and should result in the "annotate" field
    # being updated. Argparse can't really do it, so do it here.
    if args.annotate_extra > 1:
        args.annotate = "verbose"
    elif args.annotate_extra == 1:
        args.annotate = "slab"
    # In order for crash commands to even run, we need to have a Linux kernel
    # program, which guarantees that we have a platform. But mypy doesn't know
    # that.
    assert prog.platform is not None

    # For compatibility with crash, only enable annotations for hex output
    if args.format != "x":
        args.annotate = None
    # For compatibility with crash, disable the ascii translation when
    # annotations are enabled, or for non-hexadecimal formats
    if args.annotate is not None or args.format != "x":
        args.show_ascii = False
    # The unit default is the word size, unless reading ascii data or dumping
    # directly to a file.
    if args.unit is None:
        if args.ascii or args.raw:
            args.unit = 1
        else:
            args.unit = prog.address_size()
    # Unless we're printing ascii strings, default count to be 1. Ascii string
    # mode needs to know whether count was specified, since that is used as the
    # maximum read size.
    if args.count is None and not args.ascii:
        args.count = 1

    # We're doing something a little odd here, by reading the memory even before
    # we've emitted the drgn code. This helps us emit the correct drgn code by
    # heuristically determining whether we've been given a user or kernel
    # address. It wouldn't make sense for the --drgn operation to raise errors
    # related to looking up a symbol or reading the memory, so we need to catch
    # those errors and emit corresponding code anyway (even though it would
    # fail!). Only raise the resulting errors later, once we know we're not
    # emitting code.
    is_kernel = not args.user
    exc: Optional[Exception] = None
    try:
        start = _resolve_addr_or_sym(prog, args.start) + args.offset
    except LookupError as e:
        exc = e
        start = None
    # Only continue to read memory if we didn't fail a symbol lookup above.
    if start is not None:
        if args.end is not None:
            count = (args.end - start) // args.unit
        elif args.reverse:
            count = args.count
            start -= args.unit * (args.count - 1)
        else:
            count = args.count
        memory = None
        # Try reading kernel memory first, if the user didn't hint a userspace
        # address. Note that count may be None, in ascii mode! So fall back to a
        # one-byte read in that case. It's good enough to determine whether the
        # address is user or kernel, and the ascii mode will do its own reads
        # anyway.
        if is_kernel:
            try:
                memory = prog.read(start, (count or 1) * args.unit)
            except FaultError as e:
                exc = exc or e
        # Try reading the context process address space
        if memory is None:
            try:
                task = crash_get_context(prog)
                memory = access_process_vm(
                    task,
                    start,
                    (count or 1) * args.unit,
                )
            except FaultError as e:
                exc = exc or e
            else:
                # Success? Clear exc and note that it's a user address
                is_kernel = False
                exc = None

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.append("start = ")
        code.append_addr_or_sym(args.start)
        code.append("\n")
        if args.offset != 0:
            code.append(f"start += {args.offset}\n")
        code.append(f"unit = {args.unit}\n")

        if args.end is not None:
            code.append(
                f"""\
end = {hex(args.end)}
count = (end - start) // unit
"""
            )
        elif args.reverse:
            code.append(
                f"""\
# Print memory leading up to start:
count = {args.count or 1}
start -= unit * (count - 1)
"""
            )
        else:
            code.append(f"count = {args.count or 1}\n")

        if is_kernel and args.annotate is not None:
            code.add_from_import("drgn.helpers.common.memory", "print_annotated_memory")
            code.append(
                f"""\
print_annotated_memory(start, count * unit, physical={args.physical})
"""
            )
        elif is_kernel:
            code.append(
                f"""\
memory = prog.read(start, count * unit, physical={args.physical})
"""
            )
        else:
            code.add_from_import("drgn.helpers.linux.mm", "access_process_vm")
            code.add_from_import("drgn.helpers.linux.pid", "find_task")
            code.append(
                f"""\
task = find_task(prog, {task.pid.value_()})
memory = access_process_vm(task, start, count)
"""
            )

        if args.raw:
            code.append(
                f"""\
with open({args.raw!r}, "wb") as f:
    f.write(memory)
"""
            )
        code.print()
        return
    if exc:
        raise exc
    assert memory is not None
    assert start is not None

    if args.raw:
        with open(args.raw, "wb") as f:
            f.write(memory)
        print(f"{len(memory)} bytes copied from 0x{start:x} to {args.raw}")
    elif args.ascii:
        _dump_printable_memory(
            prog, start, count, physical=args.physical, kernel=is_kernel
        )
    else:
        _print_memory(
            prog,
            start,
            memory,
            unit=args.unit,
            annotate=args.annotate,
            format=args.format,
            endian=args.endian,
            show_ascii=args.show_ascii,
        )
