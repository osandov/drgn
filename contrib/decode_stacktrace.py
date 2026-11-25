#!/usr/bin/env python3
# Copyright (c) 2026, Yiwei Lin
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Decode a kernel oops or stack trace from dmesg text using vmlinux and .ko
files.

Usage: decode_stacktrace.py [-m MODULES_DIR] vmlinux [dmesg.txt]

Frames in modules are resolved from ``<name>.ko`` found under MODULES_DIR
(default: the directory containing vmlinux). Register values and the
faulting-instruction analysis are x86-64 only; disassembly needs Capstone.
Without CONFIG_PRINTK_CALLER, a log with oopses from several CPUs interleaved
cannot be paired up correctly; the symbolized frames are still right.
"""

import argparse
import os
import re
import signal
import struct
import sys
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

import drgn
from drgn import Object, Program, StackFrame
from drgn.helpers.common.type import member_at_offset

_FRAME_RE = re.compile(
    r"(?:\? )?(?P<rip>RIP: \d{4}:)?(?P<sym>[A-Za-z_][\w.]*)\+0x(?P<off>[0-9a-f]+)/0x[0-9a-f]+"
    r"(?: \[(?P<mod>[\w-]+)\])?"
)
_X86_REG_RE = re.compile(r"\b(R[A-Z][A-Z]|R\d\d?): (?:\d{4}:)?([0-9a-f]{16})\b")
# printk's CONFIG_PRINTK_CALLER tag, "[    T220]" or "[     C8]": task or CPU
_CALLER_RE = re.compile(r"^\[[ \d.]+\]\s*\[ *([TC]\d+)\]")
_CODE_RE = re.compile(r"Code: ((?:(?:<[0-9a-f]{2}>|[0-9a-f]{2}) ?)+)")

_X86_REGS = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp") + tuple(
    f"r{i}" for i in range(8, 16)
)
_MODULE_BASE = 0xFFFFFFFFC0000000  # where x86-64 maps modules; any gap would do


def pt_regs_name(reg: str) -> str:
    """rax -> ax, rsp -> sp, r08 -> r8, r12 -> r12"""
    reg = reg.lower()
    return reg[1:] if reg[1:].isalpha() else "r" + str(int(reg[1:]))


# Loading files


def load_vmlinux(path: str) -> Program:
    prog = drgn.Program()
    module = prog.extra_module(name="vmlinux", id=0, create=True)
    module.try_file(path, force=True)
    if module.debug_file_status != drgn.ModuleFileStatus.HAVE:
        sys.exit(f"{path}: no debugging information")
    module.address_ranges = [
        (prog.symbol("_text").address, prog.symbol("_end").address)
    ]
    return prog


def elf_alloc_sections(path: str) -> Iterator[Tuple[str, int, int]]:
    """Yield (name, size, alignment) of each SHF_ALLOC section of an ELF64 file."""
    with open(path, "rb") as f:
        data = f.read()
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shdrs = [
        struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
        for i in range(shnum)
    ]
    strtab = shdrs[shstrndx][4]
    for name, _, flags, _, _, size, _, _, align, _ in shdrs:
        if flags & 2 and size:  # SHF_ALLOC
            end = data.index(b"\0", strtab + name)
            yield data[strtab + name : end].decode(), size, max(align, 1)


def load_module(prog: Program, name: str, path: str, base: int) -> drgn.Module:
    """Map a .ko at base as if the kernel had loaded it there."""
    module = prog.relocatable_module(name, base, create=True)
    address = base
    for section, size, align in elf_alloc_sections(path):
        address = (address + align - 1) & -align
        module.section_addresses[section] = address
        address += size
    module.address_range = (base, address)
    module.try_file(path, force=True)
    return module


def load_modules(
    prog: Program, names: Iterable[str], root: str
) -> Dict[str, drgn.Module]:
    """Load <name>.ko from under root for each name that has one."""
    paths = {}
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if filename.endswith(".ko"):
                paths[filename[:-3].replace("-", "_")] = os.path.join(dirpath, filename)
    loaded = {}
    base = _MODULE_BASE
    for name in names:
        path = paths.get(name.replace("-", "_"))
        if path is None:
            print(f"warning: {name}.ko not found under {root}", file=sys.stderr)
            continue
        loaded[name] = load_module(prog, name, path, base)
        base = (loaded[name].address_range[1] + 0xFFFFF) & -0x100000
    return loaded


# Symbolizing


def symbol_address(
    prog: Program, name: str, module: Optional[drgn.Module]
) -> Optional[int]:
    """Address of the symbol, in the given module or else in vmlinux."""
    for sym in prog.symbols(name):
        if module is None:
            return sym.address
        start, end = module.address_range
        if start <= sym.address < end:
            return sym.address
    return None


def source_prefix(prog: Program) -> str:
    """The build directory prefix on file names, e.g. "../" or "/src/linux/"."""
    # kernel_init is in init/main.c; +1 skips the first instruction, which has
    # no line number.
    pc = prog.symbol("kernel_init").address + 1
    try:
        filename = prog.stack_trace_from_pcs([pc])[0].source()[0]
    except LookupError:
        return ""
    return filename[: -len("init/main.c")] if filename.endswith("init/main.c") else ""


def source(frame: StackFrame, prefix: str) -> str:
    try:
        filename, line, _ = frame.source()
    except LookupError:
        return ""
    if filename.startswith(prefix):
        filename = filename[len(prefix) :]
    return f"{filename}:{line}"


def symbolize(prog: Program, address: int) -> str:
    try:
        sym = prog.symbol(address)
        return f"{sym.name}+{address - sym.address:#x}"
    except LookupError:
        return f"{address:#x}"


# The faulting frame (x86-64)


def frame_at(prog: Program, pc: int, regs: Dict[str, int]) -> StackFrame:
    return prog.stack_trace(Object(prog, "struct pt_regs", {**regs, "ip": pc}))[0]


def local_registers(prog: Program, pc: int) -> Dict[str, str]:
    """Which register each local of the frame at pc lives in, per DWARF.

    Found by filling every register with a distinct marker and reading the
    locals back. Locals that DWARF describes as constants are left out: they
    cannot have caused a fault.
    """
    markers = {reg: 0x7F00000000 + 8 * i for i, reg in enumerate(_X86_REGS)}
    frame = frame_at(prog, pc, markers)
    by_value = {value: reg for reg, value in markers.items()}
    result = {}
    for name in frame.locals():
        try:
            value = frame[name].value_()
        except Exception:  # absent, optimized out, ...
            continue
        # Structs and arrays come back as dict or list: not in a register.
        if isinstance(value, int) and value in by_value:
            result[name] = by_value[value]
    return result


def disassemble(
    prog: Program, block: str, pc: int
) -> Tuple[List[str], Optional[Tuple[str, int]]]:
    """Disassemble the Code: line in an oops block.

    Returns the output lines and (base register, displacement) of the trapping
    instruction's memory operand, if it has one.
    """
    match = _CODE_RE.search(block)
    if not match:
        return [], None
    tokens = match.group(1).split()
    before = next((i for i, t in enumerate(tokens) if t.startswith("<")), None)
    if before is None:  # no marker: we cannot tell where the trapping insn is
        return [], None
    code = bytes(int(t.strip("<>"), 16) for t in tokens)
    try:
        import capstone  # type: ignore  # No type hints available.
    except ImportError:
        return ["(install Capstone to disassemble)"], None
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.syntax = capstone.CS_OPT_SYNTAX_ATT
    md.detail = True

    out = []
    trap = None
    # The bytes before the trapping instruction may start mid-instruction, so
    # disassemble the two halves separately to keep the second one aligned.
    for data, address in ((code[:before], pc - before), (code[before:], pc)):
        for insn in md.disasm(data, address):
            mark = ""
            if insn.address == pc:
                mark = "    <-- trapping instruction"
                for op in insn.operands:
                    if op.type == capstone.x86.X86_OP_MEM and op.mem.base:
                        base = insn.reg_name(op.mem.base)
                        trap = (pt_regs_name(base), op.mem.disp)
            out.append(
                f"{symbolize(prog, insn.address)}: {insn.mnemonic} {insn.op_str}{mark}"
            )
    return out, trap


def caller(line: str) -> Optional[str]:
    match = _CALLER_RE.match(line)
    return match.group(1) if match else None


def oops_block(lines: List[str], i: int) -> str:
    """The register dump and Code: line belonging to the RIP: line at lines[i].

    The registers and Code: precede the Call Trace:, so stop there; also stop
    at the next RIP: line, which belongs to another dump (the oops repeats it,
    and a WARN also dumps the user-space RIP:). If the log has caller tags,
    lines printed by other CPUs or tasks in between are skipped.
    """
    tag = caller(lines[i])
    block = []
    for line in lines[i + 1 :]:
        if tag is not None and caller(line) != tag:
            continue
        if "RIP: " in line or "Call Trace:" in line:
            break
        block.append(line)
    return "\n".join(block)


def fault_frame(
    prog: Program, block: str, pc: int, prefix: str
) -> Tuple[str, List[str], List[str]]:
    """Decode the frame at a RIP: line, given the oops block that follows it.

    Returns the frame's location, the lines for its register-resident locals,
    and the disassembly of the block's Code: line.
    """
    regs: Dict[str, int] = {}
    for name, value in _X86_REG_RE.findall(block):
        regs.setdefault(pt_regs_name(name), int(value, 16))  # first dump wins
    frame = frame_at(prog, pc, regs)
    disasm, trap = disassemble(prog, block, pc)
    in_register = local_registers(prog, pc)

    locals_out = []
    for name in frame.locals():
        if name not in in_register:  # constants and stack slots: not interesting
            continue
        value = frame[name]
        note = ""
        if trap is not None and in_register[name] == trap[0]:
            # This pointer was the base of the faulting access.
            note = f"    <- %{trap[0]}"
            try:
                note += f", {name}->{member_at_offset(value.type_.type, trap[1])}"
            except (LookupError, TypeError):
                pass
        shown = value.format_(dereference=False, type_name=False)
        locals_out.append(f"    {name} = {shown}{note}")
    return f"{frame.name} ({source(frame, prefix)})", locals_out, disasm


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("vmlinux")
    parser.add_argument(
        "dmesg",
        nargs="?",
        type=argparse.FileType("r", errors="replace"),
        default=sys.stdin,
    )
    parser.add_argument(
        "-m", "--modules-dir", help="where to look for .ko files (default: vmlinux's)"
    )
    args = parser.parse_args()
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet exit on `| head`
    prog = load_vmlinux(args.vmlinux)
    if args.dmesg.isatty():
        parser.error("pass the dmesg text as a file or on stdin")
    text = args.dmesg.read()

    prefix = source_prefix(prog)
    modules = load_modules(
        prog,
        {m.group("mod") for m in _FRAME_RE.finditer(text) if m.group("mod")},
        args.modules_dir or os.path.dirname(os.path.abspath(args.vmlinux)),
    )

    # Every line passes through; frames are rewritten in place and the Code:
    # line gets its disassembly appended, like scripts/decode_stacktrace.sh.
    pending_disasm: Dict[Optional[str], List[str]] = {}  # per caller tag
    lines = text.splitlines()
    for i, line in enumerate(lines):
        match = _FRAME_RE.search(line)
        if match is None:
            print(line)
            if _CODE_RE.search(line):
                for out in pending_disasm.pop(caller(line), []):
                    print(f"{line[: line.index('Code:')]}  {out}")
            continue

        head, tail = line[: match.start()], line[match.end() :]
        mod = match.group("mod")
        address = None
        if not mod or mod in modules:
            address = symbol_address(prog, match.group("sym"), modules.get(mod))
        if address is None:
            print(line)  # unknown symbol or module: leave it as is
            continue
        pc = address + int(match.group("off"), 16)

        if match.group("rip") and prog.platform.arch == drgn.Architecture.X86_64:
            location, locals_out, disasm = fault_frame(
                prog, oops_block(lines, i), pc, prefix
            )
            pending_disasm[caller(line)] = disasm
            print(f"{head}{match.group('rip')}{location}{tail}")
            for out in locals_out:
                print(f"{head}{out}")
            continue
        unreliable = "? " if match.group(0).startswith("? ") else ""
        in_mod = f" [{mod}]" if mod else ""
        for frame in prog.stack_trace_from_pcs([pc]):
            inline = " (inlined)" if frame.is_inline else ""
            print(
                f"{head}{unreliable}{frame.name} ({source(frame, prefix)}){inline}{in_mod}{tail}"
            )


if __name__ == "__main__":
    main()
