#!/usr/bin/env python3
"""
Print a kernel & userspace stack
"""
import sys
from struct import Struct
from typing import BinaryIO
from typing import NamedTuple
from typing import Optional
from typing import Tuple
from typing import Type
from typing import TypeVar

from drgn import Program
from drgn import Object
from drgn import TypeMember
from drgn import sizeof
from drgn.helpers.linux import access_remote_vm
from drgn.helpers.linux import d_path
from drgn.helpers.linux import find_vmap_area
from drgn.helpers.linux import for_each_vma


AT_PHDR = 3
SHT_DYNAMIC = 6
PT_DYNAMIC = 2

T = TypeVar("T")


def read_struct(cls: Type[T], prog: Program, addr: int, file: Optional[BinaryIO], file_base: int) -> T:
    if file:
        file.seek(addr - file_base)
        return cls(*cls.struct.unpack(file.read(cls.struct.size)))
    else:
        return cls(*cls.struct.unpack(prog.read(addr, cls.struct.size)))


class Ehdr(NamedTuple):
    e_ident: bytes
    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    struct = Struct("=16sHHIQQQIHHHHHH")


class Phdr(NamedTuple):
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    struct = Struct("=IIQQQQQQ")


class Shdr(NamedTuple):
    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int

    struct = Struct("=IIQQQQIIQQ")


def dynamic_address(up: Program, file_addr: int, path: Optional[str]) -> int:
    file = None
    if path:
        file = open(path, "rb")
    ehdr = read_struct(Ehdr, up, file_addr, file, file_addr)
    if ehdr.e_shoff:
        for i in range(ehdr.e_phnum):
            phdr = read_struct(
                Phdr, up, file_addr + ehdr.e_phoff + i * ehdr.e_phentsize, file, file_addr
            )
            if phdr.p_type == PT_DYNAMIC:
                return phdr.p_offset
    raise LookupError(f"cannot find DYNAMIC address in {file_addr:x}")


def get_auxval(arr: Object, kind: int) -> int:
    for i in range(0, len(arr), 2):
        if arr[i] == kind:
            return arr[i + 1].value_()
    raise LookupError(f"cannot find auxval: {kind}")


def find_main(mm: Object) -> Tuple[bytes, int, Object]:
    phdr = get_auxval(mm.saved_auxv, AT_PHDR)
    for vma in for_each_vma(mm):
        if vma.vm_start <= phdr < vma.vm_end:
            path = d_path(vma.vm_file.f_path)
            return (path, vma.vm_start.value_(), vma)


def address_range(mm: Object, file: Object, start: int, end: int) -> Tuple[int, int]:
    for vma in for_each_vma(mm):
        if vma.vm_file == file:
            start = min(start, vma.vm_start.value_())
            end = max(end, vma.vm_end.value_())
    return start, end


def load_shared_libraries(up: Program, mm: Object, main: bytes):
    VM_EXEC = 0x4
    for vma in for_each_vma(mm):
        if vma.vm_flags & VM_EXEC:
            path = None
            if vma.vm_file:
                path = d_path(vma.vm_file.f_path)
            if path == main:
                continue
            file_start = (
                vma.vm_start - vma.vm_pgoff * mm.prog_["PAGE_SIZE"]
            ).value_()
            try:
                address = dynamic_address(up, file_start, path)
            except Exception:
                print(f"error setting up module for {file_start} ({path})")
                continue
            if path:
                mod, _ = up.shared_library_module(
                    path, dynamic_address=file_start + address, create=True
                )
                mod.try_file(path, force=True)
                mod.address_range = address_range(mm, vma.vm_file, vma.vm_start.value_(), vma.vm_end.value_())
            else:
                # vdso
                mod, _ = up.vdso_module(
                    "linux-vdso.so.1", dynamic_address=file_start + address, create=True
                )


def get_user_prog(prog: Program, pid: int):
    up = Program(prog.platform)
    thread = prog.thread(pid)
    tsk = thread.object
    mm = tsk.mm

    def read_fn(addr, count, offset, _):
        val = access_remote_vm(mm, offset, count)
        return val

    up.add_memory_segment(0, 0xFFFFFFFFFFFFFFFF, read_fn, False)

    main_prog, bias, vma = find_main(mm)
    main_mod, _ = up.main_module(name=main_prog, create=True)
    main_mod.try_file(main_prog, force=True)
    main_mod.loaded_file_bias = bias
    main_mod.address_range = address_range(mm, vma.vm_file, vma.vm_start.value_(), vma.vm_end.value_())
    load_shared_libraries(up, mm, main_prog)
    return up


def get_pt_regs(prog: Program, pid: int, up: Program) -> Object:
    # The pt_regs is dumped at the top of the stack. The stack size may vary,
    # but I believe it gets one page of padding, and the registers are dumped at
    # an offset of 16 bytes for 64-bit.
    thread = prog.thread(pid)
    stack = thread.object.stack
    regs_addr = (
        find_vmap_area(prog, stack).va_end.value_()
        - sizeof(prog.type("struct pt_regs"))
        - prog["PAGE_SIZE"]
        - 16
    )
    regs = Object(prog, "struct pt_regs", address=regs_addr)

    # Luckily, all drgn cares about for x86_64 pt_regs is that it is a
    # structure. Rather than creating a matching struct pt_regs definition,
    # we can just create a dummy one of the correct size:
    #     struct pt_regs { unsigned char[size]; };
    # Drgn will happily use that and reinterpret the bytes correctly.
    fake_pt_regs_type = up.struct_type(
        tag="pt_regs",
        size=regs.type_.size,
        members=[
            TypeMember(
                up.array_type(
                    up.int_type("unsigned char", 1, False),
                    regs.type_.size,
                ),
                "data",
            ),
        ],
    )
    # Return a fake struct pt_regs that drgn will unwind.
    return Object.from_bytes_(
        up, fake_pt_regs_type, regs.to_bytes_()
    )


def main(prog: Program, pid: int) -> None:
    print(prog.stack_trace(pid))
    up = get_user_prog(prog, pid)
    regs = get_pt_regs(prog, pid, up)
    print("------ userspace ---------")
    print(up.stack_trace(regs))


if __name__ == "__main__":
    prog: Program
    main(prog, int(sys.argv[1]))  # noqa
