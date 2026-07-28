# Copyright (c) IBM Corp. 2026
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
KVM (Kernel-based Virtual Machine)
-----------------------------------

The ``drgn.helpers.linux.kvm`` module provides helpers for working with KVM
virtual machines and their components.
"""

from typing import Callable, Iterator, Optional, Union

from drgn import FaultError, Object, Program, cast
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.mm import access_remote_vm, for_each_vma
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry
from drgn.helpers.linux.xarray import xa_for_each

__all__ = (
    "for_each_kvm",
    "for_each_kvm_memslot",
    "kvm_from_task",
    "kvm_for_each_vcpu",
    "prog_from_kvm",
)


@takes_program_or_default
def for_each_kvm(prog: Union[Object, Program]) -> Iterator[Object]:
    """
    Iterate over all unique KVM virtual machines in the system.

    :param prog: :class:`~drgn.Program` or :ref:`omitted <default-program>`.
    :return: Iterator of ``struct kvm *`` objects.
    """
    kvm_addr_set = {}
    for task in for_each_task(prog):
        kvm = kvm_from_task(task)
        if kvm and kvm.value_() not in kvm_addr_set:
            yield kvm
            kvm_addr_set[kvm.value_()] = True


def kvm_from_task(task: Object) -> Optional[Object]:
    """
    Return the KVM virtual machine owned by a task.

    :param task: ``struct task_struct *``
    :return: ``struct kvm *`` if the task owns a KVM VM, ``None`` otherwise.
    """
    kvm_fops_addr = task.prog_["kvm_vm_fops"].address_
    kvm_type = task.prog_.type("struct kvm *")
    try:
        for fd in task.files.fd_array:
            if fd.value_() == 0:
                break
            if fd.f_op.value_() == kvm_fops_addr:
                return cast(kvm_type, fd.private_data)
        return None
    except FaultError:
        # We tried reading from the fd array and we got a null
        # so we're past the end, or the files array was missing etc.
        # This is mostly a best effort at the moment, so we're just
        # going to eat the error and assume there's no VM associated
        # with this task.
        return None


def kvm_for_each_vcpu(kvm: Object) -> Iterator[Object]:
    """
    Iterate over all virtual CPUs in a KVM virtual machine.

    :param kvm: ``struct kvm *``
    :return: Iterator of ``struct kvm_vcpu *`` objects.
    """
    vcpu_type = kvm.prog_.type("struct kvm_vcpu *")
    return (cast(vcpu_type, v[1]) for v in xa_for_each(kvm.vcpu_array))


def for_each_kvm_memslot(kvm: Object) -> Iterator[Object]:
    """
    Iterate over all memory slots in a KVM virtual machine.

    Memory slots are returned in ascending guest physical address order.

    :param kvm: ``struct kvm *``
    :return: Iterator of ``struct kvm_memory_slot *`` objects.
    """
    return rbtree_inorder_for_each_entry(
        kvm.prog_.type("struct kvm_memory_slot"), kvm.memslots[0].gfn_tree, "gfn_node"
    )


def _make_read_user_memory(
    slot: Object, mm: Object
) -> Callable[[int, int, int, bool], bytes]:
    page_size = mm.prog_["PAGE_SIZE"].value_()
    start_addr = slot.base_gfn.value_() * page_size
    userspace_base = slot.userspace_addr.value_()

    def read_user_memory(addr: int, count: int, _offset: int, physical: bool) -> bytes:
        host_addr = addr - start_addr + userspace_base
        return access_remote_vm(mm, host_addr, count)

    return read_user_memory


def prog_from_kvm(kvm: Object) -> Program:
    """
    Create a Program for debugging a KVM guest's memory.

    This function creates a new :class:`~drgn.Program` that can be used to
    inspect the guest physical memory of a KVM virtual machine.

    :param kvm: ``struct kvm *``
    :return: :class:`~drgn.Program` configured to access the guest's memory.
    """
    prog = Program(kvm.prog_.platform)
    prog.cache["_kvm"] = kvm
    page_size = kvm.prog_["PAGE_SIZE"].value_()
    for slot in for_each_kvm_memslot(kvm):
        start_addr = slot.base_gfn.value_() * page_size
        size = slot.npages.value_() * page_size
        prog.add_memory_segment(
            start_addr, size, _make_read_user_memory(slot, kvm.mm), True
        )
    return prog
