# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Types
-----

The ``drgn.helpers.common.type`` module provides generic helpers for working
with types in ways that aren't provided by the core drgn library.
"""

import enum
import operator
import typing
from typing import Container, List, Tuple

from drgn import IntegerLike, Type, TypeKind, TypeMember, sizeof

__all__ = (
    "enum_type_to_class",
    "member_at_offset",
)


def enum_type_to_class(
    type: Type, name: str, exclude: Container[str] = (), prefix: str = ""
) -> typing.Type[enum.IntEnum]:
    """
    Get an :class:`enum.IntEnum` class from an enumerated :class:`drgn.Type`.

    :param type: Enumerated type to convert.
    :param name: Name of the ``IntEnum`` type to create.
    :param exclude: Container (e.g., list or set) of enumerator names to
        exclude from the created ``IntEnum``.
    :param prefix: Prefix to strip from the beginning of enumerator names.
    """
    if type.enumerators is None:
        raise TypeError("enum type is incomplete")
    enumerators = [
        (name[len(prefix) :] if name.startswith(prefix) else name, value)
        for (name, value) in type.enumerators
        if name not in exclude
    ]
    return enum.IntEnum(name, enumerators)  # type: ignore  # python/mypy#4865


def member_at_offset(type: Type, offset: IntegerLike) -> str:
    """
    Return the name of the member at an offset in a type.

    This is effectively the opposite of :func:`~drgn.offsetof()`.

    >>> prog.type('struct list_head')
    struct list_head {
            struct list_head *next;
            struct list_head *prev;
    }
    >>> member_at_offset(prog.type('struct list_head'), 0)
    'next'
    >>> member_at_offset(prog.type('struct list_head'), 8)
    'prev'

    This includes nested structures and array elements:

    >>> prog.type('struct sigpending')
    struct sigpending {
            struct list_head list;
            sigset_t signal;
    }
    >>> prog.type('sigset_t')
    typedef struct {
            unsigned long sig[1];
    } sigset_t
    >>> member_at_offset(prog.type('struct sigpending'), 0)
    'list.next'
    >>> member_at_offset(prog.type('struct sigpending'), 8)
    'list.prev'
    >>> member_at_offset(prog.type('struct sigpending'), 16)
    'signal.sig[0]'

    This also includes all possible matches for a union:

    >>> prog.type('union mc_target')
    union mc_target {
            struct folio *folio;
            swp_entry_t ent;
    }
    >>> prog.type('swp_entry_t')
    typedef struct {
            unsigned long val;
    } swp_entry_t
    >>> member_at_offset(prog.type('union mc_target'), 0)
    'folio or ent.val'

    Offsets in the middle of a member are represented:

    >>> member_at_offset(prog.type('struct list_head'), 4)
    'next+0x4'

    Offsets in padding or past the end of the type are also represented:

    >>> prog.type('struct autogroup')
    struct autogroup {
            struct kref kref;
            struct task_group *tg;
            struct rw_semaphore lock;
            unsigned long id;
            int nice;
    }
    >>> member_at_offset(prog.type('struct autogroup'), 4)
    '<padding between kref and tg>'
    >>> member_at_offset(prog.type('struct autogroup'), 70)
    '<padding at end>'
    >>> member_at_offset(prog.type('struct autogroup'), 72)
    '<end>'
    >>> member_at_offset(prog.type('struct autogroup'), 80)
    '<past end>'

    :param type: Type to check.
    :param offset: Offset in bytes.
    :raises TypeError: if *type* is not a structure, union, class, or array
        type (or a typedef of one of those)
    """
    bit_offset = operator.index(offset) * 8

    while type.kind == TypeKind.TYPEDEF:
        type = type.type
    if type.kind not in (
        TypeKind.STRUCT,
        TypeKind.UNION,
        TypeKind.CLASS,
        TypeKind.ARRAY,
    ):
        raise TypeError("must be compound type or array")

    # Chain of member accesses and array subscripts that we've followed.
    chain = []
    # We traverse all union members in a depth-first search. This stack stores
    # the members that still need to be explored, along with the remaining
    # bit_offset from that member and the length of the chain leading to that
    # member.
    stack: List[Tuple[TypeMember, int, int]] = []
    results = []

    # When we've reached the end of a chain, add it to the results and go to
    # the next member in the stack (if any).
    def emit_and_pop_member() -> bool:
        nonlocal type, bit_offset

        if bit_offset:
            if (bit_offset & 7) == 0:
                chain.append("+")
                chain.append(hex(bit_offset // 8))
            else:
                chain.append("+")
                chain.append(str(bit_offset))
                chain.append(" bits")
        results.append("".join(chain))

        if not stack:
            return False

        member, parent_bit_offset, chain_len = stack.pop()

        type = member.type
        bit_offset = parent_bit_offset - member.bit_offset
        del chain[chain_len:]
        if member.name is not None:
            if chain:
                chain.append(".")
            chain.append(member.name)

        return True

    while True:
        if type.kind == TypeKind.TYPEDEF:  # type: ignore[comparison-overlap]  # python/mypy#17096
            type = type.type
        elif type.kind == TypeKind.ARRAY:
            element_bit_size = sizeof(type.type) * 8
            # Treat incomplete arrays as if they have infinite size.
            if type.length is None or bit_offset < type.length * element_bit_size:
                i = bit_offset // element_bit_size
                bit_offset -= i * element_bit_size
                chain.append(f"[{i}]")
                type = type.type
            else:
                if bit_offset == type.length * element_bit_size:
                    chain.append("<end>")
                else:
                    chain.append("<past end>")
                bit_offset = 0
                if not emit_and_pop_member():
                    break
        else:
            members = getattr(type, "members", None)
            if members is None:
                if not emit_and_pop_member():
                    break
                continue

            orig_bit_offset = bit_offset
            orig_chain_len = len(chain)

            # At first, we go forwards through the members. If this is a union,
            # then we go backwards through the rest once we've found a match.
            # This allows us to (1) avoid the stack as an optimization for the
            # common case of structures and (2) return results sorted by
            # declaration order in the source code.
            i = 0
            end = len(members)
            step = 1
            while i != end:
                member = members[i]
                bit_size = member.bit_field_size
                if bit_size is None:
                    try:
                        bit_size = sizeof(member.type) * 8
                    except TypeError:
                        # Ignore incomplete members other than arrays.
                        if member.type.kind != TypeKind.ARRAY:
                            i += step
                            continue
                if (
                    member.bit_offset <= bit_offset
                    # Treat incomplete arrays as if they have infinite size.
                    and (bit_size is None or bit_offset < member.bit_offset + bit_size)
                ):
                    if step == 1:
                        step = -1
                        if type.kind == TypeKind.UNION:
                            i, end = end, i
                        else:
                            # Set i so that we break on the next iteration.
                            i = end + 1

                        type = member.type
                        bit_offset -= member.bit_offset
                        if member.name is not None:
                            if chain:
                                chain.append(".")
                            chain.append(member.name)
                    else:
                        stack.append((member, orig_bit_offset, orig_chain_len))
                i += step
            if step == 1:
                # No matching members.
                bit_size = sizeof(type) * 8
                if bit_offset == bit_size:
                    chain.append("<end>")
                elif bit_offset > bit_size:
                    chain.append("<past end>")
                else:
                    prev_member = None
                    next_member = None
                    for member in members:
                        if member.bit_offset < bit_offset:
                            if (
                                prev_member is None
                                or member.bit_offset > prev_member.bit_offset
                            ):
                                prev_member = member
                        else:
                            if (
                                next_member is None
                                or member.bit_offset < next_member.bit_offset
                            ):
                                next_member = member
                    if chain:
                        chain.append(".")
                    if prev_member and next_member:
                        chain.append("<padding between ")
                        chain.append(
                            "<unnamed>"
                            if prev_member.name is None
                            else prev_member.name
                        )
                        chain.append(" and ")
                        chain.append(
                            "<unnamed>"
                            if next_member.name is None
                            else next_member.name
                        )
                        chain.append(">")
                    elif next_member:
                        chain.append("<padding at beginning>")
                    else:
                        chain.append("<padding at end>")
                bit_offset = 0
                if not emit_and_pop_member():
                    break

    return " or ".join(results)
