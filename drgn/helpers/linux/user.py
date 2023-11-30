# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Users
-----

The ``drgn.helpers.linux.user`` module provides helpers for working with users
in the Linux kernel.
"""

import operator
from typing import Iterator, Union

from drgn import NULL, IntegerLike, Object, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.list import hlist_for_each_entry

__all__ = (
    "find_user",
    "for_each_user",
)


def _kuid_val(uid: Union[Object, IntegerLike]) -> int:
    if isinstance(uid, Object) and uid.type_.type_name() == "kuid_t":
        uid = uid.val
    return operator.index(uid)


@takes_program_or_default
def find_user(prog: Program, uid: Union[Object, IntegerLike]) -> Object:
    """
    Return the user structure with the given UID.

    :param uid: ``kuid_t`` object or integer.
    :return: ``struct user_struct *`` (``NULL`` if not found)
    """
    try:
        uidhashentry = prog.cache["uidhashentry"]
    except KeyError:
        uidhash_table = prog["uidhash_table"]
        uidhash_sz = len(uidhash_table)
        uidhash_bits = uidhash_sz.bit_length() - 1
        uidhash_mask = uidhash_sz - 1

        def uidhashentry(uid: int) -> Object:
            hash = ((uid >> uidhash_bits) + uid) & uidhash_mask
            return uidhash_table + hash

        prog.cache["uidhashentry"] = uidhashentry

    uid = _kuid_val(uid)
    for user in hlist_for_each_entry(
        "struct user_struct", uidhashentry(uid), "uidhash_node"
    ):
        if user.uid.val == uid:
            return user
    return NULL(prog, "struct user_struct *")


@takes_program_or_default
def for_each_user(prog: Program) -> Iterator[Object]:
    """
    Iterate over all users in the system.

    :return: Iterator of ``struct user_struct *`` objects.
    """
    for hash_entry in prog["uidhash_table"]:
        yield from hlist_for_each_entry(
            "struct user_struct", hash_entry, "uidhash_node"
        )
