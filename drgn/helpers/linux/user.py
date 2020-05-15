# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Users
-----

The ``drgn.helpers.linux.user`` module provides helpers for working with users
in the Linux kernel.
"""

import operator

from drgn import NULL, Object
from drgn.helpers.linux.list import hlist_for_each_entry

__all__ = (
    "find_user",
    "for_each_user",
)


def _kuid_val(uid):
    if isinstance(uid, Object) and uid.type_.type_name() == "kuid_t":
        uid = uid.val
    return operator.index(uid)


def find_user(prog, uid):
    """
    .. c:function:: struct user_struct *find_user(kuid_t uid)

    Return the user structure with the given UID, which may be a ``kuid_t`` or
    an integer.
    """
    try:
        uidhashentry = prog.cache["uidhashentry"]
    except KeyError:
        uidhash_table = prog["uidhash_table"]
        uidhash_sz = len(uidhash_table)
        uidhash_bits = uidhash_sz.bit_length() - 1
        uidhash_mask = uidhash_sz - 1

        def uidhashentry(uid):
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


def for_each_user(prog):
    """
    Iterate over all users in the system.

    :return: Iterator of ``struct user_struct *`` objects.
    """
    for hash_entry in prog["uidhash_table"]:
        for user in hlist_for_each_entry(
            "struct user_struct", hash_entry, "uidhash_node"
        ):
            yield user
