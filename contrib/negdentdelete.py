# Copyright (c) 2024, Oracle and/or its affiliates.
"""
negdentdelete - remove negative dentries from a directory

Normally, there aren't many good ways to get rid of negative dentries. You
could:

1. Delete the entire directory containing them. This works, but if there are
   real files in it, then it's a lot of work.
2. Use drop_caches. This option is unfortunately global and so you can't target
   specific files.
3. Wait until your memory fills up and the LRU starts to handle it...

This script can help you target a specific directory and remove all negative
dentries within it. Note that while the script is reasonably safe, it can't be
100% reliable: iterating over a frequently changing linked list in the kernel
may go awry. The script also creates and unlinks files within the target
directory, so the user must have permission to do so. If the script runs as
root, then you should ensure that root-owned files inside the directory won't
cause any problems.
"""
import argparse
import os
import time
from typing import Iterator, List

from drgn import Object, Program
from drgn.helpers.linux.fs import path_lookup
from drgn.helpers.linux.list import hlist_for_each_entry, list_for_each_entry


def for_each_child_dentry(dentry: Object) -> Iterator[Object]:
    try:
        # da549bdd15c29 ("dentry: switch the lists of children to hlist")
        return hlist_for_each_entry(
            "struct dentry",
            dentry.d_children.address_of_(),
            "d_sib",
        )
    except LookupError:
        return list_for_each_entry(
            "struct dentry", dentry.d_subdirs.address_of_(), "d_child"
        )


def yield_negative_dentries(
    prog: Program, dir_: str, chunk_size: int = 10000
) -> Iterator[List[bytes]]:
    parent = path_lookup(prog, dir_).dentry
    negdent_names = []

    for child in for_each_child_dentry(parent):
        # Do this at the top of the loop so that there's less of a chance of the
        # current child being freed out from under us. It's sort of like
        # list_for_each_entry_safe(). Of course, there's no guarantee that this
        # dentry will still be here when we come back (we're not holding a
        # reference, after all). But at least we're not actively freeing the
        # dentry we're currently looking at.
        if len(negdent_names) >= chunk_size:
            yield negdent_names
            negdent_names = []

        if not child.d_inode:
            negdent_names.append(child.d_name.name.string_())
    if negdent_names:
        yield negdent_names


def remove_negative_dentries(
    dir_: str, names: List[bytes], verbose: bool = False
) -> None:
    dir_fd = os.open(dir_, os.O_PATH)
    try:
        for name in names:
            # When a file is open and it is unlinked, its associated dentry cannot
            # remain a part of the dentry cache (since a new file of the same name
            # could be created). So, it is removed from the dentry hash table so it
            # can no longer be looked up (see d_delete() in fs/dcache.c).
            #
            # When the file is closed, dput() will find that the dentry is
            # unhashed, and so it will immediately free it. Thus, creating a file
            # with the same name as a negative dentry, unlinking, and then closing
            # it, is a sneaky way of removing the cached negative dentry. While
            # this isn't ideal (creating the file does result in some I/O), it is
            # still remarkably quick.
            fd = os.open(name, os.O_RDONLY | os.O_CREAT, dir_fd=dir_fd)
            os.unlink(name, dir_fd=dir_fd)
            os.close(fd)
            if verbose:
                print(name.decode(), fd)
    finally:
        os.close(dir_fd)


def main(prog: Program):
    parser = argparse.ArgumentParser(
        description="remove negative dentries from a directory"
    )
    parser.add_argument(
        "directory",
        help="directory to clear negative dentries from",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="print each dentry we delete (much slower!)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=10000,
        help="number of negative dentries to read at a time",
    )
    args = parser.parse_args()
    directory = os.path.abspath(args.directory)
    removed = 0
    start = time.time()
    for batch in yield_negative_dentries(prog, directory, args.chunk_size):
        remove_negative_dentries(directory, batch, verbose=args.verbose)
        removed += len(batch)
    total = time.time() - start
    dps = removed / total
    print(f"removed {removed} negative dentries in {total:.2f}s ({dps:.2f}/s)")


if __name__ == "__main__":
    prog: Program
    main(prog)
