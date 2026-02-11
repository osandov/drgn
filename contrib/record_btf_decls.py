# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Execute a drgn script and record all object lookups

This script is part of a workflow that makes it simpler to use drgn with BTF in
its current upstream form. Since the kernel's BTF does not contain the mapping
of global variables to their types, we need to provide it manually. The
"record_btf_decls.py" script can be used to create a simple C header file
declaring all the variables that drgn accessed while running a script. Then, the
"run_with_btf.py" script can be used to execute that same script with debuginfo.

    # Record declarations:
    $ drgn [args] contrib/record_btf_decls.py -o decls.h  SCRIPT

    # Run script with BTF:
    $ drgn --no-default-symbols [args] contrib/run_with_btf.py decls.h SCRIPT

The generated header file is quite small, as it doesn't define the types, only
declare them. As a result, you can embed the types into a multiline string in
your script. If you declare them at the module scope like below, run_with_btf.py
will parse and load them automatically, without requiring a separate file::

    __BTF_DECLS__ = '''
    struct list_head modules, btf_modules;
    '''

Then you can simply run:

    $ drgn --no-default-symbols [args] contrib/run_with_btf.py SCRIPT_WITH_DECLS

Some notes and warnings:

1. The generated header is specific to your kernel version and configuration.
   However, many declarations will not change much across versions, so in many
   cases the header can be relatively portable. You'll want to verify before
   relying on it.

2. The record_btf_decls.py script can only record what objects were actually
   accessed by a drgn script. Branches of the script which were not taken could
   contain other object accesses; these won't have a corresponding declaration.
   You'll want to check scripts for `prog["name"]` and `prog.object("name")`
   constructs to identify these.
"""
import argparse
import os
import pkgutil
import runpy
import sys
from typing import Optional

from drgn import FindObjectFlags, Program, Type, TypeKind
from drgn.cli import run_interactive


def record_object_lookups(prog: Program) -> None:
    if "record_object_lookups" in prog.registered_object_finders():
        return

    lookups = set()

    def ofind(prog, name, flags, filename) -> None:
        if flags & FindObjectFlags.VARIABLE:
            lookups.add((name, filename))
        return None

    # Register at index 1 so that we don't observe the "linux_kernel" object
    # finder lookups, but we see everything else.
    prog.register_object_finder("record_object_lookups", ofind, enable_index=1)
    prog.cache["record_object_lookups"] = lookups


def _format_type(tp: Type, name: Optional[str]) -> str:
    if tp.kind in (TypeKind.STRUCT, TypeKind.UNION, TypeKind.ENUM, TypeKind.CLASS):
        if not tp.tag:
            raise ValueError(f"cannot reference anonymous {tp.kind.name.lower()}")
        if name:
            return f"{tp.kind.name.lower()} {tp.tag} {name}"
        else:
            return f"{tp.kind.name.lower()} {tp.tag}"
    elif tp.kind == TypeKind.POINTER:
        return _format_type(tp.type, f"*{name}")
    elif tp.kind == TypeKind.ARRAY:
        if tp.length is None:
            return _format_type(tp.type, f"{name}[]")
        else:
            return _format_type(tp.type, f"{name}[{tp.length}]")
    elif tp.kind == TypeKind.FUNCTION:
        raise NotImplementedError("function declarations are not implemented")
    elif name:
        return f"{tp.name} {name}"
    else:
        return tp.name


def get_object_declarations(prog: Program) -> str:
    # Include the minimum modules + btf_modules for any generated result
    decls = [
        "struct list_head modules, btf_modules;"
    ]
    for name, filename in prog.cache["record_object_lookups"]:
        try:
            result = prog.variable(name, filename)
        except LookupError:
            continue
        try:
            decls.append(_format_type(result.type_,name) + ";")
        except ValueError as e:
            decls.append(f"// {name}: {e}")
    return "\n".join(decls)


def main(prog: Program):
    parser = argparse.ArgumentParser(
        description="run a script, recording object accesses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-o", "--output", type=str, help="file to store declarations")
    args, remainder = parser.parse_known_args()
    record_object_lookups(prog)
    try:
        if remainder:
            sys.argv = remainder
            script_path = sys.argv[0]
            if pkgutil.get_importer(script_path) is None:
                sys.path.insert(0, os.path.dirname(os.path.abspath(script_path)))
            runpy.run_path(
                script_path, init_globals={"prog": prog}, run_name="__main__"
            )
        else:
            run_interactive(prog)
    finally:
        decls = get_object_declarations(prog)
        if args.output:
            with open(args.output, "w") as f:
                f.write(decls)
        else:
            print("==== DECLARATIONS ====")
            print(decls)


if __name__ == "__main__":
    main(prog)  # noqa
