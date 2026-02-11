# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Execute an unmodified drgn script with BTF debuginfo

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
import os
import pkgutil
import re
import runpy
import sys
from typing import Optional

from drgn import Program
from drgn.cli import run_interactive
from drgn.helpers.experimental.btf import load_builtin_btf


def read_decls_from_script(filename: str) -> Optional[str]:
    """
    Read declarations of the form
    """
    decl_lines = []
    start = re.compile(r"^__BTF_DECLS__\s*=\s*('''|\"\"\")\s*$")
    with open(filename, "r") as f:
        lines = iter(f)
        for line in lines:
            m = start.fullmatch(line.rstrip('\n'))
            if m is not None:
                break
        else:
            sys.exit("No header provided and __BTF_DECLS__ missing from script.")
        endquote = m.group(1)
        for line in lines:
            if line.rstrip('\n') == endquote:
                break
            else:
                decl_lines.append(line)
        else:
            sys.exit("Syntax error: unclosed __BTF_DECLS__")
        return "".join(decl_lines)



def main(prog: Program):
    if len(sys.argv) < 2:
        sys.exit(f"""\
usage: drgn {sys.argv[0]} decls.h script.py
   or: drgn {sys.argv[0]} script_with_decls.py""")
    if sys.argv[1] in ("-h", "--help"):
        sys.exit(__doc__)

    if sys.argv[1].endswith(".py"):
        # Assume it's a script with declarations:
        decls = read_decls_from_script(sys.argv[1])
        remainder = sys.argv[1:]
    else:
        decls = open(sys.argv[1], "r").read()
        remainder = sys.argv[2:]
    load_builtin_btf(prog, declarations=decls)
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


if __name__ == "__main__":
    main(prog)  # noqa
