#!/usr/bin/env python3
"""
A sample IPython-based system for running Drgn with magic commands.

You'll need IPython installed:

    pip install ipython

Make sure to run this from the root of the repository:

    python -m contrib.ipyshell -c /proc/kcore -s vmlinux

Once launched, you're in an IPython shell with the usual prog object and
imports. Objects will be formatted nicely.

Instead of entering Python expressions and statements, you can also enter "magic
commands", prefixed by a percent sign (%). You can define implementations of
these commands by sub-classing the Command class in this file. If the command
name doesn't correspond to a variable in the session, then you don't even need
to use the prefix. Also, built into IPython is the ability to run shell commands
via the exclamation prefix (!). With these abilities, the drgn + IPython shell
could be made to have similar abilities as Crash.
"""
import argparse
import collections
import importlib
import os
import shlex
from abc import ABC
from abc import abstractmethod
from typing import Any
from typing import Dict
from typing import List
from typing import Type

import drgn
import IPython
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.fs import path_lookup
from drgn.helpers.linux.list import list_for_each_entry
from drgn.internal.sudohelper import open_via_sudo
from IPython.core.magic import Magics
from IPython.core.magic import line_magic
from IPython.core.magic import magics_class
from IPython.terminal.ipapp import load_default_config


class Command(ABC):
    """A very simple base class for a Drgn command with arguments"""

    prog: Program

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError("Implement name")

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        pass

    def run(self, args: argparse.Namespace) -> None:
        raise NotImplementedError("Implement run")

    def _do_run(self, arg_list: List[str]) -> None:
        parser = argparse.ArgumentParser(
            prog=self.name,
            description=getattr(self, "description", ""),
        )
        self.add_args(parser)
        try:
            args = parser.parse_args(arg_list)
        except SystemExit:
            return
        return self.run(args)

    def __init__(self, prog: Program) -> None:
        self.prog = prog


def get_all_commands(prog: Program) -> List[Command]:

    # If you define a command in a different file, you'd need to import that
    # module prior to this executing. Command.__subclasses__ can't know about
    # subclasses that haven't been imported yet.

    subclasses = collections.deque(Command.__subclasses__())
    cmds = []
    while subclasses:
        subcls = subclasses.popleft()
        this_node_subclasses = subcls.__subclasses__()
        if this_node_subclasses:
            # Assume that any class with subclasses is not executable. Add its
            # children to the queue (BFS) but do not instantiate it.
            subclasses.extend(this_node_subclasses)
        else:
            cmds.append(subcls(prog))
    return cmds


class HelloWorldCommand(Command):
    """The most basic implementation"""

    name = "hello"

    def run(self, _: argparse.Namespace) -> None:
        print("Hello world!")


def for_each_dentry_child(dentry):
    return list_for_each_entry(
        "struct dentry",
        dentry.d_subdirs.address_of_(),
        "d_child",
    )


def list_dentry(dentry, include_negative=False):
    for child in for_each_dentry_child(dentry):
        negative = "N" if not child.d_inode else " "
        if negative == "N" and not include_negative:
            continue
        name = escape_ascii_string(child.d_name.name.string_())
        print(f"{negative} {hex(child)} {name}")


def list_dir(prog, path, include_negative=False):
    list_dentry(path_lookup(prog, path, include_negative).dentry, include_negative)


class LsCommand(Command):
    """A helper which lists the contents of directories in the program"""

    name = "ls"

    def add_args(self, parser: argparse.ArgumentParser):
        parser.add_argument("path", help="path to list")
        parser.add_argument("--negative", "-n", action="store_true",
                            help="show negative dentries too")

    def run(self, args: argparse.Namespace):
        list_dir(self.prog, args.path, args.negative)


################################################################################
# IPython Stuff Below


def fmt_drgn_object(obj, p, cycle):
    """
    In the default "drgn" application shell, a return value which is a
    drgn.Object will be pretty-printed (by calling repr rather than str).
    However, if the return value is a complex type (e.g. python list), then the
    "str" operation is used, which is preferred because the repr could be quite
    large, and we don't want to spew output.

    We would like to replicate this with IPython, but unfortunately it is not
    simple. The pretty-printing system uses a "stack" of objects, which is
    pushed to each time a new datastructure is being printed. The size is 1 when
    no data structure is printed, but we're in an IPython output block. (this is
    probably an implementation detail)

    In addition to the above complexity, repr() could actually fail as it tries
    to read data from memory (e.g. a per_cpu pointer, or some other bad
    pointer).  When that happens, we should handle it gracefully by falling back
    to str() and warning the user of the error.
    """
    if len(p.stack) > 1:
        f = repr
    else:
        f = str
    try:
        p.text(f(obj))
    except drgn.FaultError:
        p.text("while displaying this object, drgn failed to read memory:")
        p.break_()
        p.text(f"  address: 0x{obj.address_:x}")
        p.break_()
        p.text(f"  type   : {obj.type_.type_name()}")


def _make_ipymagic(cmd: Command) -> Type:
    # The IPython magic system actually expects you to declare a class and
    # decorate, and then declare a function, and decorate that... I don't love
    # it. The Command class above is much simpler, and allows us to have
    # argument parsers and the Program attached as attributes. This function
    # simply takes a command and creates a corresponding Magic class and
    # decorates it accordingly for IPython's API.

    name = cmd.name

    def fn(self, line: List[str]):
        args = shlex.split(line)
        return cmd._do_run(args)

    fn.__name__ = name
    fn = line_magic(fn)
    cls = type(cmd.name, (Magics,), {name: fn})
    cls = magics_class(cls)
    return cls


def load_ipython_extension(ipython):
    for cmd in get_all_commands(ipython.config.prog):
        ipython.register_magics(_make_ipymagic(cmd))
    fmt = ipython.display_formatter.formatters["text/plain"]
    fmt.for_type(drgn.Object, fmt_drgn_object)


def configure(prog: Program):
    c = load_default_config()
    c.prog = prog
    c.InteractiveShellApp.extensions = [
        "contrib.ipyshell",
    ]
    c.TerminalInteractiveShell.banner1 = (
        "\nWelcome to drgn IPython mode\n"
        "You can run python code or %commands in the same prompt\n"
    )
    return c


################################################################################
# Low-effort clone of the drgn CLI arguments and globals


def make_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        "idrgn",
        description="a drgn+IPython shell for interactive vmcore debugging",
    )
    parser.add_argument(
        "-c",
        "--core",
        help="core dump to debug",
    )
    parser.add_argument(
        "--symbols",
        "-s",
        action="append",
        help="path to symbols (vmlinux) -- if specified, we won't search",
    )
    return parser


def create_user_namespace(prog: drgn.Program) -> Dict[str, Any]:
    user_ns = {
        "prog": prog,
        "drgn": importlib.import_module("drgn"),
    }
    drgn_globals = [
        "NULL",
        "Object",
        "cast",
        "container_of",
        "execscript",
        "offsetof",
        "reinterpret",
        "sizeof",
    ]
    for attr in drgn_globals:
        user_ns[attr] = getattr(drgn, attr)
    user_ns["__name__"] = "__main__"
    user_ns["__doc__"] = None
    lh = importlib.import_module("drgn.helpers.linux")
    user_ns.update({n: lh.__dict__[n] for n in lh.__all__})
    return user_ns


def main():
    parser = make_argument_parser()
    args = parser.parse_args()
    prog = drgn.Program()
    try:
        prog.set_core_dump(args.core)
    except PermissionError:
        # I literally cannot live without this already
        if args.core == "/proc/kcore":
            prog.set_core_dump(open_via_sudo(args.core, os.O_RDONLY))
        else:
            raise
    prog.load_debug_info(paths=args.symbols)
    user_ns = create_user_namespace(prog)
    IPython.start_ipython(argv=[], user_ns=user_ns, config=configure(prog))


if __name__ == '__main__':
    main()
