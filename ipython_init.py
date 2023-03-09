#!/usr/bin/env python3

from pathlib import Path

import IPython
from IPython.core.magic import Magics, line_magic, magics_class
from IPython.terminal.ipapp import load_default_config
from IPython.utils.capture import capture_output
from IPython.utils.text import SList

from drgn import execscript


@magics_class
class MyMagics(Magics):
    # FIXME
    contrib = Path("/home/marxin/Programming/drgn/contrib/")
    commands = None

    def _init_commands(self) -> None:
        self.commands = {}

        for cmd in self.contrib.iterdir():
            if cmd.suffix != ".py":
                continue
            helpmsg = self._get_command_help(cmd)
            if helpmsg:
                self.commands[cmd.stem] = (str(cmd), helpmsg)

    def _run_cmd(self, line: str) -> None:
        if not self.commands:
            self._init_commands()

        command, _, args = line.partition(" ")
        if not command or command == "help":
            print(self._get_help())
        elif command in self.commands:
            execscript(self.commands[command][0], *args.split())
        else:
            print(f"Command {command} not found")

    def _get_help(self) -> str:
        msg = "Available commands:\n"
        for cmd in sorted(self.commands.keys()):
            msg += f"  {cmd}: {self.commands[cmd][1]}\n"
        return msg.strip()

    def _get_command_help(self, path: Path) -> str:
        needle = '"""'
        for line in path.open().read().splitlines():
            if line.startswith(needle) and line.endswith(needle):
                return line[len(needle) : -len(needle)]
        return ""

    @line_magic
    def cmd(self, line: str):
        self._run_cmd(line)

    @line_magic
    def cmds(self, line: str):
        with capture_output() as co:
            self._run_cmd(line)
            return SList(co.stdout.splitlines())


def load_ipython_extension(ipython):
    ipython.register_magics(MyMagics)


def configure():
    c = load_default_config()
    c.InteractiveShellApp.extensions = [
        __name__,
    ]
    c.TerminalInteractiveShell.banner1 = (
        "\nWelcome to the IPython drgn\n"
        "You can run %cmd and %cmds magics that run scripts in contrib folder.\n"
    )
    return c


def main():
    IPython.start_ipython(user_ns=globals(), config=configure())


if __name__ == "__main__":
    main()
