from drgn.dwarf import DwarfProgram
from drgn.ftrace import Kprobe, FtraceInstance
import re
import os


def sanitize_probe_name(name: str) -> str:
    name = re.sub('[^0-9A-Za-z]', '_', name)
    if name[0].isdigit():
        name = '_' + name
    return name


def cmd_probe(args):
    if args.line or (not args.function and ':' in args.location):
        function = None
        filename, lineno = args.location.rsplit(':', 1)
        # TODO: catch ValueError
        lineno = int(lineno)
        probe_name = sanitize_probe_name(f'{filename}_{lineno}')
    else:
        function = args.location
        probe_name = sanitize_probe_name(function)
    probe_name = f'drgn/{probe_name}'

    binary = f'/lib/modules/{os.uname().release}/build/vmlinux'
    with DwarfProgram(binary) as dwarf_program:
        if function is not None:
            probe_location = function
        else:
            probe_location = dwarf_program.find_breakpoint_location(filename, lineno)

    # TODO: deal with probe name collisions
    with FtraceInstance(f'drgn_{os.getpid()}') as instance, \
         Kprobe(probe_name, probe_location) as probe:
        probe.enable(instance)
        try:
            import subprocess
            subprocess.call(['cat', f'/sys/kernel/debug/tracing/instances/{instance.name}/trace_pipe'])
        finally:
            probe.disable(instance)


def register(subparsers):
    subparser = subparsers.add_parser(
        'probe')

    subparser.add_argument(
        'location', metavar='LOCATION',
        help='location to probe; either a function name or file:line')

    group = subparser.add_mutually_exclusive_group()
    group.add_argument(
        '--line', '-l', action='store_true',
        help='force location to be treated as file:line')
    group.add_argument(
        '--function', '-f', action='store_true',
        help='force location to be treated as function name')

    subparser.set_defaults(func=cmd_probe)
