# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash sym command."""

import argparse
import operator
import re
from typing import Any, List, Sequence

from drgn import Program, Symbol, SymbolKind
from drgn.commands import _repr_black, argument, drgn_argument, mutually_exclusive_group
from drgn.commands._crash.common import CrashDrgnCodeBuilder, crash_command

# Ignore symbols that the kernel excludes from kallsyms. See scripts/mksysmap
# in the Linux kernel source.
#
# scripts/mksysmap also ignores some symbols based on their nm(1) types, but we
# don't have a good way to do that.
_IGNORED_PREFIXES = (
    r"\$",
    r"\.L",
    r"__efistub_",
    r"__pi_\\$",
    r"__pi_\.L",
    r"__kvm_nvhe_\$",
    r"__kvm_nvhe_\.L",
    r"__\w*Thunk_",
    r"__kcfi_typeid_",
    r"__kvm_nvhe___kcfi_typeid_",
    r"__pi___kcfi_typeid_",
    r"__crc_",
    r"__kstrtab_",
    r"__kstrtabns_",
    r"__mod_device_table__",
)

_IGNORED_SUFFIXES = (
    r"_from_arm",
    r"_from_thumb",
    r"_veneer",
)

_IGNORED_EXACT = (
    r"L0",
    r"_SDA_BASE_",
    r"_SDA2_BASE_",
    r"__UNIQUE_ID_modinfo[0-9]*",
)

_IGNORED_CONTAINS = (
    r"\.long_branch\.",
    r"\.plt_branch\.",
)

_IGNORE_REGEX = re.compile(
    "|".join(
        [
            r"^(" + "|".join(_IGNORED_PREFIXES) + ")",
            r"(" + "|".join(_IGNORED_SUFFIXES) + ")$",
            r"^(" + "|".join(_IGNORED_EXACT) + ")$",
            r"(" + "|".join(_IGNORED_CONTAINS) + ")",
        ]
    )
)


def _include_symbol(sym: Symbol) -> bool:
    if sym.kind in {SymbolKind.SECTION, SymbolKind.FILE}:
        return False
    return not _IGNORE_REGEX.search(sym.name)


def _print_symbols(
    prog: Program, symbols: Sequence[Symbol], indent: str = "", verbose: bool = False
) -> None:
    for symbol in symbols:
        source_str = ""
        if verbose:
            try:
                source = prog.source_location(symbol.address)
            except LookupError:
                pass
            else:
                source_str = f" {source[0].filename}: {source[0].line}"
        print(f"{indent}{symbol.address:x} {symbol.name}{source_str}")


def _print_substring_matches(
    prog: Program, symbols: Sequence[Symbol], substring: str, indent: str = ""
) -> None:
    symbols = [symbol for symbol in symbols if substring in symbol.name]
    if symbols:
        _print_symbols(prog, symbols, indent)
    else:
        print(indent + "(none found)")


@crash_command(
    description="symbol table lookup",
    arguments=(
        mutually_exclusive_group(
            argument(
                "-l",
                dest="all",
                action="store_true",
                help="display all symbols and their values",
            ),
            argument(
                "-q",
                dest="string",
                action="append",
                help="""
                display all symbols whose name contains *STRING*. May be given
                multiple times
                """,
            ),
            # Crash allows -q to be combined with a name or address argument,
            # but that's confusing. Forbid it until someone complains.
            argument(
                "name_or_address",
                metavar="name|address",
                nargs="*",
                # Work around https://github.com/python/cpython/issues/72795
                # before Python 3.13.
                default=[],
                help="""
                symbol name or hexadecimal address to search for. May be given
                multiple times
                """,
            ),
            required=True,
        ),
        argument(
            "-p",
            dest="prev",
            action="store_true",
            help="display the target symbol and the previous symbol",
        ),
        argument(
            "-n",
            dest="next",
            action="store_true",
            help="display the target symbol and the next symbol",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_sym(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    *,
    parser: argparse.ArgumentParser,
    **kwargs: Any,
) -> None:
    if (args.next or args.prev) and not args.name_or_address:
        parser.error("-n/-p only make sense with name or address")

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)

        first = True
        if args.string or args.all or args.next or args.prev:
            code.add_import("operator")
            code.append(
                """\
all_symbols = prog.symbols()
all_symbols.sort(key=operator.attrgetter("address"))
"""
            )
            first = False

        if args.string is not None:
            code.append("\nfor sym in all_symbols:\n")
            if len(args.string) == 1:
                code.append(f"    if {_repr_black(args.string[0])} in sym.name:\n")
            else:
                code.append("    if any(substring in sym.name for substring in (")
                code.append(", ".join([_repr_black(string) for string in args.string]))
                code.append(")):\n")
            code.append("        ...\n")
            first = False

        for arg in args.name_or_address:
            if first:
                first = False
            else:
                code.append("\n")

            address = None
            try:
                prog.symbol(arg)
            except LookupError:
                try:
                    address = int(arg, 16)
                except ValueError:
                    pass

            if address is None:
                code.append(f"sym = prog.symbol({_repr_black(arg)})\n")
            else:
                code.append(f"sym = prog.symbol({hex(address)})\n")
            code.append(
                """\
try:
    source = prog.source_location(sym.address)
except LookupError:
    pass
"""
            )

            if args.prev or args.next:
                code.append("\ni = all_symbols.index(sym)\n")
            if args.prev:
                code.append(
                    """\
if i > 0:
    prev_sym = all_symbols[i - 1]
"""
                )
            if args.next:
                code.append(
                    """\
if i + 1 < len(all_symbols):
    next_sym = all_symbols[i + 1]
"""
                )

        if args.all:
            code.append(
                """\

for sym in all_symbols:
    ...
"""
            )

        return code.print()

    _all_symbols = None

    def all_symbols() -> List[Symbol]:
        nonlocal _all_symbols
        if _all_symbols is None:
            _all_symbols = [
                symbol for symbol in prog.symbols() if _include_symbol(symbol)
            ]
            _all_symbols.sort(key=operator.attrgetter("address"))
        return _all_symbols

    if args.string is not None:
        for string in args.string:
            _print_substring_matches(prog, all_symbols(), string)

    for arg in args.name_or_address:
        try:
            symbol = prog.symbol(arg)
        except LookupError:
            try:
                symbol = prog.symbol(int(arg, 16))
            except (ValueError, LookupError):
                print(f"symbol not found: {arg}\npossible alternatives:")
                _print_substring_matches(prog, all_symbols(), arg, "  ")
                continue

        symbols = [symbol]
        if args.prev or args.next:
            try:
                i = all_symbols().index(symbol)
            except ValueError:
                pass
            else:
                symbols = all_symbols()[
                    (i - 1 if args.prev and i > 0 else i) : (
                        i + 2 if args.next else i + 1
                    )
                ]

        _print_symbols(prog, symbols, verbose=True)

    if args.all:
        _print_symbols(prog, all_symbols())
