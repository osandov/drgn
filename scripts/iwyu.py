#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import argparse
import json
import os
import os.path
import re
import subprocess
import sys
import sysconfig
import tempfile

import yaml

BUILD_BASE = "build/compile_commands"
CDB = BUILD_BASE + "/compile_commands.json"

IWYU_REGEXES = [
    ("add", r"(.*) should add these lines:"),
    ("remove", r"(.*) should remove these lines:"),
    ("include_list", r"The full include-list for (.*):"),
    ("none", r"---"),
    ("none", r"\(.* has correct #includes/fwd-decls\)"),
]


# Python.h is the canonical header for the Python C API. The actual definitions
# come from internal header files, so we need an IWYU mapping file. Ideally we
# could do this with include mappings. Unfortunately, Python.h uses ""-style
# includes for those headers, one of which is "object.h". This conflicts with
# libdrgn's "object.h", and IWYU doesn't seem to have a way to distinguish
# between those in the mapping file. So, we generate symbol mappings with the
# find-all-symbols Clang tool.
def gen_python_mapping_file(mapping_path):
    # These headers are guaranteed to be included by Python.h. See
    # https://docs.python.org/3/c-api/intro.html#include-files.
    IMPLIED_HEADERS = (
        "<assert.h>",
        "<errno.h>",
        "<limits.h>",
        "<stdio.h>",
        "<stdlib.h>",
        "<string.h>",
    )

    include = sysconfig.get_path("include")
    platinclude = sysconfig.get_path("platinclude")

    with open(
        mapping_path + ".tmp", "w"
    ) as imp, tempfile.TemporaryDirectory() as tmpdir:
        imp.write("[\n")
        for header in IMPLIED_HEADERS:
            imp.write(
                f'  {{"include": ["{header}", "public", "<Python.h>", "public"]}},\n'
            )

        build_dir = os.path.join(tmpdir, "build")
        os.mkdir(build_dir)
        source = os.path.join(build_dir, "python.c")
        with open(source, "w") as f:
            f.write("#include <Python.h>")

        commands = [
            {
                "arguments": [
                    "clang",
                    "-I",
                    include,
                    "-I",
                    platinclude,
                    "-c",
                    "python.c",
                ],
                "directory": build_dir,
                "file": "python.c",
            }
        ]
        with open(os.path.join(build_dir, "compile_commands.json"), "w") as f:
            json.dump(commands, f)

        symbols_dir = os.path.join(tmpdir, "find_all_symbols")
        os.mkdir(symbols_dir)
        subprocess.check_call(
            [
                "find-all-symbols",
                "-p=" + build_dir,
                "--output-dir=" + symbols_dir,
                source,
            ]
        )

        find_all_symbols_db = os.path.join(tmpdir, "find_all_symbols_db.yaml")
        subprocess.check_call(
            [
                "find-all-symbols",
                "-p=" + build_dir,
                "--merge-dir=" + symbols_dir,
                find_all_symbols_db,
            ]
        )

        with open(find_all_symbols_db, "r") as f:
            for document in yaml.safe_load_all(f):
                name = document["Name"]
                path = document["FilePath"]
                if path.startswith(include + "/"):
                    header = path[len(include) + 1 :]
                elif path.startswith(platinclude + "/"):
                    header = path[len(platinclude) + 1 :]
                else:
                    continue
                if header == "pyconfig.h":
                    # Probably best not to use these.
                    continue
                imp.write(
                    f'  {{"symbol": ["{name}", "private", "<Python.h>", "public"]}},  # From {header}\n'
                )
        # "cpython/object.h" defines struct _typeobject { ... } PyTypeObject.
        # For some reason, include-what-you-mean wants struct _typeobject, but
        # find-all-symbols only reports PyTypeObject. Add it manually.
        imp.write(
            f'  {{"symbol": ["_typeobject", "private", "<Python.h>", "public"]}},  # From cpython/object.h\n'
        )

        imp.write("]\n")

    os.rename(mapping_path + ".tmp", mapping_path)


def main():
    parser = argparse.ArgumentParser(description="run include-what-you-use on drgn")
    parser.add_argument(
        "source", nargs="*", help="run on given file instead of all source files"
    )
    args = parser.parse_args()

    if args.source:
        sources = {os.path.realpath(source) for source in args.source}

    os.makedirs(BUILD_BASE, exist_ok=True)
    subprocess.check_call(
        [
            "bear",
            "--output",
            CDB,
            "--append",
            "--",
            sys.executable,
            "setup.py",
            "build",
            "-b",
            BUILD_BASE,
            "build_ext",
        ]
    )

    python_mapping_file = os.path.join(
        BUILD_BASE,
        f"python.{sysconfig.get_platform()}.{sysconfig.get_python_version()}.imp",
    )
    if not os.path.exists(python_mapping_file):
        gen_python_mapping_file(python_mapping_file)

    with open(CDB, "r") as f:
        commands = json.load(f)

    for command in commands:
        if (
            args.source
            and os.path.realpath(os.path.join(command["directory"], command["file"]))
            not in sources
        ):
            continue

        with subprocess.Popen(
            ["include-what-you-use"]
            + command["arguments"][1:]
            + [
                "-Xiwyu",
                "--mapping_file=" + os.path.abspath(python_mapping_file),
                "-w",  # We don't want warnings from Clang.
            ],
            cwd=command["directory"],
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            state = "none"
            header = None
            lines = []
            for line in proc.stdout:
                line = line.rstrip("\n")
                match = None
                for new_state, regex in IWYU_REGEXES:
                    match = re.fullmatch(regex, line)
                    if match:
                        break
                if match:
                    state = new_state
                    if state != "none":
                        path = os.path.relpath(
                            os.path.join(command["directory"], match.group(1))
                        )
                    if state in ("add", "remove"):
                        header = f"{path} should {state} these lines:"
                    else:
                        header = None
                    lines.clear()
                elif state != "include_list" and line:
                    if header is not None:
                        print("\n" + header)
                        header = None
                    print(line)
    print(
        "Please ignore suggestions to declare opaque types if the appropriate header has already been included."
    )


if __name__ == "__main__":
    main()
