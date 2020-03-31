import os
import os.path
import shlex
import subprocess
from typing import Dict

from util import out_of_date


def _compile(
    *args: str,
    CPPFLAGS: str = "",
    CFLAGS: str = "",
    LDFLAGS: str = "",
    LIBADD: str = ""
) -> None:
    # This mimics automake: the order of the arguments allows for the default
    # flags to be overridden by environment variables, and we use the same
    # default CFLAGS.
    cmd = [
        os.getenv("CC", "cc"),
        *shlex.split(CPPFLAGS),
        *shlex.split(os.getenv("CPPFLAGS", "")),
        *shlex.split(CFLAGS),
        *shlex.split(os.getenv("CFLAGS", "-g -O2")),
        *shlex.split(LDFLAGS),
        *shlex.split(os.getenv("LDFLAGS", "")),
        *args,
        *shlex.split(LIBADD),
        *shlex.split(os.getenv("LIBS", "")),
    ]
    print(" ".join([shlex.quote(arg) for arg in cmd]))
    subprocess.check_call(cmd)


def build_vmtest(dir: str) -> Dict[str, str]:
    os.makedirs(dir, exist_ok=True)

    init = os.path.join(dir, "init")
    init_c = os.path.relpath(os.path.join(os.path.dirname(__file__), "init.c"))
    if out_of_date(init, init_c):
        _compile("-o", init, init_c, CPPFLAGS="-D_GNU_SOURCE", LDFLAGS="-static")

    onoatimehack_so = os.path.join(dir, "onoatimehack.so")
    onoatimehack_c = os.path.relpath(
        os.path.join(os.path.dirname(__file__), "onoatimehack.c")
    )
    if out_of_date(onoatimehack_so, onoatimehack_c):
        _compile(
            "-o",
            onoatimehack_so,
            onoatimehack_c,
            CPPFLAGS="-D_GNU_SOURCE",
            CFLAGS="-fPIC",
            LDFLAGS="-shared",
            LIBADD="-ldl",
        )

    return {
        "init": init,
        "onoatimehack": onoatimehack_so,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="build vmtest files",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default="build/vmtest",
        help="directory to put built files in",
    )
    args = parser.parse_args()
    print(build_vmtest(args.directory))
