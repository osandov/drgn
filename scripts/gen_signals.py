#!/usr/bin/env python3

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Mapping, Sequence, Set, Tuple

_SRCARCH_TO_MACHINE_NAMES = {
    "arm64": ["aarch64"],
    "loongarch": ["loongarch", "loongarch64"],
    "mips": ["mips", "mips64"],
    "parisc": ["parisc", "parisc64"],
    "powerpc": ["ppc", "ppc64"],
    "riscv": ["riscv32", "riscv64"],
    "s390": ["s390", "s390x"],
    "sparc": ["sparc", "sparc64"],
    "x86": ["i386", "x86_64"],
}


def srcarch_to_machine_names(srcarch: str) -> List[str]:
    return _SRCARCH_TO_MACHINE_NAMES.get(srcarch, [srcarch])


def parse_mandatory_y(path: Path) -> List[str]:
    return re.findall(r"^\s*mandatory-y\s*\+=\s*(\S+)", path.read_text(), flags=re.M)


def create_mandatory(
    dest_dir: Path, arch_dir: Path, generic_dir: Path, files: List[str]
) -> None:
    dest_dir.mkdir(parents=True)
    for file in files:
        if not (arch_dir / file).exists():
            shutil.copyfile(generic_dir / file, dest_dir / file)


def parse_constants(contents: str, prefix: str) -> Dict[str, int]:
    result = {}
    for name, definition in re.findall(
        rf"^gen_signals_py_({re.escape(prefix)}\S+) (.*)", contents, flags=re.M
    ):
        if match := re.fullmatch(r"\(\s*([0-9]+)\s*-\s*([0-9]+)\s*\)", definition):
            # Hack for xtensa, which defines SIGRTMAX as (_NSIG-1)
            result[name] = int(match.group(1)) - int(match.group(2))
        else:
            result[name] = int(
                # Remove U and L suffixes.
                re.sub(
                    r"^([0-9]+|0x[0-9a-f]+)[ul]+$",
                    r"\1",
                    definition,
                    flags=re.IGNORECASE,
                ),
                0,
            )
    return result


def add_synonym(constants: Dict[str, int], name1: str, name2: str) -> None:
    try:
        if constants[name1] != constants[name2]:
            raise ValueError(f"{name1} and {name2} are not synonyms")
        return
    except KeyError:
        pass
    try:
        constants[name1] = constants[name2]
        return
    except KeyError:
        pass
    try:
        constants[name2] = constants[name1]
    except KeyError:
        pass


def sort_constants(
    constants: Dict[str, int], preferred_synonyms: Set[str]
) -> Tuple[Tuple[str, int], ...]:
    def key_func(item: Tuple[str, int]):
        name, value = item
        return value, name not in preferred_synonyms

    sorted_constants = tuple(sorted(constants.items(), key=key_func))
    for i in range(1, len(sorted_constants)):
        if key_func(sorted_constants[i - 1]) == key_func(sorted_constants[i]):
            raise ValueError(
                f"duplicate constants {sorted_constants[i - 1][0]} and {sorted_constants[i][0]}"
            )
    return sorted_constants


def print_deduplicated(
    deduplicated: Mapping[Tuple[Tuple[str, int], ...], Sequence[str]],
    dict_name: str,
    value_format: str,
) -> None:
    sys.stdout.write(f"_{dict_name}_TMP = {{}}\n")
    for items, machine_names in sorted(
        deduplicated.items(), key=lambda item: min(item[1])
    ):
        if len(machine_names) == 1:
            sys.stdout.write(f'_{dict_name}_TMP["{machine_names[0]}"] = ')
            indent = ""
        else:
            quoted_machine_names = [
                f'"{machine_name}"' for machine_name in machine_names
            ]
            quoted_machine_names.sort()
            sys.stdout.write(
                f"""\
for _name in ({", ".join(quoted_machine_names)}):
    _{dict_name}_TMP[_name] = """
            )
            indent = "    "
        sys.stdout.write(
            f"""types.MappingProxyType(
{indent}    {{
"""
        )
        for name, value in items:
            sys.stdout.write(f'{indent}        "{name}": {value:{value_format}},\n')
        sys.stdout.write(
            f"""\
{indent}    }}
{indent})
"""
        )
    sys.stdout.write(
        f"""\
{dict_name} = types.MappingProxyType(_{dict_name}_TMP)
del _{dict_name}_TMP
"""
    )


def main() -> None:
    argparse.ArgumentParser(
        description="Generate Python dictionaries containing signal numbers and sigaction flags from the kernel source code"
    ).parse_args()

    asm_generic_mandatory_y = parse_mandatory_y(Path("include/asm-generic/Kbuild"))
    uapi_asm_generic_mandatory_y = parse_mandatory_y(
        Path("include/uapi/asm-generic/Kbuild")
    )

    deduplicated_signals: Dict[Tuple[Tuple[str, int], ...], List[str]] = {}
    deduplicated_flags: Dict[Tuple[Tuple[str, int], ...], List[str]] = {}
    for arch_dir in Path("arch").iterdir():
        if not arch_dir.is_dir() or arch_dir.name == "um":
            continue

        with tempfile.TemporaryDirectory() as arch_include_generated_dir:
            arch_include_generated = Path(arch_include_generated_dir)
            create_mandatory(
                arch_include_generated / "asm",
                arch_dir / "include/asm",
                Path("include/asm-generic"),
                asm_generic_mandatory_y,
            )
            create_mandatory(
                arch_include_generated / "uapi/asm",
                arch_dir / "include/uapi/asm",
                Path("include/uapi/asm-generic"),
                uapi_asm_generic_mandatory_y,
            )
            if arch_dir.name == "arm64":
                # These headers get included at some point. Normally the kernel
                # build process generates them, but we don't actually need
                # their contents.
                for name in ("cpucap-defs.h", "sysreg-defs.h"):
                    (arch_include_generated / "asm" / name).touch()

            gcc_args = [
                "-w",
                "-nostdinc",
                f"-I./{arch_dir}/include",
                f"-I{arch_include_generated}",
                "-I./include",
                f"-I./{arch_dir}/include/uapi",
                f"-I{arch_include_generated}/uapi",
                "-I./include/uapi",
                "-D__KERNEL__",
                "-DIS_ENABLED(x)=0",
            ]

            defines = subprocess.run(
                ["gcc", *gcc_args, "-dM", "-E", "-"],
                input="#include <linux/signal_types.h>\n",
                stdout=subprocess.PIPE,
                check=True,
                text=True,
            ).stdout

            constant_names = set(
                re.findall(
                    r"^\s*#\s*define\s+(SIG[A-Z0-9]+|SA_\w+)\b", defines, flags=re.M
                )
            )
            # This is the size of the signal stack, not a signal.
            constant_names.discard("SIGSTKSZ")

            lines = [
                f"gen_signals_py_{constant_name} {constant_name}\n"
                for constant_name in constant_names
            ]
            lines.insert(0, "#include <linux/signal_types.h>\n")
            expanded = subprocess.run(
                ["gcc", *gcc_args, "-E", "-"],
                input="".join(lines),
                stdout=subprocess.PIPE,
                check=True,
                text=True,
            ).stdout

            machine_names = srcarch_to_machine_names(arch_dir.name)

            signals = parse_constants(expanded, "SIG")
            add_synonym(signals, "SIGCHLD", "SIGCLD")
            add_synonym(signals, "SIGABRT", "SIGIOT")
            add_synonym(signals, "SIGIO", "SIGPOLL")
            add_synonym(signals, "SIGSYS", "SIGUNUSED")
            sorted_signals = sort_constants(
                signals,
                {
                    "SIGCHLD",
                    "SIGABRT",
                    "SIGIO",
                    "SIGSYS",
                    # Preferred over SIGINFO on alpha.
                    "SIGPWR",
                    # Preferred over SIGSWI on arm.
                    "SIGRTMIN",
                },
            )
            deduplicated_signals.setdefault(sorted_signals, []).extend(machine_names)

            flags = parse_constants(expanded, "SA_")
            add_synonym(flags, "SA_NODEFER", "SA_NOMASK")
            add_synonym(flags, "SA_RESETHAND", "SA_ONESHOT")
            add_synonym(flags, "SA_ONSTACK", "SA_STACK")
            sorted_flags = sort_constants(
                flags, {"SA_NODEFER", "SA_RESETHAND", "SA_ONSTACK"}
            )
            deduplicated_flags.setdefault(sorted_flags, []).extend(machine_names)

    print_deduplicated(deduplicated_signals, "SIGNALS_BY_MACHINE_NAME", "")
    print()
    print_deduplicated(deduplicated_flags, "SIGACTION_FLAGS_BY_MACHINE_NAME", "#x")


if __name__ == "__main__":
    main()
