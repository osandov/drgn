#!/usr/bin/env python3

from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext
import os.path


def out_of_date(dependencies, target):
    dependency_mtimes = [os.path.getmtime(dependency) for dependency in dependencies]
    try:
        target_mtime = os.path.getmtime(target)
    except OSError:
        return True
    return any(dependency_mtime >= target_mtime for dependency_mtime in dependency_mtimes)


def gen_header():
    import drgn.dwarf.defs as defs

    def write_enum(e):
        f.write('enum {\n')
        for name, value in e.__members__.items():
            f.write(f'\t{e.__name__}_{name} = 0x{value:x},\n')
        f.write('};\n\n')

    with open('lldwarf/dwarfdefs.h', 'w') as f:
        f.write('#ifndef DWARFDEFS_H\n')
        f.write('#define DWARFDEFS_H\n\n')

        write_enum(defs.DW_CHILDREN)
        write_enum(defs.DW_TAG)
        write_enum(defs.DW_AT)
        write_enum(defs.DW_FORM)
        write_enum(defs.DW_LNS)
        write_enum(defs.DW_LNE)

        f.write('#endif /* DWARFDEFS_H */\n')


class my_build_ext(build_ext):
    def run(self):
        if out_of_date(['drgn/dwarf/defs.py', 'setup.py'], 'lldwarf/dwarfdefs.h'):
            try:
                gen_header()
            except Exception as e:
                try:
                    os.remove('lldwarf/dwarfdefs.h')
                except OSError:
                    pass
                raise e
        super().run()


module = Extension(
    name='drgn.lldwarf',
    sources=[
        'lldwarf/module.c',
        'lldwarf/object.c',
        'lldwarf/abbrev.c',
        'lldwarf/cu.c',
        'lldwarf/die.c',
        'lldwarf/line.c',
    ],
    extra_compile_args=['-DTEST_LLDWARFOBJECT'],
)

setup(
    name='drgn',
    entry_points={
        'console_scripts': ['drgn=drgn.cli:main'],
    },
    cmdclass={'build_ext': my_build_ext},
    ext_modules=[module],
    packages=find_packages(),
    test_suite='tests',
)
