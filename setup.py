#!/usr/bin/env python3

import re
import os
import os.path
from distutils.errors import DistutilsSetupError
import distutils.log
from setuptools import setup, find_packages
from setuptools.extension import Extension
from setuptools.command.build_ext import build_ext
from setuptools.command.egg_info import egg_info
from setuptools.command.sdist import sdist
import subprocess


def out_of_date(dependencies, target):
    dependency_mtimes = [os.path.getmtime(dependency) for dependency in
                         dependencies]
    try:
        target_mtime = os.path.getmtime(target)
    except OSError:
        return True
    return any(dependency_mtime >= target_mtime for dependency_mtime in
               dependency_mtimes)


# This is also used to integrate with external build systems.
def gen_constants(input_path, output_path, header_directory=None):
    with open(input_path, 'r') as f:
        drgn_h = f.read()

    program_flags = re.findall(r'^\s*DRGN_PROGRAM_([a-zA-Z0-9_]+)\s*[=,]',
                               drgn_h, flags=re.MULTILINE)
    program_flags.remove('ENDIAN')
    qualifiers = re.findall(r'^\s*DRGN_QUALIFIER_([a-zA-Z0-9_]+)\s*[=,]',
                            drgn_h, flags=re.MULTILINE)
    type_kinds = re.findall(r'^\s*DRGN_TYPE_([a-zA-Z0-9_]+)\s*[=,]', drgn_h,
                            flags=re.MULTILINE)

    with open(output_path, 'w') as f:
        f.write(f"""\
#include "{os.path.join(header_directory or '', 'drgnpy.h')}"

PyObject *ProgramFlags_class;
PyObject *Qualifiers_class;
PyObject *TypeKind_class;

int add_module_constants(PyObject *m)
{{
	PyObject *enum_module;
	PyObject *tmp, *item;
	int ret = -1;

	enum_module = PyImport_ImportModule("enum");
	if (!enum_module)
		return -1;

	tmp = PyList_New({len(program_flags)});
	if (!tmp)
		goto out;
""")
        for i, program_flag in enumerate(program_flags):
            f.write(f"""\
	item = Py_BuildValue("sk", "{program_flag}", DRGN_PROGRAM_{program_flag});
	if (!item)
		goto out;
	PyList_SET_ITEM(tmp, {i}, item);
""")

        f.write(f"""\
	ProgramFlags_class = PyObject_CallMethod(enum_module, "Flag", "sO", "ProgramFlags", tmp);
	if (!ProgramFlags_class)
		goto out;
	if (PyModule_AddObject(m, "ProgramFlags", ProgramFlags_class) == -1) {{
		Py_CLEAR(ProgramFlags_class);
		goto out;
	}}
	Py_DECREF(tmp);
	tmp = PyUnicode_FromString("Program flags.");
	if (!tmp)
		goto out;
	if (PyObject_SetAttrString(ProgramFlags_class, "__doc__", tmp) == -1)
		goto out;
	Py_DECREF(tmp);

	tmp = PyList_New({len(qualifiers)});
	if (!tmp)
		goto out;
""")
        for i, qualifier in enumerate(qualifiers):
            f.write(f"""\
	item = Py_BuildValue("sk", "{qualifier}", DRGN_QUALIFIER_{qualifier});
	if (!item)
		goto out;
	PyList_SET_ITEM(tmp, {i}, item);
""")
        f.write(f"""\
	Qualifiers_class = PyObject_CallMethod(enum_module, "Flag", "sO", "Qualifiers", tmp);
	if (!Qualifiers_class)
		goto out;
	if (PyModule_AddObject(m, "Qualifiers", Qualifiers_class) == -1) {{
		Py_CLEAR(Qualifiers_class);
		goto out;
	}}
	Py_DECREF(tmp);
	tmp = PyUnicode_FromString("Type qualifiers.");
	if (!tmp)
		goto out;
	if (PyObject_SetAttrString(Qualifiers_class, "__doc__", tmp) == -1)
		goto out;
	Py_DECREF(tmp);

	tmp = PyList_New({len(type_kinds)});
	if (!tmp)
		goto out;
""")
        for i, type_kind in enumerate(type_kinds):
            f.write(f"""\
	item = Py_BuildValue("sk", "{type_kind}", DRGN_TYPE_{type_kind});
	if (!item)
		goto out;
	PyList_SET_ITEM(tmp, {i}, item);
""")
        f.write(f"""\
	TypeKind_class = PyObject_CallMethod(enum_module, "Enum", "sO", "TypeKind", tmp);
	if (!TypeKind_class)
		goto out;
	if (PyModule_AddObject(m, "TypeKind", TypeKind_class) == -1) {{
		Py_CLEAR(TypeKind_class);
		goto out;
	}}
	Py_DECREF(tmp);
	tmp = PyUnicode_FromString("Kind of type.");
	if (!tmp)
		goto out;
	if (PyObject_SetAttrString(TypeKind_class, "__doc__", tmp) == -1)
		goto out;

	ret = 0;
out:
	Py_XDECREF(tmp);
	Py_XDECREF(enum_module);
	return ret;
}}
""")


class my_build_ext(build_ext):
    def run(self):
        drgn_h_path = 'libdrgn/drgn.h'
        constants_path = '_drgn/constants.c'
        if out_of_date([drgn_h_path], constants_path):
            distutils.log.info('generating %r from %r', constants_path,
                               drgn_h_path)
            try:
                gen_constants(drgn_h_path, constants_path)
            except Exception:
                try:
                    os.remove(constants_path)
                except OSError:
                    pass
                raise
        super().run()


class my_egg_info(egg_info):
    def run(self):
        if not os.path.exists('libdrgn/configure'):
            subprocess.check_call(['autoreconf', '-i', 'libdrgn'])
        super().run()


class my_sdist(sdist):
    user_options = sdist.user_options + [
        ('force', 'f',
         'create the source distribution even if the repository is unclean'),
    ]

    boolean_options = sdist.boolean_options + ['force']

    def initialize_options(self):
        super().initialize_options()
        self.force = 0

    def run(self):
        # In order to avoid shipping a stale source distribution (e.g., due to
        # pypa/setuptools#436 or the autotools output being out of date),
        # require the repository to be clean (no unknown or ignored files).
        # This check can be disabled with --force.
        if not self.force and subprocess.check_output(['git', 'clean', '-dnx']):
            raise DistutilsSetupError('repository has untracked or ignored files; '
                                      'please run git clean -dfx or use --force')
        super().run()


extensions = [
    Extension(
        name='_drgn',
        # The Python bindings for libdrgn rely on some internal APIs, so the
        # extension can't be a client of libdrgn. It's also a pain to get
        # libtool to produce a PIC static library that we can link to, so we
        # just compile libdrgn directly into the extension.
        sources=[
            '_drgn/constants.c',
            '_drgn/module.c',
            '_drgn/object.c',
            '_drgn/program.c',
            '_drgn/test.c',
            '_drgn/type.c',
            '_drgn/util.c',
            'libdrgn/dwarf_index.c',
            'libdrgn/dwarf_object_index.c',
            'libdrgn/dwarf_type_index.c',
            'libdrgn/error.c',
            'libdrgn/hash_table.c',
            'libdrgn/internal.c',
            'libdrgn/language_c.c',
            'libdrgn/lexer.c',
            'libdrgn/memory_file_reader.c',
            'libdrgn/mock.c',
            'libdrgn/object.c',
            'libdrgn/object_index.c',
            'libdrgn/path.c',
            'libdrgn/program.c',
            'libdrgn/serialize.c',
            'libdrgn/string_builder.c',
            'libdrgn/type.c',
            'libdrgn/type_index.c',
        ],
        extra_compile_args=['-D_GNU_SOURCE', '-DLIBDRGN_PUBLIC=',
                            '-fvisibility=hidden', '-fopenmp'],
        extra_link_args=['-fopenmp'],
        libraries=['dw', 'elf'],
    ),
]


if __name__ == '__main__':
    with open('libdrgn/drgn.h', 'r') as f:
        drgn_h = f.read()
    version_major = re.search('^#define DRGN_VERSION_MAJOR ([0-9])+$', drgn_h,
                              re.MULTILINE).group(1)
    version_minor = re.search('^#define DRGN_VERSION_MINOR ([0-9])+$', drgn_h,
                              re.MULTILINE).group(1)
    version_patch = re.search('^#define DRGN_VERSION_PATCH ([0-9])+$', drgn_h,
                              re.MULTILINE).group(1)

    setup(
        name='drgn',
        version=f'{version_major}.{version_minor}.{version_patch}',
        packages=find_packages(exclude=['examples', 'scripts', 'tests']),
        ext_modules=extensions,
        cmdclass={
            'build_ext': my_build_ext,
            'egg_info': my_egg_info,
            'sdist': my_sdist,
        },
        entry_points={
            'console_scripts': ['drgn=drgn.internal.cli:main'],
        },
        author='Omar Sandoval',
        author_email='osandov@osandov.com',
        description='Scriptable debugger library',
        license='GPL-3.0+',
        url='https://github.com/osandov/drgn',
    )
