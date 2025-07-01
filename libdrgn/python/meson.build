constants_c = custom_target(
    output: 'constants.c',
    input: ['../drgn.h'],
    command: [prog_python, files('../build-aux/gen_constants.py')],
    feed: true,
    capture: true,
)

drgndoc_docstrings_files = files(
    '../../docs/exts/drgndoc/__init__.py',
    '../../docs/exts/drgndoc/docstrings.py',
    '../../docs/exts/drgndoc/ext.py',
    '../../docs/exts/drgndoc/format.py',
    '../../docs/exts/drgndoc/namespace.py',
    '../../docs/exts/drgndoc/parse.py',
    '../../docs/exts/drgndoc/util.py',
    '../../docs/exts/drgndoc/visitor.py',
)

docstrings_env = environment()
docstrings_env.prepend(
    'PYTHONPATH',
    meson.current_source_dir() / '../../docs/exts',
)

docstrings_c = custom_target(
    output: 'docstrings.c',
    input: '../../_drgn.pyi',
    depend_files: drgndoc_docstrings_files,
    command: [prog_python, '-m', 'drgndoc.docstrings', '-m', '_drgn:drgn', '@INPUT@'],
    capture: true,
    env: docstrings_env,
)

docstrings_h = custom_target(
    output: 'docstrings.h',
    input: '../../_drgn.pyi',
    depend_files: drgndoc_docstrings_files,
    command: [prog_python, '-m', 'drgndoc.docstrings', '-H', '-m', '_drgn:drgn', '@INPUT@'],
    capture: true,
    env: docstrings_env,
)

py.extension_module(
    '_drgn',
    [
        'debug_info_options.c',
        'error.c',
        'helpers.c',
        'language.c',
        'main.c',
        'module.c',
        'module_section_addresses.c',
        'object.c',
        'platform.c',
        'plugins.c',
        'program.c',
        'stack_trace.c',
        'symbol.c',
        'symbol_index.c',
        'test.c',
        'thread.c',
        'type.c',
        'type_kind_set.c',
        'util.c',
        constants_c,
        docstrings_c,
        docstrings_h,
    ],
    include_directories: incdir,
    gnu_symbol_visibility: 'hidden',
    link_with: libdrgn.get_static_lib(),
    install: true,
)
