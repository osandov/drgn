fs = import('fs')
prog_python = find_program('python3')
incdir = include_directories('include')

arch_defs = [
    'aarch64',
    'arm',
    'ppc64',
    's390x',
    'x86_64',
]

arch_defs_inc_strswitches = []

foreach arch : arch_defs
    arch_defs_inc_strswitches += custom_target(
        output: 'arch_' + arch + '_defs.inc.strswitch',
        input: [
            'build-aux/gen_arch_inc_strswitch.py',
            'arch_' + arch + '_defs.py',
        ],
        depend_files: 'build-aux/codegen_utils.py',
        command: [prog_python, '@INPUT@'],
        capture: true,
    )
endforeach

c_keywords_inc_strswitch = custom_target(
    output: 'c_keywords.inc.strswitch',
    input: 'build-aux/gen_c_keywords_inc_strswitch.py',
    depend_files: 'build-aux/codegen_utils.py',
    command: [prog_python, '@INPUT@'],
    capture: true,
)

drgn_section_name_to_index_inc_strswitch = custom_target(
    output: 'drgn_section_name_to_index.inc.strswitch',
    input: 'build-aux/gen_elf_sections.py',
    depend_files: 'build-aux/codegen_utils.py',
    command: [prog_python, '@INPUT@'],
    capture: true,
)

elf_sections_h = custom_target(
    output: 'elf_sections.h',
    input: 'build-aux/gen_elf_sections.py',
    depend_files: 'build-aux/codegen_utils.py',
    command: [prog_python, '@INPUT@', '-H'],
    capture: true,
)

strswitch_inputs = [
    'drgn_program_parse_vmcoreinfo.inc.strswitch',
    'linux_kernel_object_find.inc.strswitch',
    c_keywords_inc_strswitch,
    drgn_section_name_to_index_inc_strswitch,
] + arch_defs_inc_strswitches

strswitch_outputs = []

foreach strswitch : strswitch_inputs
    strswitch_outputs += custom_target(
        output: fs.replace_suffix(fs.name(strswitch), ''),
        input: [strswitch, 'build-aux/gen_strswitch.py'],
        depend_files: 'build-aux/codegen_utils.py',
        command: [prog_python, '@INPUT1@', '-o', '@OUTPUT@', '@INPUT0@'],
    )
endforeach

version_c = custom_target(
    output: 'version.c',
    build_always_stale: true,
    command: [
        prog_python,
        files('../scripts/version.py'),
        '--source-root',
        meson.project_source_root(),
        '--gen-version-c',
        '@OUTPUT@',
    ],
)

libdrgn = both_libraries(
    'drgn',
    [
        'accessors.c',
        'arch_aarch64.c',
        'arch_arm.c',
        'arch_i386.c',
        'arch_ppc64.c',
        'arch_riscv.c',
        'arch_s390x.c',
        'arch_x86_64.c',
        'binary_buffer.c',
        'cfi.c',
        'crc32.c',
        'debug_info.c',
        'debug_info_options.c',
        'dwarf_constants.c',
        'dwarf_info.c',
        'elf_file.c',
        'elf_notes.c',
        'elf_symtab.c',
        'error.c',
        'handler.c',
        'hash_table.c',
        'hexlify.c',
        'io.c',
        'kallsyms.c',
        'kdump.c',
        'language.c',
        'language_c.c',
        'lazy_object.c',
        'lexer.c',
        'linux_kernel.c',
        'linux_kernel_helpers.c',
        'log.c',
        'memory_reader.c',
        # TODO: 'no_python.c',
        'object.c',
        'openmp.c',
        'orc_info.c',
        'path.c',
        'platform.c',
        'program.c',
        'register_state.c',
        'serialize.c',
        'splay_tree.c',
        'stack_trace.c',
        'string_builder.c',
        'symbol.c',
        'type.c',
        'util.c',
        elf_sections_h,
        version_c,
    ] + (libkdumpfile_dep.found() ? ['kdump.c'] : []) + strswitch_outputs,
    include_directories: incdir,
    gnu_symbol_visibility: 'hidden',
    dependencies: [
        cc.find_library('m', required: false),
        libdw_dep,
        libelf_dep,
        libkdumpfile_dep,
        liblzma_dep,
        openmp_dep,
    ],
    build_by_default: false,
)

subdir('examples')
subdir('python')
subdir('tests')
