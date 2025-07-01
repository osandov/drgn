prog_awk = find_program('awk')

check_tests = [
    'binary_search',
    'cityhash',
    'language_c',
    'lexer',
    'path',
    'recursion_guard',
]

# TODO: make this required only if running tests
check_dep = dependency('check', version: '>=0.10.0')

foreach check_test : check_tests
    test_c = custom_target(
        output: check_test + '.c',
        input: [check_test + '.c.in'],
        command: [prog_awk, '-f', files('../build-aux/checkmk'), '@INPUT@'],
        capture: true,
    )
    test_exe = executable(
        check_test,
        test_c,
        dependencies: check_dep,
        link_with: libdrgn.get_static_lib(),
        # TODO: this doesn't seem to work: https://github.com/mesonbuild/meson/issues/2518
        build_by_default: false,
    )
    test('test_' + check_test, test_exe)
endforeach
