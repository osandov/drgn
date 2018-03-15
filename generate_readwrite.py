#!/usr/bin/env python3

SIZES = [8, 16, 32, 64]


def generate_read(name, read_type, ret_type=None):
    if ret_type is None:
        ret_type = read_type

    print(f"""

cdef inline int read_{name}(const char *buffer, Py_ssize_t buffer_size, Py_ssize_t *offset, {ret_type} *ret) except -1:
    check_bounds(buffer_size, offset[0], sizeof({read_type}))
    ret[0] = (<const {read_type} *>(buffer + offset[0]))[0]
    offset[0] += sizeof({read_type})
    return 0""")


def generate_write(name, write_type):
    print(f"""

cdef inline int write_{name}(char *buffer, Py_ssize_t buffer_size, Py_ssize_t offset, {write_type} value) except -1:
    check_bounds(buffer_size, offset, sizeof({write_type}))
    (<{write_type} *>(buffer + offset))[0] = value
    return 0""")


if __name__ == '__main__':
    for size in SIZES:
        generate_read(f's{size}', f'int{size}_t')
        generate_read(f'u{size}', f'uint{size}_t')
        if size < 64:
            generate_read(f'u{size}_into_u64', f'uint{size}_t', f'uint64_t')
            generate_read(f'u{size}_into_ssize_t', f'uint{size}_t', f'Py_ssize_t')
        generate_write(f'u{size}', f'uint{size}_t')
