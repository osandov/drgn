from drgn import (
    int_type,
    float_type,
    struct_type,
    union_type,
    enum_type,
    typedef_type,
)


point_type = struct_type('point', 8, (
    (int_type('int', 4, True), 'x', 0),
    (int_type('int', 4, True), 'y', 32),
))
line_segment_type = struct_type('line_segment', 16, (
    (point_type, 'a'),
    (point_type, 'b', 64),
))
option_type = union_type('option', 4, (
    (int_type('int', 4, True), 'i'),
    (float_type('float', 4), 'f'),
))
color_type = enum_type('color', int_type('unsigned int', 4, False),
                       (('RED', 0), ('GREEN', 1), ('BLUE', 2)))
pid_type = typedef_type('pid_t', int_type('int', 4, True))
