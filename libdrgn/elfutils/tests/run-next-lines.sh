#! /bin/sh
# Variant of run-get-lines that uses dwarf_next_lines.
# Copyright (C) 2018 Red Hat, Inc.
# This file is part of elfutils.
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# elfutils is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

. $srcdir/test-subr.sh

testfiles testfile testfile2 testfilenolines

testrun_compare ${abs_builddir}/next-lines testfile testfile2 <<\EOF
off = 0
 5 lines
804842c: /home/drepper/gnu/new-bu/build/ttt/m.c:5:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048432: /home/drepper/gnu/new-bu/build/ttt/m.c:6:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
804844d: /home/drepper/gnu/new-bu/build/ttt/m.c:7:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048458: /home/drepper/gnu/new-bu/build/ttt/m.c:8:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
804845a: /home/drepper/gnu/new-bu/build/ttt/m.c:8:0: is_stmt:yes, end_seq:yes, bb:no, prologue:no, epilogue:no
off = 75
 4 lines
804845c: /home/drepper/gnu/new-bu/build/ttt/b.c:4:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
804845f: /home/drepper/gnu/new-bu/build/ttt/b.c:5:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048464: /home/drepper/gnu/new-bu/build/ttt/b.c:6:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048466: /home/drepper/gnu/new-bu/build/ttt/b.c:6:0: is_stmt:yes, end_seq:yes, bb:no, prologue:no, epilogue:no
off = 480
 4 lines
8048468: /home/drepper/gnu/new-bu/build/ttt/f.c:3:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
804846b: /home/drepper/gnu/new-bu/build/ttt/f.c:4:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048470: /home/drepper/gnu/new-bu/build/ttt/f.c:5:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048472: /home/drepper/gnu/new-bu/build/ttt/f.c:5:0: is_stmt:yes, end_seq:yes, bb:no, prologue:no, epilogue:no
off = 0
 4 lines
10000470: /shoggoth/drepper/b.c:4:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
1000047c: /shoggoth/drepper/b.c:5:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
10000480: /shoggoth/drepper/b.c:6:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
10000490: /shoggoth/drepper/b.c:6:0: is_stmt:yes, end_seq:yes, bb:no, prologue:no, epilogue:no
off = 418
 4 lines
10000490: /shoggoth/drepper/f.c:3:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
1000049c: /shoggoth/drepper/f.c:4:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
100004a0: /shoggoth/drepper/f.c:5:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
100004b0: /shoggoth/drepper/f.c:5:0: is_stmt:yes, end_seq:yes, bb:no, prologue:no, epilogue:no
off = 485
 5 lines
100004b0: /shoggoth/drepper/m.c:5:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
100004cc: /shoggoth/drepper/m.c:6:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
100004e8: /shoggoth/drepper/m.c:7:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
100004f4: /shoggoth/drepper/m.c:8:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
10000514: /shoggoth/drepper/m.c:8:0: is_stmt:yes, end_seq:yes, bb:no, prologue:no, epilogue:no
EOF

# - lines.c
# int ft;
#
# int
# main (int argc, char **argv)
# {
#   return ft - 42;
# }
#
# - nolines.c
# int ft = 42;
#
# gcc -g -c lines.c
# gcc -g -c nolines.c
# gcc -g -o testfilenolines lines.o nolines.o

testrun_compare ${abs_builddir}/next-lines testfilenolines <<\EOF
off = 0
 4 lines
400474: /home/mark/src/tests/lines.c:5:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
40047f: /home/mark/src/tests/lines.c:6:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
400488: /home/mark/src/tests/lines.c:7:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
40048a: /home/mark/src/tests/lines.c:7:0: is_stmt:yes, end_seq:yes, bb:no, prologue:no, epilogue:no
off = 59
 0 lines
EOF

# See run-next-files.
# Note no, comp_dir, so all paths are relative.
testfiles testfile-only-debug-line
testrun_compare ${abs_builddir}/next-lines testfile-only-debug-line <<\EOF
off = 0
 5 lines
804842c: m.c:5:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048432: m.c:6:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
804844d: m.c:7:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048458: m.c:8:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
804845a: m.c:8:0: is_stmt:yes, end_seq:yes, bb:no, prologue:no, epilogue:no
off = 75
 4 lines
804845c: b.c:4:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
804845f: b.c:5:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048464: b.c:6:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048466: b.c:6:0: is_stmt:yes, end_seq:yes, bb:no, prologue:no, epilogue:no
off = 480
 4 lines
8048468: f.c:3:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
804846b: f.c:4:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048470: f.c:5:0: is_stmt:yes, end_seq:no, bb:no, prologue:no, epilogue:no
8048472: f.c:5:0: is_stmt:yes, end_seq:yes, bb:no, prologue:no, epilogue:no
EOF

exit 0
