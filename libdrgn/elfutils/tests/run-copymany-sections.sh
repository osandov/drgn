#! /bin/sh
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

# Same as run-copyadd-sections.sh, but for many > 0xffff sections.
# Doesn't use mmap for addsections since that doesn't work.
# ELF_C_RDWR_MMAP needs mremap which will fail since it needs too 
# much space and the original mmap cannot move.

. $srcdir/test-subr.sh

test_copy_and_add ()
{
  in_file="$1"
  out_file="${in_file}.copy"
  out_file_mmap="${out_file}.mmap"

  tempfiles ${out_file} ${out_file_mmap} readelf.out

  # Can we copy the file?
  testrun ${abs_builddir}/elfcopy ${in_file} ${out_file}
  testrun ${abs_top_builddir}/src/elfcmp ${in_file} ${out_file}

  # Can we add a section (in-place)?
  testrun ${abs_builddir}/addsections 65535 ${out_file}
  testrun ${abs_top_builddir}/src/readelf -S ${out_file} > readelf.out
  nr=$(grep '.extra' readelf.out | wc -l)
  # We try twice...
  if test ${nr} != 65535 -a ${nr} != 131070; then
    # Show what went wrong
    testrun ${abs_top_builddir}/src/readelf -S ${out_file}
    exit 1
  fi

  # Can we copy the file using ELF_C_WRITE_MMAP?
  testrun ${abs_builddir}/elfcopy --mmap ${in_file} ${out_file_mmap}
  testrun ${abs_top_builddir}/src/elfcmp ${in_file} ${out_file_mmap}

  # Don't try to add using mmap (see above)
}

# A collection of random testfiles to test 32/64bit, little/big endian
# and non-ET_REL (with phdrs)/ET_REL (without phdrs).
# Try to add 0xffff sections twice.

# 32bit, big endian, rel
testfiles testfile29
test_copy_and_add testfile29
test_copy_and_add testfile29.copy

# 64bit, big endian, rel
testfiles testfile23
test_copy_and_add testfile23
test_copy_and_add testfile23.copy

# 32bit, little endian, rel
testfiles testfile9
test_copy_and_add testfile9
test_copy_and_add testfile9.copy

# 64bit, little endian, rel
testfiles testfile38
test_copy_and_add testfile38
test_copy_and_add testfile38.copy

# 32bit, big endian, non-rel
testfiles testfile26
test_copy_and_add testfile26
test_copy_and_add testfile26.copy

# 64bit, big endian, non-rel
testfiles testfile27
test_copy_and_add testfile27
test_copy_and_add testfile27.copy

# 32bit, little endian, non-rel
testfiles testfile
test_copy_and_add testfile
test_copy_and_add testfile.copy

# 64bit, little endian, non-rel
testfiles testfile10
test_copy_and_add testfile10
test_copy_and_add testfile10.copy

exit 0
