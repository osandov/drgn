#! /bin/bash
# Copyright (C) 2019 Red Hat, Inc.
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

# Only run on 64bit systems, 32bit systems don't support > 4GB
# ELF files.
long_bit=$(getconf LONG_BIT)
echo "long_bit: $long_bit"
if test $long_bit -ne 64; then
  echo "Only 64bit systems can create > 4GB ELF files"
  exit 77
fi

# These tests need lots of disk space since they test files > 4GB.
# Skip if there just isn't enough (2.5 * 4 = 10GB).
space_available=$[$(stat -f --format="%a*%S" .)/(1024 * 1024 * 1024)]
echo "space_available: $space_available"
if test $space_available -lt 10; then
  echo "Not enough disk space, need at least 10GB available"
  exit 77
fi

# Make sure the files fit into memory, assume 6GB needed (2.5 * 2 + 1 extra).
# Running under valgrind might need even more.
mem_needed=6
if [ "x$VALGRIND_CMD" != "x" ]; then
  mem_needed=$[${mem_needed} + 2]
fi
echo "mem_needed: $mem_needed"
mem_available=$(free -g 2>/dev/null | grep ^Mem: | awk -F ' +' '{print $7}')
echo "mem_available: $mem_available"
if test -z "$mem_available" || test $mem_available -lt $mem_needed; then
  echo "Need at least ${mem_needed}GB free available memory"
  exit 77
fi

# Make sure the disk is reasonably fast, should be able to write 100MB/s
fast_disk=1
timeout -s9 10s dd conv=fsync if=/dev/zero of=tempfile bs=1M count=1K \
  || fast_disk=0; rm tempfile
if test $fast_disk -eq 0; then
  echo "File system not fast enough, need at least 100MB/s"
  exit 77
fi

# NOTE: test file will be mangled and removed!
test_file ()
{
  in_file="$1"
  readelf_out="${in_file}.readelf.out"
  out_file_strip="${in_file}.strip"
  out_file_debug="${in_file}.debug"

  testfiles ${in_file}
  tempfiles ${readelf_out} ${out_file_mmap} ${out_file_strip} ${out_file_debug}

  # Add two 2GB sections to the file.
  echo "addsections 2 ${in_file} 2147483648"
  testrun ${abs_builddir}/addsections 2 ${in_file} 2147483648
  testrun ${abs_top_builddir}/src/readelf -S ${in_file} > ${readelf_out}
  nr=$(grep '.extra' ${readelf_out} | wc -l)
  if test ${nr} != 2; then
    # Show what went wrong
    cat ${readelf_out}
    exit 1
  fi

  echo "strip -o ${out_file_strip} -f ${out_file_debug} ${in_file}"
  testrun ${abs_top_builddir}/src/strip -o ${out_file_strip} \
                                        -f ${out_file_debug} ${in_file}

  echo "elflint --gnu ${out_file_strip}"
  testrun ${abs_top_builddir}/src/elflint --gnu ${out_file_strip}

  echo "elflint --gnu -d ${out_file_debug}"
  testrun ${abs_top_builddir}/src/elflint --gnu -d ${out_file_debug}

  # Now test unstrip recombining those files.
  echo "unstrip ${out_file_strip} ${out_file_debug}"
  testrun ${abs_top_builddir}/src/unstrip ${out_file_strip} ${out_file_debug}

  echo "elfcmp ${out_file} ${out_file_strip}"
  testrun ${abs_top_builddir}/src/elfcmp ${in_file} ${out_file_debug}

  # Remove the temp files immediately, they are big...
  rm -f ${in_file} ${out_file_strip} ${out_file_debug}
}

# A collection of random testfiles to test 64bit, little/big endian
# and non-ET_REL (with phdrs)/ET_REL (without phdrs).
# Don't test 32bit, they cannot go beyond 4GB.

# 64bit, little endian, rel
test_file testfile38

# 64bit, big endian, non-rel
test_file testfile27

exit 0
