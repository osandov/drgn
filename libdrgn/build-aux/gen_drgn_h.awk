# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

# This script generates "drgn.h" from "drgn.h.in" and all of the
# "arch_foo.c.in" files. It replaces @DRGN_VERSION_*@ based on the "version"
# variable given on the command line and @ENUM_DRGN_REGISTER_NUMBER@ with the
# definition generated from the "arch_foo.c.in" files.

BEGIN {
	if (!match(version, /^([0-9]+)\.([0-9]+)\.([0-9]+)/, version_arr)) {
		print "could not parse version" > "/dev/stderr"
		exit 1
	}
	enum = "enum drgn_register_number {\n"
}

ARGIND == ARGC - 1 {
	gsub(/@DRGN_VERSION_MAJOR@/, version_arr[1])
	gsub(/@DRGN_VERSION_MINOR@/, version_arr[2])
	gsub(/@DRGN_VERSION_PATCH@/, version_arr[3])
	gsub(/@ENUM_DRGN_REGISTER_NUMBER@/, enum)
	print
	next
}

ENDFILE {
	if (ARGIND == ARGC - 1)
		exit
	if (!match(FILENAME, /^([^\/]*\/)*arch_([^\/]*)\.c\.in$/, group)) {
		print FILENAME ": error: could not parse architecture name" > "/dev/stderr"
		exit 1
	}
	prefix = "DRGN_REGISTER_" toupper(sanitize(arch_name)) "_"
	PROCINFO["sorted_in"] = "@val_num_asc"
	for (reg in registers)
		enum = enum "\t" prefix sanitize(reg) " = " registers[reg] ",\n"
	if (ARGIND == ARGC - 2)
		enum = enum "};"
}
