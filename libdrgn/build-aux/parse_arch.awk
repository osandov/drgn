# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

# This script parses the architecture support files in drgn (arch_foo.c.in).
# The overall format of these files is:
#
# %{
# prologue
# %}
# declarations
# %%
# registers
# %%
# epilogue
#
# (This is similar to the format used by flex, bison, and gperf.)
#
# This script does not generate any output; it parses the input into several
# output variables which can be consumed by another script.
#
# The prologue and epilogue sections are copied verbatim into the "prologue"
# and "epilogue" variables.
#
# The declarations section contains additional options. Currently, the only
# option is the architecture name, which is indicated by a line not starting
# with "%". The name is assigned to the "arch_name" variable.
#
# The registers section contains a list of register definitions formatted as
# "name, number", one per line. The ", number" may be omitted, in which case it
# defaults to the previous number plus one (or zero for the first register).
# These are saved in the "registers" array; the indices are the register names,
# and the values are the numbers.
#
# Lines outside of the prologue and epilogue sections that start with "#" are
# ignored.

function error(msg,    filename) {
	print FILENAME ":" FNR ": error: " msg > "/dev/stderr"
	exit 1
}

function sanitize(s) {
	gsub(/[^a-zA-Z0-9_]/, "_", s)
	return s
}

BEGINFILE {
	state = "DECLARATIONS"
	prologue = ""
	epilogue = ""
	arch_name = ""
	split("", registers)
	regno = 0
}

# Comments.

state != "PROLOGUE" && state != "EPILOGUE" && /^#/ {
	next
}

# State transitions.

state == "DECLARATIONS" && $0 == "%{" {
	state = "PROLOGUE"
	next
}

state == "DECLARATIONS" && $0 == "%%" {
	if (length(arch_name) == 0)
		error("missing architecture name")
	state = "REGISTERS"
	next
}

state == "PROLOGUE" && $0 == "%}" {
	state = "DECLARATIONS"
	next
}

state == "REGISTERS" && $0 == "%%" {
	state = "EPILOGUE"
	next
}

# States.

state == "PROLOGUE" {
	prologue = prologue $0 "\n"
	next
}

state == "DECLARATIONS" && !/^%/ &&
match($0, /^\s*(\S+)\s*$/, group) {
	if (length(arch_name) != 0)
		error("architecture name redefined")
	arch_name = group[1]
	next
}

state == "REGISTERS" &&
match($0, /^\s*([^[:space:],]+)\s*(,\s*([[:digit:]]+|0[xX][[:xdigit:]]+))?\s*$/, group) {
	name = group[1] ""
	if (3 in group)
		regno = strtonum(group[3] "")
	registers[name] = regno++
	next
}

state == "EPILOGUE" {
	epilogue = epilogue $0 "\n"
	next
}

/\S/ {
	error("invalid input in " state)
}

ENDFILE {
	if (state != "EPILOGUE")
		error("file ended in " state)
}
