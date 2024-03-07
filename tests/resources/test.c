/* Copyright (c) 2024 Oracle and/or its affiliates
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * A very basic program which holds a variety of types, for testing CTF.
 * It can also test DWARF representations as well.
 *
 * To generate DWARF file for debugging:
 *     gcc -g -o test test.c
 *
 * To generate standard CTF file for debugging:
 *     gcc -gctf -Wl,--ctf-variables -o test.ctf test.c
 *
 * To generate dwarf2ctf file for debugging:
 *   1. Build "libdtrace-ctf" [1]
 *   2. Build dwarf2ctf from UEK5 tree [2]
 *   3. Run the following:
 *     gcc -g -o test test.c
 *     mkdir output
 *     ./dwarf2ctf output -e <(echo test)
 *     cp output/test.mod.ctf.new test.dwarf2ctf
 *     rm test
 *
 * Finally, run ./ctf to generate the core dump.
 */
#include <stdlib.h>

typedef unsigned long __u64;
typedef __u64 u64;
u64 var_u64;

typedef unsigned int __u32;
typedef __u32 u32;
u32 var_u32;

typedef unsigned short __u16;
typedef __u16 u16;
u16 var_u16;

typedef unsigned char __u8;
typedef __u8 u8;
u8 var_u8;

typedef unsigned long ulong_t;
ulong_t var_ulong_t;

struct basic_struct {
	int member_int;
	char *member_ptr;
	void *member_vptr;
	char name[16];
};
struct basic_struct var_basic_struct;

struct simple_flex_array {
	int size;
	char data[0];
};
struct simple_flex_array var_struct_simple_flex_array;

struct blank_flex_array {
	int size;
	char data[];
};
struct blank_flex_array var_struct_blank_flex_array;

struct multidim_flex_array {
	int size;
	char data[0][16];
};
struct multidim_flex_array var_struct_multidim_flex_array;

struct bitfield {
	unsigned long sixteen:16, eight:8, four: 4, one: 1, rem: 35;
	u64 sixteen_td: 16, eight_td: 8, four_td: 4, one_td: 1, rem_td: 35;
	int not_a_bitfield;
};
struct bitfield var_bitfield;

enum constants {
	CONST_ONE = 1,
	CONST_TWO,
	CONST_THREE
};
enum constants var_constants;

struct enum_bitfield {
	enum constants val: 16;
	unsigned short other: 16;
};
struct enum_bitfield var_enum_bitfield;

int multidim[3][4][5];

float myfloat;
double mydouble;

void function_voidarg(void) {
}

void (*fptr_voidarg)(void) = &function_voidarg;

void function_noarg() {
}

void (*fptr_noarg)() = &function_noarg;

int function_onearg(int foo) {
	return foo;
}

int (*fptr_onearg)(int foo) = &function_onearg;

int function_varargs(char *format, ...) {
	return 0;
}

int (*fptr_varargs)(char *format, ...) = &function_varargs;

int function_args(int foo, struct basic_struct *ptr)
{
	return 0;
}

int (*fptr_args)(int foo, struct basic_struct *ptr) = &function_args;

int main(int argc, char **argv)
{
	function_voidarg();
	function_noarg();
	function_onearg(1);
	function_varargs("foo", 2);
	function_args(1, &var_basic_struct);
	abort();
}
