// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

#include "debug_info.h"
#include "drgn.h"
#include "error.h"
#include "program.h"
#include "symbol.h"
#include "util.h"

LIBDRGN_PUBLIC void drgn_symbol_destroy(struct drgn_symbol *sym)
{
	free(sym);
}

LIBDRGN_PUBLIC void drgn_symbols_destroy(struct drgn_symbol **syms,
					 size_t count)
{
	for (size_t i = 0; i < count; i++)
		drgn_symbol_destroy(syms[i]);
	free(syms);
}

void drgn_symbol_from_elf(const char *name, uint64_t address,
			  const GElf_Sym *elf_sym, struct drgn_symbol *ret)
{
	ret->name = name;
	ret->address = address;
	ret->size = elf_sym->st_size;
	int binding = GELF_ST_BIND(elf_sym->st_info);
	if (binding <= STB_WEAK || binding == STB_GNU_UNIQUE)
		ret->binding = binding + 1;
	else
		ret->binding = DRGN_SYMBOL_BINDING_UNKNOWN;
	int type = GELF_ST_TYPE(elf_sym->st_info);
	if (type <= STT_TLS || type == STT_GNU_IFUNC)
		ret->kind = type;
	else
		ret->kind = DRGN_SYMBOL_KIND_UNKNOWN;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_symbol_source(struct drgn_symbol *sym,
	           struct drgn_program *prog,
	           unsigned long offset,
	           size_t size,
	           char *src_file_ret,
	           int *line_num_ret,
	           int *line_col_ret)
{
	if (sym->kind != DRGN_SYMBOL_KIND_FUNC)
		return drgn_error_create(DRGN_ERROR_LOOKUP,
					 "symbol is not a function");

	unsigned long sym_address = sym->address + offset;
	struct drgn_debug_info_module *dim;
	dim = drgn_debug_info_module_byaddress(prog->dbinfo, sym_address);
	if (dim == NULL)
		return drgn_error_create(DRGN_ERROR_LOOKUP,
                                         "could not locate module from function address");


	Dwfl_Line *line = dwfl_module_getsrc(dim->dwfl_module, sym_address);
	if (line == NULL)
		return drgn_error_create(DRGN_ERROR_LOOKUP,
                                         "could not obtain source code information");

	const char *src;
	int lineno, linecol;
	if ((src = dwfl_lineinfo(line, &sym_address, &lineno, &linecol,
				 NULL, NULL)) != NULL) {
		strncpy(src_file_ret, src, size);
		*line_num_ret = lineno;
		*line_col_ret = linecol;
	}

	return NULL;
}

LIBDRGN_PUBLIC const char *drgn_symbol_name(struct drgn_symbol *sym)
{
	return sym->name;
}

LIBDRGN_PUBLIC uint64_t drgn_symbol_address(struct drgn_symbol *sym)
{
	return sym->address;
}

LIBDRGN_PUBLIC uint64_t drgn_symbol_size(struct drgn_symbol *sym)
{
	return sym->size;
}


LIBDRGN_PUBLIC enum drgn_symbol_binding
drgn_symbol_binding(struct drgn_symbol *sym)
{
	return sym->binding;
}

LIBDRGN_PUBLIC enum drgn_symbol_kind drgn_symbol_kind(struct drgn_symbol *sym)
{
	return sym->kind;
}

LIBDRGN_PUBLIC bool drgn_symbol_eq(struct drgn_symbol *a, struct drgn_symbol *b)
{
	return (strcmp(a->name, b->name) == 0 && a->address == b->address &&
		a->size == b->size && a->binding == b->binding &&
		a->kind == b->kind);
}
