// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <elf.h>
#include <stdlib.h>
#include <string.h>

#include "drgn.h"
#include "symbol.h"
#include "util.h"

LIBDRGN_PUBLIC void drgn_symbol_destroy(struct drgn_symbol *sym)
{
	free(sym);
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
