// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <dwarf.h>
#include <elfutils/libdw.h>
#include <inttypes.h>

#include "internal.h"
#include "dwarf_index.h"
#include "dwarf_info_cache.h"
#include "symbol_index.h"
#include "type_index.h"

static struct drgn_error *
drgn_symbol_from_dwarf_enumerator(struct drgn_dwarf_symbol_index *dsindex,
				  Dwarf_Die *die, const char *name,
				  struct drgn_symbol *ret)
{
	struct drgn_error *err;

	assert(dwarf_tag(die) == DW_TAG_enumeration_type);
	err = drgn_type_from_dwarf(dsindex->dicache, die, &ret->qualified_type);
	if (err)
		return err;
	return drgn_symbol_from_enumerator(ret, name);
}

static struct drgn_error *
drgn_symbol_from_dwarf_subprogram(struct drgn_dwarf_symbol_index *dsindex,
				  Dwarf_Die *die, const char *name,
				  struct drgn_symbol *ret)
{
	struct drgn_error *err;
	Dwarf_Addr low_pc;

	err = drgn_type_from_dwarf(dsindex->dicache, die, &ret->qualified_type);
	if (err)
		return err;

	if (dwarf_lowpc(die, &low_pc) == -1) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find address of '%s'",
					 name);
	}
	ret->is_enumerator = false;
	ret->address = low_pc;
	ret->little_endian = dwarf_die_is_little_endian(die);
	if (dsindex->dicache->relocation_hook) {
		err = dsindex->dicache->relocation_hook(dsindex->dicache->prog,
							name, die, ret);
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *
drgn_symbol_from_dwarf_variable(struct drgn_dwarf_symbol_index *dsindex,
				Dwarf_Die *die, const char *name,
				struct drgn_symbol *ret)
{
	struct drgn_error *err;
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	Dwarf_Op *loc;
	size_t nloc;

	err = drgn_type_from_dwarf_child(dsindex->dicache, die,
					 "DW_TAG_variable", true,
					 &ret->qualified_type);
	if (err)
		return err;

	if (!(attr = dwarf_attr_integrate(die, DW_AT_location, &attr_mem))) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find address of '%s'",
					 name);
	}
	if (dwarf_getlocation(attr, &loc, &nloc))
		return drgn_error_libdw();

	if (nloc != 1 || loc[0].atom != DW_OP_addr) {
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_AT_location has unimplemented operation");
	}
	ret->is_enumerator = false;
	ret->address = loc[0].number;
	ret->little_endian = dwarf_die_is_little_endian(die);
	if (dsindex->dicache->relocation_hook) {
		err = dsindex->dicache->relocation_hook(dsindex->dicache->prog,
							name, die, ret);
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *
drgn_dwarf_symbol_index_find(struct drgn_symbol_index *sindex, const char *name,
			     const char *filename,
			     enum drgn_find_object_flags flags,
			     struct drgn_symbol *ret)
{
	struct drgn_error *err;
	struct drgn_dwarf_symbol_index *dsindex;
	uint64_t tags[3];
	size_t num_tags;
	struct drgn_dwarf_index_iterator it;
	Dwarf_Die die;

	num_tags = 0;
	if (flags & DRGN_FIND_OBJECT_CONSTANT)
		tags[num_tags++] = DW_TAG_enumerator;
	if (flags & DRGN_FIND_OBJECT_FUNCTION)
		tags[num_tags++] = DW_TAG_subprogram;
	if (flags & DRGN_FIND_OBJECT_VARIABLE)
		tags[num_tags++] = DW_TAG_variable;

	dsindex = container_of(sindex, struct drgn_dwarf_symbol_index, sindex);
	drgn_dwarf_index_iterator_init(&it, dsindex->dicache->dindex, name,
				       strlen(name), tags, num_tags);
	while (!(err = drgn_dwarf_index_iterator_next(&it, &die))) {
		if (!die_matches_filename(&die, filename))
			continue;
		switch (dwarf_tag(&die)) {
		case DW_TAG_enumeration_type:
			return drgn_symbol_from_dwarf_enumerator(dsindex, &die,
								 name, ret);
		case DW_TAG_subprogram:
			return drgn_symbol_from_dwarf_subprogram(dsindex, &die,
								 name, ret);
		case DW_TAG_variable:
			return drgn_symbol_from_dwarf_variable(dsindex, &die,
							       name, ret);
		default:
			DRGN_UNREACHABLE();
		}
	}
	if (err && err->code != DRGN_ERROR_STOP)
		return err;
	return drgn_symbol_index_not_found_error(name, filename, flags);
}

static void
drgn_dwarf_symbol_index_destroy(struct drgn_symbol_index *sindex)
{
	struct drgn_dwarf_symbol_index *dsindex;

	dsindex = container_of(sindex, struct drgn_dwarf_symbol_index, sindex);
	free(dsindex);
}

static const struct drgn_symbol_index_ops drgn_dwarf_symbol_index_ops = {
	.destroy = drgn_dwarf_symbol_index_destroy,
	.find = drgn_dwarf_symbol_index_find,
};

struct drgn_error *
drgn_dwarf_symbol_index_create(struct drgn_dwarf_info_cache *dicache,
			       struct drgn_dwarf_symbol_index **ret)
{
	struct drgn_dwarf_symbol_index *dsindex;

	dsindex = malloc(sizeof(*dsindex));
	if (!dsindex)
		return &drgn_enomem;
	dsindex->sindex.ops = &drgn_dwarf_symbol_index_ops;
	dsindex->dicache = dicache;

	*ret = dsindex;
	return NULL;
}
