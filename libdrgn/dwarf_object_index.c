// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <dwarf.h>
#include <elfutils/libdw.h>
#include <inttypes.h>

#include "internal.h"
#include "dwarf_index.h"
#include "object_index.h"
#include "type_index.h"

static struct drgn_error *
drgn_partial_object_from_dwarf_enumerator(struct drgn_dwarf_object_index *doindex,
					  Dwarf_Die *die, const char *name,
					  struct drgn_partial_object *ret)
{
	struct drgn_error *err;

	assert(dwarf_tag(die) == DW_TAG_enumeration_type);
	err = drgn_type_from_dwarf(doindex->dtindex, die, &ret->qualified_type);
	if (err)
		return err;
	return drgn_partial_object_from_enumerator(ret, name);
}

static struct drgn_error *
drgn_partial_object_from_dwarf_subprogram(struct drgn_dwarf_object_index *doindex,
					  Dwarf_Die *die, const char *name,
					  struct drgn_partial_object *ret)
{
	struct drgn_error *err;
	Dwarf_Addr low_pc;

	err = drgn_type_from_dwarf(doindex->dtindex, die, &ret->qualified_type);
	if (err)
		return err;

	if (dwarf_lowpc(die, &low_pc) == -1) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find address of '%s'",
					 name);
	}
	ret->is_enumerator = false;
	ret->address = low_pc;
	ret->little_endian = doindex->dtindex->tindex.little_endian;
	if (doindex->relocation_hook) {
		err = doindex->relocation_hook(doindex->prog, name, die, ret);
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *
drgn_partial_object_from_dwarf_variable(struct drgn_dwarf_object_index *doindex,
					Dwarf_Die *die, const char *name,
					struct drgn_partial_object *ret)
{
	struct drgn_error *err;
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	Dwarf_Op *loc;
	size_t nloc;

	err = drgn_type_from_dwarf_child(doindex->dtindex, die,
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
	ret->little_endian = doindex->dtindex->tindex.little_endian;
	if (doindex->relocation_hook) {
		err = doindex->relocation_hook(doindex->prog, name, die, ret);
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *
drgn_dwarf_object_index_find(struct drgn_object_index *oindex, const char *name,
			     const char *filename,
			     enum drgn_find_object_flags flags,
			     struct drgn_partial_object *ret)
{
	struct drgn_error *err;
	struct drgn_dwarf_object_index *doindex;
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

	doindex = container_of(oindex, struct drgn_dwarf_object_index, oindex);
	drgn_dwarf_index_iterator_init(&it, doindex->dtindex->dindex, name,
				       strlen(name), tags, num_tags);
	while (!(err = drgn_dwarf_index_iterator_next(&it, &die))) {
		if (!die_matches_filename(&die, filename))
			continue;
		switch (dwarf_tag(&die)) {
		case DW_TAG_enumeration_type:
			return drgn_partial_object_from_dwarf_enumerator(doindex,
									 &die,
									 name,
									 ret);
		case DW_TAG_subprogram:
			return drgn_partial_object_from_dwarf_subprogram(doindex,
									 &die,
									 name,
									 ret);
		case DW_TAG_variable:
			return drgn_partial_object_from_dwarf_variable(doindex,
								       &die,
								       name,
								       ret);
		default:
			DRGN_UNREACHABLE();
		}
	}
	if (err && err->code != DRGN_ERROR_STOP)
		return err;
	return drgn_object_index_not_found_error(name, filename, flags);
}

static void
drgn_dwarf_object_index_destroy(struct drgn_object_index *oindex)
{
	struct drgn_dwarf_object_index *doindex;

	doindex = container_of(oindex, struct drgn_dwarf_object_index, oindex);
	free(doindex);
}

static const struct drgn_object_index_ops drgn_dwarf_object_index_ops = {
	.destroy = drgn_dwarf_object_index_destroy,
	.find = drgn_dwarf_object_index_find,
};

struct drgn_error *
drgn_dwarf_object_index_create(struct drgn_dwarf_type_index *dtindex,
			       struct drgn_dwarf_object_index **ret)
{
	struct drgn_dwarf_object_index *doindex;

	doindex = malloc(sizeof(*doindex));
	if (!doindex)
		return &drgn_enomem;
	doindex->oindex.ops = &drgn_dwarf_object_index_ops;
	doindex->dtindex = dtindex;
	doindex->prog = NULL;
	doindex->relocation_hook = NULL;

	*ret = doindex;
	return NULL;
}
