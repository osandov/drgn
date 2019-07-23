// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <string.h>

#include "internal.h"
#include "symbol_index.h"
#include "type.h"

void drgn_symbol_index_init(struct drgn_symbol_index *sindex)
{
	sindex->finders = NULL;
}

void drgn_symbol_index_deinit(struct drgn_symbol_index *sindex)
{
	struct drgn_symbol_finder *finder;

	finder = sindex->finders;
	while (finder) {
		struct drgn_symbol_finder *next = finder->next;

		free(finder);
		finder = next;
	}
}

struct drgn_error *
drgn_symbol_index_add_finder(struct drgn_symbol_index *sindex,
			     drgn_symbol_find_fn fn, void *arg)
{
	struct drgn_symbol_finder *finder;

	finder = malloc(sizeof(*finder));
	if (!finder)
		return &drgn_enomem;
	finder->fn = fn;
	finder->arg = arg;
	finder->next = sindex->finders;
	sindex->finders = finder;
	return NULL;
}

static struct drgn_error *drgn_symbol_from_enumerator(struct drgn_symbol *sym,
						      const char *name)
{
	const struct drgn_type_enumerator *enumerators;
	size_t num_enumerators, i;

	if (drgn_type_kind(sym->type) != DRGN_TYPE_ENUM) {
		return drgn_type_error("'%s' is not an enumerated type",
				       sym->type);
	}
	enumerators = drgn_type_enumerators(sym->type);
	num_enumerators = drgn_type_num_enumerators(sym->type);
	for (i = 0; i < num_enumerators; i++) {
		if (strcmp(enumerators[i].name, name) != 0)
			continue;

		if (drgn_enum_type_is_signed(sym->type))
			sym->svalue = enumerators[i].svalue;
		else
			sym->uvalue = enumerators[i].uvalue;
		sym->kind = DRGN_SYMBOL_CONSTANT;
		return NULL;
	}
	return drgn_error_format(DRGN_ERROR_LOOKUP,
				 "could not find '%s' in 'enum %s'", name,
				 drgn_type_is_anonymous(sym->type) ?
				 "<anonymous>" : drgn_type_tag(sym->type));
}

struct drgn_error *drgn_symbol_index_find(struct drgn_symbol_index *sindex,
					  const char *name,
					  const char *filename,
					  enum drgn_find_object_flags flags,
					  struct drgn_symbol *ret)
{
	struct drgn_error *err;
	size_t name_len;
	struct drgn_symbol_finder *finder;
	const char *kind_str;

	if ((flags & ~DRGN_FIND_OBJECT_ANY) || !flags) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid find object flags");
	}

	name_len = strlen(name);
	finder = sindex->finders;
	while (finder) {
		err = finder->fn(name, name_len, filename, flags, finder->arg,
				 ret);
		if (!err) {
			if (ret->kind == DRGN_SYMBOL_ENUMERATOR ||
			    ret->kind == DRGN_SYMBOL_CONSTANT) {
			    if (!(flags & DRGN_FIND_OBJECT_CONSTANT))
				    goto wrong_kind;
			} else if (!(flags &
				     (DRGN_FIND_OBJECT_FUNCTION | DRGN_FIND_OBJECT_VARIABLE))) {
				    goto wrong_kind;
			}
			if (ret->kind == DRGN_SYMBOL_ENUMERATOR) {
				err = drgn_symbol_from_enumerator(ret, name);
				if (err)
					return err;
			}
			if (ret->kind == DRGN_SYMBOL_CONSTANT) {
				ret->little_endian = (__BYTE_ORDER__ ==
						      __ORDER_LITTLE_ENDIAN__);
			}
			return NULL;
		}
		if (err != &drgn_not_found)
			return err;
		finder = finder->next;
	}

	switch (flags) {
	case DRGN_FIND_OBJECT_CONSTANT:
		kind_str = "constant ";
		break;
	case DRGN_FIND_OBJECT_FUNCTION:
		kind_str = "function ";
		break;
	case DRGN_FIND_OBJECT_VARIABLE:
		kind_str = "variable ";
		break;
	default:
		kind_str = "";
		break;
	}
	if (filename) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find %s'%s' in '%s'",
					 kind_str, name, filename);
	} else {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find %s'%s'", kind_str,
					 name);
	}

wrong_kind:
	return drgn_error_create(DRGN_ERROR_TYPE,
				 "symbol find callback returned wrong kind of symbol");
}
