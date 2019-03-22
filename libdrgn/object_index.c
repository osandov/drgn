// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <string.h>

#include "internal.h"
#include "object_index.h"
#include "type.h"

struct drgn_error *
drgn_partial_object_from_enumerator(struct drgn_partial_object *pobj,
				    const char *name)
{
	struct drgn_type *type = pobj->qualified_type.type;
	size_t num_enumerators, i;
	const struct drgn_type_enumerator *enumerators;

	pobj->is_enumerator = true;
	pobj->little_endian = __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__;
	enumerators = drgn_type_enumerators(type);
	num_enumerators = drgn_type_num_enumerators(type);
	for (i = 0; i < num_enumerators; i++) {
		if (strcmp(enumerators[i].name, name) != 0)
			continue;

		if (drgn_enum_type_is_signed(type))
			pobj->svalue = enumerators[i].svalue;
		else
			pobj->svalue = enumerators[i].uvalue;
		return NULL;
	}
	return drgn_error_format(DRGN_ERROR_LOOKUP,
				 "could not find '%s' in 'enum %s'", name,
				 drgn_type_is_anonymous(type) ?
				 "<anonymous>" : drgn_type_tag(type));
}

struct drgn_error *
drgn_object_index_not_found_error(const char *name, const char *filename,
				  enum drgn_find_object_flags flags)
{
	const char *kind;

	switch (flags) {
	case DRGN_FIND_OBJECT_CONSTANT:
		kind = "constant ";
		break;
	case DRGN_FIND_OBJECT_FUNCTION:
		kind = "function ";
		break;
	case DRGN_FIND_OBJECT_VARIABLE:
		kind = "variable ";
		break;
	default:
		kind = "";
		break;
	}
	if (filename) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find %s'%s' in '%s'", kind,
					 name, filename);
	} else {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find %s'%s'", kind, name);
	}
}
