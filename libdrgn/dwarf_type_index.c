// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <elfutils/libdw.h>
#include <dwarf.h>
#include <libelf.h>
#include <string.h>

#include "internal.h"
#include "dwarf_index.h"
#include "hash_table.h"
#include "type_index.h"

#if !_ELFUTILS_PREREQ(0, 162)
#define DW_TAG_atomic_type 0x47
#endif
#if !_ELFUTILS_PREREQ(0, 171)
#define DW_FORM_implicit_const 0x21
#endif

DEFINE_HASH_MAP_FUNCTIONS(dwarf_type_map, const void *, struct drgn_dwarf_type,
			  hash_pair_ptr_type, hash_table_scalar_eq)

struct drgn_type_from_dwarf_thunk {
	struct drgn_type_thunk thunk;
	struct drgn_dwarf_type_index *dtindex;
	Dwarf_Die die;
	bool can_be_incomplete_array;
};

static bool drgn_type_realloc(struct drgn_type **type, size_t capacity,
			      size_t element_size)
{
	struct drgn_type *tmp;
	size_t size;

	if (__builtin_mul_overflow(capacity, element_size, &size) ||
	    __builtin_add_overflow(size, sizeof(**type), &size))
		return false;

	tmp = realloc(*type, size);
	if (!tmp)
		return false;

	*type = tmp;
	return true;
}

static void drgn_dwarf_type_free(struct drgn_dwarf_type *dwarf_type)
{
	if (dwarf_type->should_free) {
		struct drgn_type *type = dwarf_type->type;

		if (drgn_type_has_members(type)) {
			size_t num_members, i;

			num_members = drgn_type_num_members(type);
			for (i = 0; i < num_members; i++)
				drgn_type_member_deinit(type, i);
		}
		if (drgn_type_has_parameters(type)) {
			size_t num_parameters, i;

			num_parameters = drgn_type_num_parameters(type);
			for (i = 0; i < num_parameters; i++)
				drgn_type_parameter_deinit(type, i);
		}
		free(type);
	}
}

static int dwarf_type(Dwarf_Die *die, Dwarf_Die *ret)
{
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;

	if (!(attr = dwarf_attr_integrate(die, DW_AT_type, &attr_mem)))
		return 1;

	return dwarf_formref_die(attr, ret) ? 0 : -1;
}

static int dwarf_flag(Dwarf_Die *die, unsigned int name, bool *ret)
{
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;

	if (!(attr = dwarf_attr_integrate(die, name, &attr_mem))) {
		*ret = false;
		return 0;
	}
	return dwarf_formflag(attr, ret);
}

static struct drgn_error *
drgn_type_from_dwarf_thunk_evaluate_fn(struct drgn_type_thunk *thunk,
				       struct drgn_qualified_type *ret)
{
	struct drgn_type_from_dwarf_thunk *t;

	t = container_of(thunk, struct drgn_type_from_dwarf_thunk, thunk);
	return drgn_type_from_dwarf_internal(t->dtindex, &t->die,
					     t->can_be_incomplete_array, NULL,
					     ret);
}

static void drgn_type_from_dwarf_thunk_free_fn(struct drgn_type_thunk *thunk)
{
	free(container_of(thunk, struct drgn_type_from_dwarf_thunk, thunk));
}

static struct drgn_error *
drgn_lazy_type_from_dwarf(struct drgn_dwarf_type_index *dtindex,
			  Dwarf_Die *parent_die, bool can_be_void,
			  bool can_be_incomplete_array, const char *tag_name,
			  struct drgn_lazy_type *ret)
{
	struct drgn_type_from_dwarf_thunk *thunk;
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	Dwarf_Die type_die;

	if (!(attr = dwarf_attr_integrate(parent_die, DW_AT_type, &attr_mem))) {
		if (can_be_void) {
			drgn_lazy_type_init_evaluated(ret, &drgn_void_type, 0);
			return NULL;
		} else {
			return drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
						 "%s is missing DW_AT_type",
						 tag_name);
		}
	}

	if (!dwarf_formref_die(attr, &type_die)) {
		return drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
					 "%s has invalid DW_AT_type", tag_name);
	}

	thunk = malloc(sizeof(*thunk));
	if (!thunk)
		return &drgn_enomem;

	thunk->thunk.evaluate_fn = drgn_type_from_dwarf_thunk_evaluate_fn;
	thunk->thunk.free_fn = drgn_type_from_dwarf_thunk_free_fn;
	thunk->dtindex = dtindex;
	thunk->die = type_die;
	thunk->can_be_incomplete_array = can_be_incomplete_array;
	drgn_lazy_type_init_thunk(ret, &thunk->thunk);
	return NULL;
}

struct drgn_error *
drgn_type_from_dwarf_child_internal(struct drgn_dwarf_type_index *dtindex,
				    Dwarf_Die *parent_die, const char *tag_name,
				    bool can_be_void,
				    bool can_be_incomplete_array,
				    bool *is_incomplete_array_ret,
				    struct drgn_qualified_type *ret)
{
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	Dwarf_Die type_die;

	if (!(attr = dwarf_attr_integrate(parent_die, DW_AT_type, &attr_mem))) {
		if (can_be_void) {
			ret->type = &drgn_void_type;
			ret->qualifiers = 0;
			return NULL;
		} else {
			return drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
						 "%s is missing DW_AT_type",
						 tag_name);
		}
	}

	if (!dwarf_formref_die(attr, &type_die)) {
		return drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
					 "%s has invalid DW_AT_type", tag_name);
	}

	return drgn_type_from_dwarf_internal(dtindex, &type_die,
					     can_be_incomplete_array,
					     is_incomplete_array_ret, ret);
}

static struct drgn_error *
drgn_base_type_from_dwarf(struct drgn_dwarf_type_index *dtindex, Dwarf_Die *die,
			  struct drgn_type **ret)
{
	struct drgn_type *type;
	Dwarf_Attribute attr;
	Dwarf_Word encoding;
	const char *name;
	int size;

	name = dwarf_diename(die);
	if (!name) {
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_base_type has missing or invalid DW_AT_name");
	}

	if (!dwarf_attr_integrate(die, DW_AT_encoding, &attr) ||
	    dwarf_formudata(&attr, &encoding)) {
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_base_type has missing or invalid DW_AT_encoding");
	}
	size = dwarf_bytesize(die);
	if (size == -1) {
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_base_type has missing or invalid DW_AT_byte_size");
	}

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	switch (encoding) {
	case DW_ATE_boolean:
		drgn_bool_type_init(type, name, size);
		break;
	case DW_ATE_float:
		drgn_float_type_init(type, name, size);
		break;
	case DW_ATE_signed:
	case DW_ATE_signed_char:
		drgn_int_type_init(type, name, size, true);
		break;
	case DW_ATE_unsigned:
	case DW_ATE_unsigned_char:
		drgn_int_type_init(type, name, size, false);
		break;
	/*
	 * GCC also supports complex integer types, but DWARF 4 doesn't have an
	 * encoding for that. GCC as of 8.2 emits DW_ATE_lo_user, but that's
	 * ambiguous because it also emits that in other cases. For now, we
	 * don't support it.
	 */
	case DW_ATE_complex_float: {
		struct drgn_qualified_type real_type;
		struct drgn_error *err;
		Dwarf_Die child;

		if (dwarf_type(die, &child)) {
			return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
						 "DW_TAG_base_type has missing or invalid DW_AT_type");
		}
		err = drgn_type_from_dwarf(dtindex, &child, &real_type);
		if (err)
			return err;
		if (drgn_type_kind(real_type.type) != DRGN_TYPE_FLOAT &&
		    drgn_type_kind(real_type.type) != DRGN_TYPE_INT) {
			return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
						 "DW_AT_type of DW_ATE_complex_float is not a floating-point or integer type");
		}
		drgn_complex_type_init(type, name, size, real_type.type);
		break;
	}
	default:
		return drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_base_type has unknown DWARF encoding 0x%llx",
					 (unsigned long long)encoding);
	}
	*ret = type;
	return NULL;
}

/*
 * DW_TAG_structure_type, DW_TAG_union_type, and DW_TAG_enumeration_type can be
 * incomplete (i.e., have a DW_AT_declaration of true). This tries to find the
 * complete type. If it succeeds, it returns NULL. If it can't find a complete
 * type, it returns a DRGN_ERROR_STOP error. Otherwise, it returns an error.
 */
static struct drgn_error *
drgn_dwarf_type_index_find_complete(struct drgn_dwarf_type_index *dtindex,
				    uint64_t tag, const char *name,
				    struct drgn_type **ret)
{
	struct drgn_error *err;
	struct drgn_dwarf_index_iterator it;
	Dwarf_Die die;
	struct drgn_qualified_type qualified_type;

	drgn_dwarf_index_iterator_init(&it, dtindex->dindex, name, strlen(name),
				       &tag, 1);
	/*
	 * Find a matching DIE. Note that drgn_dwarf_index does not contain DIEs
	 * with DW_AT_declaration, so this will always be a complete type.
	 */
	err = drgn_dwarf_index_iterator_next(&it, &die);
	if (err)
		return err;
	/*
	 * Look for another matching DIE. If there is one, then we can't be sure
	 * which type this is, so leave it incomplete rather than guessing.
	 */
	err = drgn_dwarf_index_iterator_next(&it, &die);
	if (!err)
		return &drgn_stop;
	else if (err->code != DRGN_ERROR_STOP)
		return err;

	err = drgn_type_from_dwarf(dtindex, &die, &qualified_type);
	if (err)
		return err;
	*ret = qualified_type.type;
	return NULL;
}

static struct drgn_error *
parse_member_offset(Dwarf_Die *die, struct drgn_lazy_type *member_type,
		    uint64_t bit_field_size, bool little_endian, uint64_t *ret)
{
	struct drgn_error *err;
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;

	/*
	 * The simplest case is when we have DW_AT_data_bit_offset, which is
	 * already the offset in bits from the beginning of the containing
	 * object to the beginning of the member (which may be a bit field).
	 */
	attr = dwarf_attr_integrate(die, DW_AT_data_bit_offset, &attr_mem);
	if (attr) {
		Dwarf_Word bit_offset;

		if (dwarf_formudata(attr, &bit_offset)) {
			return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
						 "DW_TAG_member has invalid DW_AT_data_bit_offset");
		}
		*ret = bit_offset;
		return NULL;
	}

	/*
	 * Otherwise, we might have DW_AT_data_member_location, which is the
	 * offset in bytes from the beginning of the containing object.
	 */
	attr = dwarf_attr_integrate(die, DW_AT_data_member_location, &attr_mem);
	if (attr) {
		Dwarf_Word byte_offset;

		if (dwarf_formudata(attr, &byte_offset)) {
			return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
						 "DW_TAG_member has invalid DW_AT_data_member_location");
		}
		*ret = 8 * byte_offset;
	} else {
		*ret = 0;
	}

	/*
	 * In addition to DW_AT_data_member_location, a bit field might have
	 * DW_AT_bit_offset, which is the offset in bits of the most significant
	 * bit of the bit field from the most significant bit of the containing
	 * object.
	 */
	attr = dwarf_attr_integrate(die, DW_AT_bit_offset, &attr_mem);
	if (attr) {
		Dwarf_Word bit_offset;

		if (dwarf_formudata(attr, &bit_offset)) {
			return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
						 "DW_TAG_member has invalid DW_AT_bit_offset");
		}

		/*
		 * If the architecture is little-endian, then we must compute
		 * the location of the most significant bit from the size of the
		 * member, then subtract the bit offset and bit size to get the
		 * location of the beginning of the bit field.
		 *
		 * If the architecture is big-endian, then the most significant
		 * bit of the bit field is the beginning.
		 */
		if (little_endian) {
			uint64_t byte_size;

			attr = dwarf_attr_integrate(die, DW_AT_byte_size,
						    &attr_mem);
			/*
			 * If the member has an explicit byte size, we can use
			 * that. Otherwise, we have to get it from the member
			 * type.
			 */
			if (attr) {
				Dwarf_Word word;

				if (dwarf_formudata(attr, &word)) {
					return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
								 "DW_TAG_member has invalid DW_AT_byte_size");
				}
				byte_size = word;
			} else {
				struct drgn_qualified_type containing_type;

				err = drgn_lazy_type_evaluate(member_type,
							      &containing_type);
				if (err)
					return err;
				if (!drgn_type_has_size(containing_type.type)) {
					return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
								 "DW_TAG_member bit field type does not have size");
				}
				byte_size = drgn_type_size(containing_type.type);
			}
			*ret += 8 * byte_size - bit_offset - bit_field_size;
		} else {
			*ret += bit_offset;
		}
	}

	return NULL;
}

static struct drgn_error *parse_member(struct drgn_dwarf_type_index *dtindex,
				       Dwarf_Die *die, struct drgn_type *type,
				       size_t i)
{
	struct drgn_error *err;
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	struct drgn_lazy_type member_type;
	const char *name;
	uint64_t bit_offset;
	uint64_t bit_field_size;

	attr = dwarf_attr_integrate(die, DW_AT_name, &attr_mem);
	if (attr) {
		name = dwarf_formstring(attr);
		if (!name) {
			return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
						 "DW_TAG_member has invalid DW_AT_name");
		}
	} else {
		name = NULL;
	}

	attr = dwarf_attr_integrate(die, DW_AT_bit_size, &attr_mem);
	if (attr) {
		Dwarf_Word bit_size;

		if (dwarf_formudata(attr, &bit_size)) {
			return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
						 "DW_TAG_member has invalid DW_AT_bit_size");
		}
		bit_field_size = bit_size;
	} else {
		bit_field_size = 0;
	}

	err = drgn_lazy_type_from_dwarf(dtindex, die, false, false,
					"DW_TAG_member", &member_type);
	if (err)
		return err;

	err = parse_member_offset(die, &member_type, bit_field_size,
				  dtindex->tindex.little_endian, &bit_offset);
	if (err) {
		drgn_lazy_type_deinit(&member_type);
		return err;
	}

	drgn_type_member_init(type, i, member_type, name, bit_offset,
			      bit_field_size);
	return NULL;
}

static struct drgn_error *
drgn_compound_type_from_dwarf(struct drgn_dwarf_type_index *dtindex,
			      Dwarf_Die *die, bool is_struct,
			      struct drgn_type **ret, bool *should_free)
{
	struct drgn_error *err;
	struct drgn_type *type;
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	const char *tag;
	bool declaration;
	Dwarf_Die child;
	int size;
	size_t num_members = 0, capacity = 0;
	int r;

	attr = dwarf_attr_integrate(die, DW_AT_name, &attr_mem);
	if (attr) {
		tag = dwarf_formstring(attr);
		if (!tag)
			return drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
						 "DW_TAG_%s_type has invalid DW_AT_name",
						 is_struct ? "structure" : "union");
	} else {
		tag = NULL;
	}

	if (dwarf_flag(die, DW_AT_declaration, &declaration)) {
		return drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_%s_type has invalid DW_AT_declaration",
					 is_struct ? "structure" : "union");
	}
	if (declaration && tag) {
		err = drgn_dwarf_type_index_find_complete(dtindex,
							  is_struct ?
							  DW_TAG_structure_type :
							  DW_TAG_union_type,
							  tag, ret);
		if (!err) {
			*should_free = false;
			return NULL;
		} else if (err->code != DRGN_ERROR_STOP) {
			return err;
		}
	}

	*should_free = true;
	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;

	if (declaration) {
		if (is_struct)
			drgn_struct_type_init_incomplete(type, tag);
		else
			drgn_union_type_init_incomplete(type, tag);
		*ret = type;
		return NULL;
	}

	size = dwarf_bytesize(die);
	if (size == -1) {
		err = drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
					"DW_TAG_%s_type has missing or invalid DW_AT_byte_size",
					is_struct ? "structure" : "union");
		goto err;
	}

	r = dwarf_child(die, &child);
	while (r == 0) {
		if (dwarf_tag(&child) == DW_TAG_member) {
			if (num_members >= capacity) {
				if (capacity == 0)
					capacity = 1;
				else
					capacity *= 2;
				if (!drgn_type_realloc(&type, capacity,
						       sizeof(struct drgn_type_member))) {
					err = &drgn_enomem;
					goto err;
				}
			}

			err = parse_member(dtindex, &child, type, num_members);
			if (err)
				goto err;
			num_members++;
		}
		r = dwarf_siblingof(&child, &child);
	}
	if (r == -1) {
		err = drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					"libdw could not parse DIE children");
		goto err;
	}
	if (capacity != num_members) {
		/* We don't care if this fails. */
		drgn_type_realloc(&type, num_members,
				  sizeof(struct drgn_type_member));
	}

	if (is_struct) {
		drgn_struct_type_init(type, tag, size, num_members);
		/*
		 * Flexible array members are only allowed as the last member of
		 * a structure with more than one named member. We defaulted
		 * can_be_incomplete_array to false in parse_member(), so fix it
		 * up.
		 */
		if (num_members > 1) {
			struct drgn_type_member *member;

			member = &drgn_type_members(type)[num_members - 1];
			/*
			 * The type may have already been evaluated if it's a
			 * bit field. Arrays can't be bit fields, so it's okay
			 * if we missed it.
			 */
			if (!drgn_lazy_type_is_evaluated(&member->type)) {
				struct drgn_type_from_dwarf_thunk *thunk;

				thunk = container_of(member->type.thunk,
						     struct drgn_type_from_dwarf_thunk,
						     thunk);
				thunk->can_be_incomplete_array = true;
			}
		}
	} else {
		drgn_union_type_init(type, tag, size, num_members);
	}
	*ret = type;
	return NULL;

err:
	while (num_members)
		drgn_type_member_deinit(type, --num_members);
	free(type);
	return err;
}

static struct drgn_error *parse_enumerator(Dwarf_Die *die,
					   struct drgn_type *type, size_t i,
					   bool *is_signed)
{
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	const char *name;
	int r;

	name = dwarf_diename(die);
	if (!name) {
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_enumerator has missing or invalid DW_AT_name");
	}

	attr = dwarf_attr_integrate(die, DW_AT_const_value, &attr_mem);
	if (!attr) {
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_enumerator is missing DW_AT_const_value");
	}

	if (attr->form == DW_FORM_sdata ||
	    attr->form == DW_FORM_implicit_const) {
		Dwarf_Sword svalue;

		r = dwarf_formsdata(attr, &svalue);
		if (r == 0) {
			drgn_type_enumerator_init_signed(type, i, name, svalue);
			if (svalue < 0)
				*is_signed = true;
		}
	} else {
		Dwarf_Word uvalue;

		r = dwarf_formudata(attr, &uvalue);
		if (r == 0) {
			drgn_type_enumerator_init_unsigned(type, i, name,
							   uvalue);
		}
	}
	if (r) {
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_enumerator has invalid DW_AT_const_value");
	}
	return NULL;
}

static struct drgn_type fallback_enum_compatible_types[2][4];

__attribute__((constructor(200)))
static void fallback_enum_compatible_types_init(void)
{
	unsigned int is_signed, shift;

	for (is_signed = 0; is_signed < 2; is_signed++) {
		for (shift = 0;
		     shift < ARRAY_SIZE(fallback_enum_compatible_types[0]);
		     shift++) {
			struct drgn_type *type;

			type = &fallback_enum_compatible_types[is_signed][shift];
			drgn_int_type_init(type, "<unknown>", 1 << shift,
					   is_signed);
		}
	}
}

/*
 * GCC before 5.1 did not include DW_AT_type for DW_TAG_enumeration_type DIEs,
 * so we have to fabricate the compatible type.
 *
 * GCC before 7.1 didn't include DW_AT_encoding for DW_TAG_enumeration_type
 * DIEs, either, so we also have to guess at the sign.
 */
static struct drgn_error *
enum_compatible_type_fallback(struct drgn_dwarf_type_index *dtindex,
			      Dwarf_Die *die, bool is_signed,
			      struct drgn_type **ret)
{
	int size;

	size = dwarf_bytesize(die);
	switch (size) {
	case 1:
		*ret = &fallback_enum_compatible_types[is_signed][0];
		return NULL;
	case 2:
		*ret = &fallback_enum_compatible_types[is_signed][1];
		return NULL;
	case 4:
		*ret = &fallback_enum_compatible_types[is_signed][2];
		return NULL;
	case 8:
		*ret = &fallback_enum_compatible_types[is_signed][3];
		return NULL;
	case -1:
		*ret = NULL;
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_enumeration_type has missing or invalid DW_AT_byte_size");
	default:
		*ret = NULL;
		return drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_enumeration_type has unsupported DW_AT_byte_size %d",
					 size);
	}
}

static struct drgn_error *
drgn_enum_type_from_dwarf(struct drgn_dwarf_type_index *dtindex, Dwarf_Die *die,
			  struct drgn_type **ret, bool *should_free)
{
	struct drgn_error *err;
	struct drgn_type *type;
	struct drgn_type *compatible_type;
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	const char *tag;
	bool declaration;
	Dwarf_Die child;
	size_t num_enumerators = 0, capacity = 0;
	bool is_signed = false;
	int r;

	attr = dwarf_attr_integrate(die, DW_AT_name, &attr_mem);
	if (attr) {
		tag = dwarf_formstring(attr);
		if (!tag)
			return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
						 "DW_TAG_enumeration_type has invalid DW_AT_name");
	} else {
		tag = NULL;
	}

	if (dwarf_flag(die, DW_AT_declaration, &declaration)) {
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_enumeration_type has invalid DW_AT_declaration");
	}
	if (declaration && tag) {
		err = drgn_dwarf_type_index_find_complete(dtindex,
							  DW_TAG_enumeration_type,
							  tag, ret);
		if (!err) {
			*should_free = false;
			return NULL;
		} else if (err->code != DRGN_ERROR_STOP) {
			return err;
		}
	}

	*should_free = true;
	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;

	if (declaration) {
		drgn_enum_type_init_incomplete(type, tag);
		*ret = type;
		return NULL;
	}

	r = dwarf_child(die, &child);
	while (r == 0) {
		int tag;

		tag = dwarf_tag(&child);
		if (tag == DW_TAG_enumerator) {
			if (num_enumerators >= capacity) {
				if (capacity == 0)
					capacity = 1;
				else
					capacity *= 2;
				if (!drgn_type_realloc(&type, capacity,
						       sizeof(struct drgn_type_enumerator))) {
					err = &drgn_enomem;
					goto err;
				}
			}

			err = parse_enumerator(&child, type, num_enumerators,
					       &is_signed);
			if (err)
				goto err;
			num_enumerators++;
		}
		r = dwarf_siblingof(&child, &child);
	}
	if (r == -1) {
		err = drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					"libdw could not parse DIE children");
		goto err;
	}
	if (capacity != num_enumerators) {
		/* We don't care if this fails. */
		drgn_type_realloc(&type, num_enumerators,
				  sizeof(struct drgn_type_enumerator));
	}

	r = dwarf_type(die, &child);
	if (r == -1) {
		err = drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					"DW_TAG_enumeration_type has invalid DW_AT_type");
		goto err;
	} else if (r) {
		err = enum_compatible_type_fallback(dtindex, die, is_signed,
						    &compatible_type);
		if (err)
			goto err;
	} else {
		struct drgn_qualified_type qualified_compatible_type;

		err = drgn_type_from_dwarf(dtindex, &child,
					   &qualified_compatible_type);
		if (err)
			goto err;
		compatible_type = qualified_compatible_type.type;
		if (drgn_type_kind(compatible_type) != DRGN_TYPE_INT) {
			err = drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
						"DW_AT_type of DW_TAG_enumeration_type is not an integer type");
			goto err;
		}
	}

	drgn_enum_type_init(type, tag, compatible_type, num_enumerators);
	*ret = type;
	return NULL;

err:
	free(type);
	return err;
}

static struct drgn_error *
drgn_typedef_type_from_dwarf(struct drgn_dwarf_type_index *dtindex,
			     Dwarf_Die *die, bool can_be_incomplete_array,
			     bool *is_incomplete_array_ret,
			     struct drgn_type **ret)
{
	struct drgn_error *err;
	struct drgn_type *type;
	struct drgn_qualified_type aliased_type;
	const char *name;

	name = dwarf_diename(die);
	if (!name) {
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_typedef has missing or invalid DW_AT_name");
	}

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;

	err = drgn_type_from_dwarf_child_internal(dtindex, die,
						  "DW_TAG_typedef", true,
						  can_be_incomplete_array,
						  is_incomplete_array_ret,
						  &aliased_type);
	if (err) {
		free(type);
		return err;
	}

	drgn_typedef_type_init(type, name, aliased_type);
	*ret = type;
	return NULL;
}

static struct drgn_error *
drgn_pointer_type_from_dwarf(struct drgn_dwarf_type_index *dtindex,
			     Dwarf_Die *die, struct drgn_type **ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type referenced_type;
	int size;

	size = dwarf_bytesize(die);
	if (size == -1) {
		return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_pointer_type has missing or invalid DW_AT_byte_size");
	}

	err = drgn_type_from_dwarf_child(dtindex, die, "DW_TAG_pointer_type",
					 true, &referenced_type);
	if (err)
		return err;

	return drgn_type_index_pointer_type(&dtindex->tindex, size,
					    referenced_type, ret);
}

struct array_dimension {
	uint64_t length;
	bool is_complete;
};

static struct drgn_error *subrange_length(Dwarf_Die *die,
					  struct array_dimension *dimension)
{
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	Dwarf_Word word;

	if (!(attr = dwarf_attr_integrate(die, DW_AT_upper_bound, &attr_mem)) &&
	    !(attr = dwarf_attr_integrate(die, DW_AT_count, &attr_mem))) {
		dimension->is_complete = false;
		return NULL;
	}

	if (dwarf_formudata(attr, &word)) {
		return drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
					 "DW_TAG_subrange_type has invalid %s",
					 attr->code == DW_AT_upper_bound ?
					 "DW_AT_upper_bound" :
					 "DW_AT_count");
	}

	dimension->is_complete = true;
	if (attr->code == DW_AT_upper_bound) {
		if (word == UINT64_MAX) {
			return drgn_error_create(DRGN_ERROR_OVERFLOW,
						 "DW_AT_count is too large");
		}
		dimension->length = (uint64_t)word + 1;
	} else {
		if (word > UINT64_MAX) {
			return drgn_error_create(DRGN_ERROR_OVERFLOW,
						 "DW_AT_upper_bound is too large");
		}
		dimension->length = word;
	}
	return NULL;
}

static struct drgn_error *
drgn_array_type_from_dwarf(struct drgn_dwarf_type_index *dtindex,
			   Dwarf_Die *die, bool can_be_incomplete_array,
			   bool *is_incomplete_array_ret,
			   struct drgn_type **ret)
{
	struct drgn_error *err;
	struct drgn_type *type;
	struct drgn_qualified_type element_type;
	Dwarf_Die child;
	struct array_dimension *dimensions = NULL;
	size_t num_dimensions = 0, capacity = 0;
	int r;

	r = dwarf_child(die, &child);
	while (r == 0) {
		if (dwarf_tag(&child) == DW_TAG_subrange_type) {
			if (num_dimensions >= capacity) {
				if (capacity == 0)
					capacity = 1;
				else
					capacity *= 2;
				if (!resize_array(&dimensions, capacity)) {
					err = &drgn_enomem;
					goto out;
				}
			}
			err = subrange_length(&child,
					      &dimensions[num_dimensions++]);
			if (err)
				goto out;
		}
		r = dwarf_siblingof(&child, &child);
	}
	if (r == -1) {
		err = drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					"libdw could not parse DIE children");
		goto out;
	}
	if (num_dimensions == 0) {
		if (!resize_array(&dimensions, 1)) {
			err = &drgn_enomem;
			goto out;
		}
		dimensions[num_dimensions++].is_complete = false;
	}

	err = drgn_type_from_dwarf_child_internal(dtindex, die,
						  "DW_TAG_array_type", false,
						  false, NULL, &element_type);
	if (err)
		goto out;

	*is_incomplete_array_ret = !dimensions[0].is_complete;
	while (num_dimensions > 0) {
		struct array_dimension *dimension;

		dimension = &dimensions[--num_dimensions];
		if (dimension->is_complete) {
			err = drgn_type_index_array_type(&dtindex->tindex,
							 dimension->length,
							 element_type, &type);
		} else if (num_dimensions || !can_be_incomplete_array) {
			err = drgn_type_index_array_type(&dtindex->tindex, 0,
							 element_type, &type);
		} else {
			err = drgn_type_index_incomplete_array_type(&dtindex->tindex,
								    element_type,
								    &type);
		}
		if (err)
			goto out;

		element_type.type = type;
		element_type.qualifiers = 0;
	}

	*ret = type;
	err = NULL;
out:
	free(dimensions);
	return err;
}

static struct drgn_error *
parse_formal_parameter(struct drgn_dwarf_type_index *dtindex, Dwarf_Die *die,
		       struct drgn_type *type, size_t i)
{
	struct drgn_error *err;
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	const char *name;
	struct drgn_lazy_type parameter_type;

	attr = dwarf_attr_integrate(die, DW_AT_name, &attr_mem);
	if (attr) {
		name = dwarf_formstring(attr);
		if (!name) {
			return drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
						 "DW_TAG_formal_parameter has invalid DW_AT_name");
		}
	} else {
		name = NULL;
	}

	err = drgn_lazy_type_from_dwarf(dtindex, die, false, true,
					"DW_TAG_formal_parameter",
					&parameter_type);
	if (err)
		return err;

	drgn_type_parameter_init(type, i, parameter_type, name);
	return NULL;
}

static struct drgn_error *
drgn_function_type_from_dwarf(struct drgn_dwarf_type_index *dtindex,
			      Dwarf_Die *die, struct drgn_type **ret)
{
	struct drgn_error *err;
	const char *tag_name;
	struct drgn_type *type;
	struct drgn_qualified_type return_type;
	Dwarf_Die child;
	size_t num_parameters = 0, capacity = 0;
	bool is_variadic = false;
	int r;

	if (dwarf_tag(die) == DW_TAG_subroutine_type)
		tag_name = "DW_TAG_subroutine_type";
	else
		tag_name = "DW_TAG_subprogram";

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;

	r = dwarf_child(die, &child);
	while (r == 0) {
		int tag;

		tag = dwarf_tag(&child);
		if (tag == DW_TAG_formal_parameter) {
			if (is_variadic) {
				err = drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
							"%s has DW_TAG_formal_parameter child after DW_TAG_unspecified_parameters child",
							tag_name);
				goto err;
			}

			if (num_parameters >= capacity) {
				if (capacity == 0)
					capacity = 1;
				else
					capacity *= 2;
				if (!drgn_type_realloc(&type, capacity,
						       sizeof(struct drgn_type_parameter))) {
					err = &drgn_enomem;
					goto err;
				}
			}

			err = parse_formal_parameter(dtindex, &child, type,
						     num_parameters);
			if (err)
				goto err;
			num_parameters++;
		} else if (tag == DW_TAG_unspecified_parameters) {
			if (is_variadic) {
				err = drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
							"%s has multiple DW_TAG_unspecified_parameters children",
							tag_name);
				goto err;
			}
			is_variadic = true;
		}
		r = dwarf_siblingof(&child, &child);
	}
	if (r == -1) {
		err = drgn_error_create(DRGN_ERROR_DWARF_FORMAT,
					"libdw could not parse DIE children");
		goto err;
	}
	if (capacity != num_parameters) {
		/* We don't care if this fails. */
		drgn_type_realloc(&type, num_parameters,
				  sizeof(struct drgn_type_parameter));
	}

	err = drgn_type_from_dwarf_child(dtindex, die, tag_name, true,
					 &return_type);
	if (err)
		goto err;

	drgn_function_type_init(type, return_type, num_parameters, is_variadic);
	*ret = type;
	return NULL;

err:
	while (num_parameters)
		drgn_type_parameter_deinit(type, --num_parameters);
	free(type);
	return err;
}

struct drgn_error *
drgn_type_from_dwarf_internal(struct drgn_dwarf_type_index *dtindex,
			      Dwarf_Die *die, bool can_be_incomplete_array,
			      bool *is_incomplete_array_ret,
			      struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	struct hash_pair hp;
	const void *key = die->addr;
	struct drgn_dwarf_type *value, dwarf_type;
	struct dwarf_type_map *map;

	if (dtindex->depth >= 1000) {
		return drgn_error_create(DRGN_ERROR_RECURSION,
					 "maximum DWARF type parsing depth exceeded");
	}

	hp = dwarf_type_map_hash(&key);
	value = dwarf_type_map_search_hashed(&dtindex->map, &key, hp);
	if (value) {
		if (!can_be_incomplete_array && value->is_incomplete_array) {
			map = &dtindex->cant_be_incomplete_array_map;
			value = dwarf_type_map_search_hashed(map, &key, hp);
		}
		if (value) {
			ret->type = value->type;
			ret->qualifiers = value->qualifiers;
			return NULL;
		}
	}

	ret->qualifiers = 0;
	dtindex->depth++;
	dwarf_type.is_incomplete_array = false;
	switch (dwarf_tag(die)) {
	case DW_TAG_const_type:
		/*
		 * Qualified types share the struct drgn_type with the
		 * unqualified type.
		 */
		dwarf_type.should_free = false;
		err = drgn_type_from_dwarf_child(dtindex, die,
						 "DW_TAG_const_type", true,
						 ret);
		ret->qualifiers |= DRGN_QUALIFIER_CONST;
		break;
	case DW_TAG_restrict_type:
		dwarf_type.should_free = false;
		err = drgn_type_from_dwarf_child(dtindex, die,
						 "DW_TAG_restrict_type", true,
						 ret);
		ret->qualifiers |= DRGN_QUALIFIER_RESTRICT;
		break;
	case DW_TAG_volatile_type:
		dwarf_type.should_free = false;
		err = drgn_type_from_dwarf_child(dtindex, die,
						 "DW_TAG_volatile_type", true,
						 ret);
		ret->qualifiers |= DRGN_QUALIFIER_VOLATILE;
		break;
	case DW_TAG_atomic_type:
		dwarf_type.should_free = false;
		err = drgn_type_from_dwarf_child(dtindex, die,
						 "DW_TAG_atomic_type", true,
						 ret);
		ret->qualifiers |= DRGN_QUALIFIER_ATOMIC;
		break;
	case DW_TAG_base_type:
		dwarf_type.should_free = true;
		err = drgn_base_type_from_dwarf(dtindex, die, &ret->type);
		break;
	case DW_TAG_structure_type:
		err = drgn_compound_type_from_dwarf(dtindex, die, true,
						    &ret->type,
						    &dwarf_type.should_free);
		break;
	case DW_TAG_union_type:
		err = drgn_compound_type_from_dwarf(dtindex, die, false,
						    &ret->type,
						    &dwarf_type.should_free);
		break;
	case DW_TAG_enumeration_type:
		err = drgn_enum_type_from_dwarf(dtindex, die, &ret->type,
						&dwarf_type.should_free);
		break;
	case DW_TAG_typedef:
		dwarf_type.should_free = true;
		err = drgn_typedef_type_from_dwarf(dtindex, die,
						   can_be_incomplete_array,
						   &dwarf_type.is_incomplete_array,
						   &ret->type);
		break;
	case DW_TAG_pointer_type:
		/* Pointer types are owned by the type index. */
		dwarf_type.should_free = false;
		err = drgn_pointer_type_from_dwarf(dtindex, die, &ret->type);
		break;
	case DW_TAG_array_type:
		/* Array types are owned by the type index. */
		dwarf_type.should_free = false;
		err = drgn_array_type_from_dwarf(dtindex, die,
						 can_be_incomplete_array,
						 &dwarf_type.is_incomplete_array,
						 &ret->type);
		break;
	case DW_TAG_subroutine_type:
	case DW_TAG_subprogram:
		dwarf_type.should_free = true;
		err = drgn_function_type_from_dwarf(dtindex, die, &ret->type);
		break;
	default:
		err = drgn_error_format(DRGN_ERROR_DWARF_FORMAT,
					"unknown DWARF type tag 0x%x",
					dwarf_tag(die));
		break;
	}
	dtindex->depth--;
	if (err)
		return err;

	dwarf_type.type = ret->type;
	dwarf_type.qualifiers = ret->qualifiers;
	if (!can_be_incomplete_array && dwarf_type.is_incomplete_array)
		map = &dtindex->cant_be_incomplete_array_map;
	else
		map = &dtindex->map;
	if (!dwarf_type_map_insert_searched(map, &key, &dwarf_type, hp)) {
		drgn_dwarf_type_free(&dwarf_type);
		return &drgn_enomem;
	}
	if (is_incomplete_array_ret)
		*is_incomplete_array_ret = dwarf_type.is_incomplete_array;
	return NULL;
}

static struct drgn_error *
drgn_dwarf_type_index_find(struct drgn_type_index *tindex,
			   enum drgn_type_kind kind, const char *name,
			   size_t name_len, const char *filename,
			   struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	struct drgn_dwarf_type_index *dtindex;
	struct drgn_dwarf_index_iterator it;
	Dwarf_Die die;
	uint64_t tag;

	switch (kind) {
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_FLOAT:
		tag = DW_TAG_base_type;
		break;
	case DRGN_TYPE_STRUCT:
		tag = DW_TAG_structure_type;
		break;
	case DRGN_TYPE_UNION:
		tag = DW_TAG_union_type;
		break;
	case DRGN_TYPE_ENUM:
		tag = DW_TAG_enumeration_type;
		break;
	case DRGN_TYPE_TYPEDEF:
		tag = DW_TAG_typedef;
		break;
	default:
		DRGN_UNREACHABLE();
	}

	dtindex = container_of(tindex, struct drgn_dwarf_type_index, tindex);
	drgn_dwarf_index_iterator_init(&it, dtindex->dindex, name, name_len,
				       &tag, 1);
	while (!(err = drgn_dwarf_index_iterator_next(&it, &die))) {
		if (die_matches_filename(&die, filename)) {
			err = drgn_type_from_dwarf(dtindex, &die, ret);
			if (err)
				return err;
			/*
			 * For DW_TAG_base_type, we need to check that the type
			 * we found was the right kind.
			 */
			if (drgn_type_kind(ret->type) == kind)
				return NULL;
		}
	}
	if (err && err->code != DRGN_ERROR_STOP)
		return err;
	return drgn_type_index_not_found_error(kind, name, name_len, filename);
}

static void drgn_dwarf_type_index_destroy(struct drgn_type_index *tindex)
{
	struct drgn_dwarf_type_index *dtindex;
	struct dwarf_type_map_pos pos;

	dtindex = container_of(tindex, struct drgn_dwarf_type_index, tindex);
	for (pos = dwarf_type_map_first_pos(&dtindex->map);
	     pos.item; dwarf_type_map_next_pos(&pos))
		drgn_dwarf_type_free(&pos.item->value);
	/* Arrays don't need to be freed, but typedefs do. */
	for (pos = dwarf_type_map_first_pos(&dtindex->cant_be_incomplete_array_map);
	     pos.item; dwarf_type_map_next_pos(&pos))
		drgn_dwarf_type_free(&pos.item->value);
	dwarf_type_map_deinit(&dtindex->cant_be_incomplete_array_map);
	dwarf_type_map_deinit(&dtindex->map);
	drgn_type_index_deinit(tindex);
	free(dtindex);
}

static const struct drgn_type_index_ops drgn_dwarf_type_index_ops = {
	.destroy = drgn_dwarf_type_index_destroy,
	.find = drgn_dwarf_type_index_find,
};

struct drgn_error *
drgn_dwarf_type_index_create(struct drgn_dwarf_index *dindex,
			     struct drgn_dwarf_type_index **ret)
{
	struct drgn_dwarf_type_index *dtindex;

	dtindex = malloc(sizeof(*dtindex));
	if (!dtindex)
		return &drgn_enomem;

	drgn_type_index_init(&dtindex->tindex, &drgn_dwarf_type_index_ops,
			     drgn_dwarf_index_word_size(dindex),
			     drgn_dwarf_index_is_little_endian(dindex));
	dwarf_type_map_init(&dtindex->map);
	dwarf_type_map_init(&dtindex->cant_be_incomplete_array_map);
	dtindex->dindex = dindex;
	dtindex->depth = 0;

	*ret = dtindex;
	return NULL;
}
