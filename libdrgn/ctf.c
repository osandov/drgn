// Copyright (c) 2024 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include <ctf.h>
#include <ctf-api.h>

#include "drgn_internal.h"
#include "drgn_ctf.h"
#include "error.h"
#include "hash_table.h"
#include "lazy_object.h"
#include "log.h"
#include "program.h"
#include "type.h"

/* Contains the "ground truth" integer / float name + id */
struct drgn_ctf_names_node {
	ctf_dict_t *dict;
	ctf_id_t id;
	struct drgn_ctf_names_node *next;
};

DEFINE_HASH_MAP(drgn_ctf_names, const char *, struct drgn_ctf_names_node,
		c_string_key_hash_pair, c_string_key_eq);

struct drgn_ctf_enumnode {
	ctf_dict_t *dict;
	ctf_id_t id;
	int64_t val;
	struct drgn_ctf_enumnode *next;
};

DEFINE_HASH_MAP(drgn_ctf_enums, const char *, struct drgn_ctf_enumnode,
		c_string_key_hash_pair, c_string_key_eq);

DEFINE_HASH_MAP(drgn_ctf_dicts, const char *, ctf_dict_t *,
		c_string_key_hash_pair, c_string_key_eq);

struct drgn_ctf_key {
	ctf_dict_t *dict;
	ctf_id_t id;
};

static struct hash_pair
drgn_ctf_key_hash_pair(const struct drgn_ctf_key *key)
{
	size_t hash;
	hash = hash_combine((uintptr_t)key->dict, key->id);
	return hash_pair_from_avalanching_hash(hash);
}

static bool drgn_ctf_key_eq_func(const struct drgn_ctf_key *a, const struct drgn_ctf_key *b)
{
	return a->dict == b->dict && a->id == b->id;
}

DEFINE_HASH_MAP(drgn_ctf_type_map, struct drgn_ctf_key, struct drgn_type *,
		drgn_ctf_key_hash_pair, drgn_ctf_key_eq_func);

struct drgn_ctf_info {
	struct drgn_program *prog;
	char *ctf_data;
	size_t ctf_size;
	ctf_archive_t *archive;
	struct drgn_ctf_dicts dicts;
	struct drgn_ctf_enums enums;
	struct drgn_ctf_names names;
	struct drgn_ctf_type_map types;
	ctf_dict_t *root;
	ctf_dict_t *vmlinux;
	bool bug_reversed_array_indices;
	int refcount; // counts the number of times we've been registered
	struct drgn_object_finder_ops ofind;
	struct drgn_type_finder_ops tfind;
};


static struct drgn_error *
drgn_type_from_ctf_id(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret,
                      bool in_bitfield);

static struct drgn_error *
drgn_type_from_ctf(uint64_t kinds, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret);

static struct drgn_error *
drgn_ctf_lookup_by_name(struct drgn_ctf_info *info, ctf_dict_t *dict, const char *name,
			uint64_t want_kinds, ctf_id_t *id_ret, ctf_dict_t **dict_ret);

static inline int get_ctf_errno(ctf_dict_t *dict)
{
	/*
	 * On some libctf versions, if an error is set on the parent dict, the
	 * child dict will still return 0 in ctf_errno. To avoid this, wrap
	 * ctf_errno() and verify.
	 */
	 int err = ctf_errno(dict);
	 ctf_dict_t *parent = ctf_parent_dict(dict);
	 if (!err && parent)
		 err = ctf_errno(parent);
	 return err;
}

static struct drgn_error *drgn_error_ctf(int err)
{
	return drgn_error_format(DRGN_ERROR_OTHER, "Internal CTF error: %s", ctf_errmsg(err));
}

static struct drgn_error *
drgn_integer_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret,
                      bool in_bitfield)
{
	ctf_encoding_t enc;
	bool _signed, is_bool, type_in_bitfield;
	const char *name;
	uint64_t size_bytes = ctf_type_size(dict, id);
	assert(ctf_type_encoding(dict, id, &enc) == 0);

	type_in_bitfield = enc.cte_offset || (enc.cte_bits != size_bytes * 8);

	if (type_in_bitfield) {
		if (!in_bitfield)
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"Integer with bitfield info outside compound type"
			);
		if (size_bytes * 8 < enc.cte_bits)
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"Integer whose bitfield size is greater than byte size"
			);
	}

	_signed = enc.cte_format & CTF_INT_SIGNED;
	is_bool = enc.cte_format & CTF_INT_BOOL;
	name = ctf_type_name_raw(dict, id);
	if (enc.cte_bits == 0) {
		ret->type = drgn_void_type(info->prog, &drgn_language_c);
	} else if (is_bool) {
		return drgn_bool_type_create(info->prog, name, size_bytes,
		                             DRGN_PROGRAM_ENDIAN,
					     &drgn_language_c, &ret->type);
	} else {
		return drgn_int_type_create(info->prog, name, size_bytes,
		                            _signed, DRGN_PROGRAM_ENDIAN,
					    &drgn_language_c, &ret->type);
	}
	return NULL;
}

static struct drgn_error *
drgn_float_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                    ctf_id_t id, struct drgn_qualified_type *ret,
                    bool in_bitfield)
{
	ctf_encoding_t enc;
	const char *name;
	bool type_in_bitfield;
	size_t size_bytes = ctf_type_size(dict, id);

	assert(ctf_type_encoding(dict, id, &enc) == 0);
	name = ctf_type_name_raw(dict, id);

	type_in_bitfield = enc.cte_offset || (enc.cte_bits != size_bytes * 8);
	if (type_in_bitfield) {
		if (!in_bitfield)
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"Float with bitfield info outside compound type"
			);
		if (size_bytes * 8 < enc.cte_bits)
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"Float whose bitfield size is greater than byte size"
			);
	}
	if (enc.cte_format != CTF_FP_DOUBLE && enc.cte_format != CTF_FP_SINGLE
	    && enc.cte_format != CTF_FP_LDOUBLE)
		return drgn_error_format(
			DRGN_ERROR_NOT_IMPLEMENTED,
			"CTF floating point format %d is not implemented",
			enc.cte_format
		);

	return drgn_float_type_create(info->prog, name, size_bytes,
				      DRGN_PROGRAM_ENDIAN, &drgn_language_c,
				      &ret->type);
}

static struct drgn_error *
drgn_typedef_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret,
		      bool in_bitfield)
{
	struct drgn_qualified_type aliased;
	struct drgn_error *err;
	const char *name;
	ctf_id_t aliased_id;

	name = ctf_type_name_raw(dict, id);
	aliased_id = ctf_type_reference(dict, id);
	if (!name || !name[0]) {
		/*
		 * An empty raw name field is wrong: typedefs must have
		 * a name, that's their reason to exist.
		 * This is an indicator that this is not really a typedef, it's
		 * a SLICE posing as a typdef. Re-grab the name and ID based on
		 * that assumption.
		 */
		name = ctf_type_name_raw(dict, aliased_id);
		aliased_id = ctf_type_reference(dict, aliased_id);
	}

	err = drgn_type_from_ctf_id(info, dict, aliased_id, &aliased, in_bitfield);
	if (err)
		return err;

	return drgn_typedef_type_create(info->prog, name, aliased,
					&drgn_language_c, &ret->type);
}

static struct drgn_error *
drgn_pointer_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_qualified_type aliased;
	struct drgn_error *err;
	ctf_id_t aliased_id;

	aliased_id = ctf_type_reference(dict, id);

	err = drgn_type_from_ctf_id(info, dict, aliased_id, &aliased, false);
	if (err)
		return err;

	ssize_t size = ctf_type_size(dict, id);
	if (size < 0)
		return drgn_error_ctf(get_ctf_errno(dict));

	return drgn_pointer_type_create(info->prog, aliased, size,
	                                DRGN_PROGRAM_ENDIAN, &drgn_language_c,
	                                &ret->type);
}

struct drgn_ctf_enum_visit_arg {
	struct drgn_enum_type_builder *builder;
	struct drgn_error *err;
};

static int drgn_ctf_enum_visit(const char *name, int val, void *arg)
{
	struct drgn_ctf_enum_visit_arg *visit = arg;
	visit->err = drgn_enum_type_builder_add_signed(visit->builder, name, val);
	return visit->err ? -1 : 0;
}

static struct drgn_error *
drgn_enum_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                   ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_enum_type_builder builder;
	struct drgn_ctf_enum_visit_arg arg;
	const char *name;
	struct drgn_qualified_type compatible_type;

	name = ctf_type_name_raw(dict, id);
	if (name && !name[0])
		name = NULL;

	arg.err = drgn_program_find_primitive_type(info->prog, DRGN_C_TYPE_INT,
						   &compatible_type.type);
	if (arg.err)
		return arg.err;

	drgn_enum_type_builder_init(&builder, info->prog);

	if (ctf_type_kind(dict, id) == CTF_K_FORWARD)
		return drgn_enum_type_create(&builder, name, compatible_type.type,
		                             &drgn_language_c, &ret->type);

	arg.builder = &builder;
	if (ctf_enum_iter(dict, id, drgn_ctf_enum_visit, &arg) != 0) {
		if (!arg.err)
			arg.err = drgn_error_ctf(get_ctf_errno(dict));
		goto out;
	}
	arg.err = drgn_enum_type_create(&builder, name, compatible_type.type,
				    &drgn_language_c, &ret->type);
	if (!arg.err)
		return NULL;
out:
	drgn_enum_type_builder_deinit(&builder);
	return arg.err;
}

static struct drgn_error *
drgn_array_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                    ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
#define MAX_DIMENSIONS 8
	int dims = 0;
	ctf_arinfo_t dim_info[MAX_DIMENSIONS];

	/*
	 * Handle multi-dimensional arrays properly...
	 *
	 * Unfortunately, CTF has several bugs related to multidimensional
	 * arrays.
	 *
	 * dwarf2ctf generated CTF simply does not represent them (it uses the
	 * last dimension's index and calls it good enough).
	 *
	 * GCC generated CTF represents the dimensions' indices in the opposite
	 * order as would be expected. The "nelems" field for the first
	 * CTF_K_ARRAY type is in fact the value for the last dimension, and so
	 * on. This is a _bug_, and future GCC implementations of CTF will fix
	 * this (they will contain a feature flag for clients detect the issue).
	 */
	while (ctf_type_kind(dict, id) == CTF_K_ARRAY) {
		if (dims >= MAX_DIMENSIONS)
			return drgn_error_format(
				DRGN_ERROR_NOT_IMPLEMENTED,
				"not supported with CTF: arrays with >%d dimensions",
				MAX_DIMENSIONS
			);

		ctf_array_info(dict, id, &dim_info[dims]);
		id = dim_info[dims].ctr_contents;
		dims++;
	}

	struct drgn_qualified_type etype = {0}, arrtype = {0};
	int i = dims - 1;
	int j;
	if (info->bug_reversed_array_indices)
		j = dims - i - 1;
	else
		j = i;

	/* First, construct the element type for a non-array type */
	err = drgn_type_from_ctf_id(info, dict, dim_info[i].ctr_contents,
				    &etype, false);
	if (err)
		return err;

	/*
	 * According to pg. 16 of CTFv3 Specification: cta_index: "If this is a
	 * variable-length aray, the index type ID will be 0 (but the actual
	 * index type of this array is probably int)."
	 *
	 * cta_nelems: The number of array elements. 0 for VLAs, and also for
	 * the historical variety of VLA which has explicit zero dimensions
	 * (which will have a nonzero cta_index.)
	 *
	 * In Linux, there are cases where explicit zero-length arrays exist,
	 * such as "struct zone_padding". These are not intended to be used as
	 * VLAs, they are intended to be used for the cache-line padding
	 * attributes. So the "historical variety" of VLA cannot be detected by
	 * testing nelems: zero is a valid array length.
	 *
	 * Thus, use ctr_index here to ensure that we define these explicit
	 * zero-length arrays as such.  Otherwise, drgn will complain about an
	 * incomplete array type in the middle of a struct.
	 *
	 * Further, we can only allow incomplete arrays if they are the outer
	 * dimension of a multi-dimensional array. Other dimensions don't make
	 * sense.
	 *
	 * We use j instead of i here to account for the reversed indexing issue
	 * described above.
	 */
	if (dim_info[j].ctr_index) {
		err = drgn_array_type_create(info->prog, etype, dim_info[j].ctr_nelems,
					&drgn_language_c, &arrtype.type);
	} else {
		if (i != 0)
			err = drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						"error: multidimensional arrays may only be incomplete in the outer dimension");
		else
			err = drgn_incomplete_array_type_create(info->prog, etype,
								&drgn_language_c,
								&arrtype.type);
	}
	if (err)
		return err;

	for (i = i - 1; i >= 0; i--) {
		etype = arrtype;
		arrtype = (struct drgn_qualified_type){0};
		if (info->bug_reversed_array_indices)
			j = dims - i - 1;
		else
			j = i;

		/* Use j for the ctr_index and ctr_nelems */
		if (dim_info[j].ctr_index) {
			err = drgn_array_type_create(info->prog, etype, dim_info[j].ctr_nelems,
						&drgn_language_c, &arrtype.type);
		} else {
			if (i != 0)
				err = drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
							"error: multidimensional arrays may only be incomplete in the outer dimension");
			else
				err = drgn_incomplete_array_type_create(info->prog, etype,
									&drgn_language_c,
									&arrtype.type);
		}
		if (err)
			return err;
	}
	*ret = arrtype;
	return err;
#undef MAX_DIMENSIONS
}

struct drgn_ctf_thunk_arg {
	struct drgn_ctf_info *info;
	ctf_dict_t *dict;
	ctf_id_t id;
	uint64_t bit_field_size;
};

static struct drgn_error *drgn_ctf_thunk(struct drgn_object *res, void *void_arg)
{
	struct drgn_ctf_thunk_arg *arg = void_arg;
	struct drgn_qualified_type type;
	struct drgn_error *err = NULL;

	/*
	 * Thunks are a bit confusing. As far as I understand, this call needs
	 * to handle three cases:
	 * 1. res == NULL: in this case, we are being deinitialized, so free the
	 *    arg.
	 * 2(a). res != NULL, and we do not encounter an error evaluating the
	 *       thunk: we won't get called again, so the arg should get freed
	 *       as well.
	 * 2(b). res != NULL, and we encounter an error. In this case, we need
	 *       to preserve the arg, because drgn will re-initialize the lazy
	 *       object. If we free the arg on failure, then we run the risk of
	 *       either a UAF if the evaluation is retried, or a double free if
	 *       the the deinitializer gets called.
	 */

	if (res) {
		err = drgn_type_from_ctf_id(arg->info, arg->dict,
		                            arg->id, &type, (bool)arg->bit_field_size);
		if (!err)
			err = drgn_object_set_absent(res, type,
						     DRGN_ABSENCE_REASON_OTHER,
						     arg->bit_field_size);

		if (!err)
			free(arg);  /* Case 2(a) */
	} else {
		free(arg);  /* Case 1 */
	}

	return err;
}

static struct drgn_error *
drgn_function_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                       ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_function_type_builder builder;
	struct drgn_qualified_type qt;
	struct drgn_error *err;
	ctf_funcinfo_t funcinfo;
	ctf_id_t *argtypes;
	bool variadic = false;

	//printf("Create function type for id %lu\n", id);

	ctf_func_type_info(dict, id, &funcinfo);
	variadic = funcinfo.ctc_flags & CTF_FUNC_VARARG;
	argtypes = calloc(funcinfo.ctc_argc, sizeof(*argtypes));
	if (!argtypes)
		return &drgn_enomem;
	ctf_func_type_args(dict, id, funcinfo.ctc_argc, argtypes);

	drgn_function_type_builder_init(&builder, info->prog);

	err = drgn_type_from_ctf_id(info, dict, funcinfo.ctc_return, &qt, false);
	if (err)
		goto out;

	for (size_t i = 0; i < funcinfo.ctc_argc; i++) {
		union drgn_lazy_object param;
		struct drgn_ctf_thunk_arg *arg;

		arg = calloc(1, sizeof(*arg));
		if (!arg) {
			err = &drgn_enomem;
			goto out;
		}
		arg->info = info;
		arg->dict = dict;
		arg->id = argtypes[i];
		drgn_lazy_object_init_thunk(&param, info->prog, drgn_ctf_thunk, arg);
		err = drgn_function_type_builder_add_parameter(&builder, &param, NULL);
		//printf("add param index %lu id %lu\n", i, argtypes[i]);
		if (err) {
			drgn_lazy_object_deinit(&param);
			goto out;
		}
	}
	free(argtypes);
	argtypes = NULL;

	err = drgn_type_from_ctf_id(info, dict, funcinfo.ctc_return, ret, false);
	if (err)
		goto out;
	err = drgn_function_type_create(&builder, qt, variadic, &drgn_language_c, &ret->type);
	if (!err)
		return NULL;
out:
	drgn_function_type_builder_deinit(&builder);
	free(argtypes);
	return err;
}

struct compound_member_visit_arg {
	struct drgn_compound_type_builder *builder;
	struct drgn_ctf_info *info;
	ctf_dict_t *dict;
	struct drgn_error *err;
};

static struct drgn_error *
check_is_bitfield(struct drgn_ctf_info *info, ctf_dict_t *dict, ctf_id_t id,
		  ctf_encoding_t enc, bool *ret)
{

	ctf_dict_t *canonical_dict;
	ctf_id_t canonical_id;
	ssize_t byte_size = ctf_type_size(dict, id);

	// When an offset is present, or when the bit count is not exactly the
	// same as the bytes, we can short-circuit: we know this must be a bit
	// field.
	if (enc.cte_offset > 0 || enc.cte_bits != byte_size * 8) {
		*ret = true;
		return NULL;
	}

	// No offset and the bit size matches byte size. Unfortunately,
	// dwarf2ctf encodes bit field integers using the smallest byte size
	// which would accommodate the bit field: not the canonical type size.
	// So, we'll need to look up the integer/float type by name and find out
	// if the bitfield size matches the real canonical type size. This will
	// let us know whether it is a bit field.
	const char *type_name = ctf_type_name_raw(dict, id);
	int kind = ctf_type_kind(dict, id);
	struct drgn_error *err = drgn_ctf_lookup_by_name(info, dict, type_name,
							 1UL << kind, &canonical_id,
							 &canonical_dict);
	if (err)
		return err;
	ssize_t canonical_size = ctf_type_size(canonical_dict, canonical_id);
	*ret = (enc.cte_bits != canonical_size * 8);
	return NULL;
}

static int compound_member_visit(const char *name, ctf_id_t membtype, unsigned long offset,
                                 void *void_arg)
{
	union drgn_lazy_object obj;
	struct compound_member_visit_arg *arg = void_arg;
	_cleanup_free_ struct drgn_ctf_thunk_arg *thunk_arg =
		calloc(1, sizeof(*thunk_arg));

	//printf("Compound member %s id %lu\n", name, membtype);
	thunk_arg->dict = arg->dict;
	thunk_arg->info = arg->info;
	thunk_arg->id = membtype;
	thunk_arg->bit_field_size = 0;

	/* libctf gives us 0-length name for anonymous members, but drgn prefers
	 * NULL. 0-length name seems to be legal, but inaccessible for the API. */
	if (name[0] == '\0')
		name = NULL;

	/*
	 * Integers and floats may be bit fields. In order to properly represent
	 * them, we need to know three things:
	 *
	 * 1. Is the member a bit field?
	 * 2. What is the bit field offset?
	 * 3. What is the bit field size?
	 *
	 * CTF readily gives #2 and #3, but it doesn't give an easy indication
	 * that a member actually is a bit field. This means we need to know the
	 * canonical bit size the underlying integer type: if the member has no
	 * bitfield offset and the same bit size as the canonical size, we can
	 * conclude the member is not a bitfield.
	 *
	 * Unfortunately, knowing the canonical type size is not always easy.
	 * CTF represents bitfields in two different ways:
	 *
	 * (a) dwarf2ctf: by creating a specialized type ID of CTF_K_INTEGER
	 *     with encoding specifying the bit field size and offset. The
	 *     ctf_type_size() reported for this type is the smallest size which
	 *     would fit the bitfield: not the size of the canonical integer
	 *     type.
	 * (b) gcc: by creating a type ID of CTF_K_SLICE (which is not visible
	 *     via the CTF API). The slice has an encoding which contains the
	 *     bitfield information, but it references the underlying canonical
	 *     type. This means we can simply compare the bit size against the
	 *     canonical size of the underlying type.
	 */

	// Resolved type ID: traverses through all qualifiers/typedefs, but not
	// slices
	ctf_id_t resolved = ctf_type_resolve(arg->dict, membtype);
	// Reference type ID: traverses through one step of references, but DOES
	// traverse slices
	ctf_id_t reference = ctf_type_reference(arg->dict, resolved);

	ctf_encoding_t enc;
	bool has_encoding = ctf_type_encoding(arg->dict, resolved, &enc) == 0;
	bool is_bit_field = false;
	if (has_encoding && reference != CTF_ERR) {
		// A slice! It has an encoding, but still references another
		// type. The underlying type will have the canonical size.
		ssize_t canonical_size = ctf_type_size(arg->dict, reference);
		is_bit_field = enc.cte_bits != 8 * canonical_size;
		// We should skip over the slice since we have the info we need
		// from it.
		thunk_arg->id = reference;
	} else if (has_encoding) {
		// Not a slice! It has an encoding, but the byte size may
		// not match the canonical size of the type.
		arg->err = check_is_bitfield(arg->info, arg->dict, resolved,
					     enc, &is_bit_field);
		if (arg->err)
			return -1;
	}

	if (is_bit_field) {
		thunk_arg->bit_field_size = enc.cte_bits;
		offset += enc.cte_offset;
	}

	drgn_lazy_object_init_thunk(&obj, arg->info->prog, drgn_ctf_thunk,
				    no_cleanup_ptr(thunk_arg));
	arg->err = drgn_compound_type_builder_add_member(arg->builder, &obj, name, offset);
	if (arg->err) {
		drgn_lazy_object_deinit(&obj); /* frees thunk_arg */
		return -1;
	} else {
		return 0;
	}
}

static struct drgn_error *
drgn_compound_type_from_ctf(enum drgn_type_kind kind, struct drgn_ctf_info *info, ctf_dict_t *dict,
                            ctf_id_t id, struct drgn_qualified_type *ret)
{
	struct drgn_compound_type_builder builder;
	struct drgn_error *err;
	struct compound_member_visit_arg arg;
	const char *tag;
	ssize_t size;

	tag = ctf_type_name_raw(dict, id);
	if (tag && !*tag)
		tag = NULL;

	drgn_compound_type_builder_init(&builder, info->prog, kind);

	/*
	 * We may be called with a kind of CTF_K_FORWARD which means an incomplete
	 * struct / union.
	 */
	if (ctf_type_kind(dict, id) == CTF_K_FORWARD)
		return drgn_compound_type_create(&builder, tag, 0, false,
		                                 &drgn_language_c, &ret->type);

	/* Don't ask for the size until after checking for forward declared types. */
	size = ctf_type_size(dict, id);
	if (size < 0 ) {
		err = drgn_error_ctf(get_ctf_errno(dict));
		goto out;
	}


	arg.builder = &builder;
	arg.info = info;
	arg.dict = dict;
	arg.err = NULL;
	if (ctf_member_iter(dict, id, compound_member_visit, &arg) == -1) {
		if (arg.err)
			err = arg.err;
		else
			err = drgn_error_ctf(get_ctf_errno(dict));
		goto out;
	}

	err = drgn_compound_type_create(&builder, tag, size, true,
	                                &drgn_language_c, &ret->type);
	if (!err) {
		//printf("Successfully created compound type %s\n", tag);
		return NULL;
	}
out:
	drgn_compound_type_builder_deinit(&builder);
	return err;
}

static struct drgn_error *
drgn_forward_from_ctf(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret)
{
	int ctf_kind = ctf_type_kind_forwarded(dict, id);
	const char *name = ctf_type_name_raw(dict, id);
	struct drgn_error *err;

	if (name && !*name)
		name = NULL;

	/*
	 * TODO: A forward declared type could be duplicated in several modules.
	 * In general, we can't really know which module to look in, this is a
	 * difficult problem to solve. For now, an easy answer is to just use
	 * the first available option.
	 */
	if (name) {
		err = drgn_ctf_lookup_by_name(info, NULL, name, (1ULL << ctf_kind),
					      &id, &dict);

		if (drgn_error_catch(&err, DRGN_ERROR_LOOKUP)) {
			const char *kind_name;
			switch (ctf_kind) {
				case CTF_K_ENUM:
					kind_name = "enum";
					break;
				case CTF_K_STRUCT:
					kind_name = "struct";
					break;
				case CTF_K_UNION:
					kind_name = "union";
					break;
				default:
					kind_name = "UNKNOWN KIND:";
					break;
			}
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "cannot resolve CTF forwarded type: %s %s\n",
						 kind_name, name);
		} else if (err) {
			return err;
		}
	}

	/*
	 * Now, either we have found an underlying definition, or we still have
	 * the forwarded type ID. Either way, we can construct the (maybe
	 * absent) type from this ID.
	 */
	switch (ctf_kind) {
		case CTF_K_ENUM:
			return drgn_enum_from_ctf(info, dict, id, ret);
		case CTF_K_STRUCT:
			return drgn_compound_type_from_ctf(DRGN_TYPE_STRUCT, info, dict, id, ret);
		case CTF_K_UNION:
			return drgn_compound_type_from_ctf(DRGN_TYPE_UNION, info, dict, id, ret);
		default:
			return drgn_error_format(DRGN_ERROR_OTHER, "Forwarded CTF type id %lu, kind %d, is not enum, struct, or union", id, ctf_kind);
	}
}

static struct drgn_error *
drgn_type_from_ctf_id(struct drgn_ctf_info *info, ctf_dict_t *dict,
                      ctf_id_t id, struct drgn_qualified_type *ret,
		      bool in_bitfield)
{
	int ctf_kind;

	ret->qualifiers = 0;
	ret->type = NULL;

again:
	ctf_kind = ctf_type_kind(dict, id);
	switch (ctf_kind) {
		case CTF_K_CONST:
			ret->qualifiers |= DRGN_QUALIFIER_CONST;
			id = ctf_type_reference(dict, id);
			goto again;
		case CTF_K_RESTRICT:
			ret->qualifiers |= DRGN_QUALIFIER_RESTRICT;
			id = ctf_type_reference(dict, id);
			goto again;
		case CTF_K_VOLATILE:
			ret->qualifiers |= DRGN_QUALIFIER_VOLATILE;
			id = ctf_type_reference(dict, id);
			goto again;
		break;
	}

	struct drgn_ctf_key key = {dict, id};
	if (ctf_type_isparent(dict, id))
		/* We should be accurate about which dict the cached type
		 * actually belongs to: otherwise, we'll cache multiple
		 * copies. */
		key.dict = info->root;
	struct hash_pair hp = drgn_ctf_type_map_hash(&key);
	struct drgn_ctf_type_map_iterator it =
		drgn_ctf_type_map_search_hashed(&info->types, &key, hp);
	if (it.entry) {
		ret->type = it.entry->value;
		return NULL;
	}

	struct drgn_error *err;
	switch (ctf_kind) {
		case CTF_K_INTEGER:
			err = drgn_integer_from_ctf(info, dict, id, ret, in_bitfield);
			break;
		case CTF_K_FLOAT:
			err = drgn_float_from_ctf(info, dict, id, ret, in_bitfield);
			break;
		case CTF_K_TYPEDEF:
			err = drgn_typedef_from_ctf(info, dict, id, ret, in_bitfield);
			break;
		case CTF_K_POINTER:
			err = drgn_pointer_from_ctf(info, dict, id, ret);
			break;
		case CTF_K_ENUM:
			err = drgn_enum_from_ctf(info, dict, id, ret);
			break;
		case CTF_K_FUNCTION:
			err = drgn_function_from_ctf(info, dict, id, ret);
			break;
		case CTF_K_ARRAY:
			err = drgn_array_from_ctf(info, dict, id, ret);
			break;
		case CTF_K_STRUCT:
			err = drgn_compound_type_from_ctf(DRGN_TYPE_STRUCT, info, dict, id, ret);
			break;
		case CTF_K_UNION:
			err = drgn_compound_type_from_ctf(DRGN_TYPE_UNION, info, dict, id, ret);
			break;
		case CTF_K_FORWARD:
			err = drgn_forward_from_ctf(info, dict, id, ret);
			break;
		default:
			return drgn_error_format(DRGN_ERROR_NOT_IMPLEMENTED, "CTF Type Kind %d is not implemented", ctf_kind);
	}
	if (err)
		return err;

	struct drgn_ctf_type_map_entry entry;
	entry.key = key;
	entry.value = ret->type;
	if (drgn_ctf_type_map_insert_searched(&info->types, &entry, hp, NULL) == -1)
		err = &drgn_enomem;
	return err;
}

static struct drgn_error *
drgn_ctf_get_dict(struct drgn_ctf_info *info, const char *name, ctf_dict_t **ret)
{
	struct hash_pair hp = drgn_ctf_dicts_hash(&name);
	struct drgn_ctf_dicts_iterator it = drgn_ctf_dicts_search_hashed(&info->dicts, &name, hp);
	if (it.entry) {
		*ret = it.entry->value;
		return NULL;
	}

	int errnum;
	const char *name_saved = strdup(name);
	struct drgn_error *err;
	if (!name_saved)
		return &drgn_enomem;

	ctf_dict_t *dict = ctf_dict_open(info->archive, name, &errnum);
	if (!dict && errnum == ECTF_ARNNAME) {
		// The common case for failure is that the dictionary name did
		// not exist, this only occurs when a dict name is passed in via
		// "drgn.type()" second argument. Return a lookup error.
		err = &drgn_not_found;
		goto out;
	} else if (!dict) {
		err = drgn_error_format(DRGN_ERROR_OTHER, "ctf_dict_open: \"%s\": %s",
					name, ctf_errmsg(errnum));
		goto out;
	}
	struct drgn_ctf_dicts_entry entry = {name_saved, dict};
	if (drgn_ctf_dicts_insert_searched(&info->dicts, &entry, hp, NULL) < 0) {
		err = &drgn_enomem;
		goto out_close;
	}
	*ret = dict;
	return NULL;
out_close:
	ctf_dict_close(dict);
out:
	free((char *)name_saved);
	return err;
}

static struct drgn_error *
drgn_ctf_lookup_by_name(struct drgn_ctf_info *info, ctf_dict_t *dict, const char *name,
			uint64_t want_kinds, ctf_id_t *id_ret, ctf_dict_t **dict_ret)
{
	struct drgn_ctf_names_iterator it = drgn_ctf_names_search(&info->names, &name);
	if (!it.entry)
		return &drgn_not_found;

	struct drgn_ctf_names_node *node;
	for (node = &it.entry->value; node; node = node->next) {
		/* When dict is provided, restrict our search to that dict, but
		 * we need to allow types from the parent dictionary too. */
		if (dict && ctf_type_ischild(node->dict, node->id)
		    && dict != node->dict)
			continue;
		int kind = ctf_type_kind(node->dict, node->id);
		if (!(want_kinds & (1ULL << kind)))
			continue;
		*id_ret = node->id;
		*dict_ret = node->dict;
		return NULL;
	}

	return &drgn_not_found;
}

static bool looks_like_filename(const char *filename)
{
	/* C filenames should contain '.' or '/' */
	return strchr(filename, '/') != NULL ||
		strchr(filename, '.') != NULL;
}

static struct drgn_error *
drgn_type_from_ctf(uint64_t kinds, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret)
{
	ctf_dict_t *dict = NULL;
	ctf_id_t id;
	struct drgn_ctf_info *info = arg;
	struct drgn_error *err = NULL;
	uint64_t ctf_kinds = 0;

	if (kinds & (1 << DRGN_TYPE_ENUM))
		ctf_kinds |= (1 << CTF_K_ENUM);
	if (kinds & (1 << DRGN_TYPE_STRUCT))
		ctf_kinds |= (1 << CTF_K_STRUCT);
	if (kinds & (1 << DRGN_TYPE_UNION))
		ctf_kinds |= (1 << CTF_K_UNION);
	if (kinds & (1 << DRGN_TYPE_TYPEDEF))
		ctf_kinds |= (1 << CTF_K_TYPEDEF);

	/*
	 * Linux kernel CTF archives don't use filenames as dictionary names:
	 * they are named by kernel module. Userspace CTF, on the other hand,
	 * does use filenames.
	 *
	 * For the kernel, we'd like to allow users to run prog.type("name",
	 * "module") for CTF in order to restrict lookup to a given module.
	 * However, for existing code which uses filenames to disambiguate, we
	 * can't interpret these filenames as modules, since lookup will always
	 * fail, breaking existing code. So, silently ignore the filename
	 * parameter when it looks like a filename, and we're debugging the
	 * kernel.
	 */
	if (filename && !((info->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
			  looks_like_filename(filename))) {
		err = drgn_ctf_get_dict(info, filename, &dict);
		if (err)
			return err;
	}

	_cleanup_free_ char *name_copy = strndup(name, name_len);

	err = drgn_ctf_lookup_by_name(info, dict, name_copy, ctf_kinds,
				      &id, &dict);

	if (!err)
		return drgn_type_from_ctf_id(info, dict, id, ret,
						false);
	return err;
}

static struct drgn_error *
drgn_ctf_find_var(struct drgn_ctf_info *info, const char *name, ctf_dict_t *dict,
		  uint64_t addr, struct drgn_object *ret)
{
	struct drgn_qualified_type qt = {0};
	struct drgn_error *err;
	ctf_id_t id;

	id = ctf_lookup_variable(dict, name);

	/* Technically, it could be possible for libctf to return an error
	 * other than a lookup error. Practically, this doesn't happen, and
	 * due to some bugs related to ctf_errno() with CTF lookup functions,
	 * reliably distinguishing this case is impossible. Just assume the
	 * CTF error was a lookup error.
	 */
	if (id == CTF_ERR)
		return &drgn_not_found;

	err = drgn_type_from_ctf_id(info, dict, id, &qt, NULL);
	if (err)
		return err;

	return drgn_object_set_reference(ret, qt, addr, 0, 0);
}

static struct drgn_error *
drgn_ctf_find_var_all_dicts(struct drgn_ctf_info *info, const char *name, uint64_t addr,
			    struct drgn_object *ret)
{
	struct drgn_ctf_dicts_iterator it;
	struct drgn_error *err;

	/*
	 * A reasonable assumption is that this is in vmlinux. First search it,
	 * and then the rest of the modules.
	 * TODO: can we use some smarts here? We should be able to determine
	 * which module an address is from. If we do that, we can skip directly
	 * to searching the relevant dict.
	 */
	if (info->vmlinux) {
		err = drgn_ctf_find_var(info, name, info->vmlinux, addr, ret);
		if (!err || !drgn_error_catch(&err, DRGN_ERROR_LOOKUP))
			return err;
	}

	for (it = drgn_ctf_dicts_first(&info->dicts); it.entry; it = drgn_ctf_dicts_next(it)) {
		if (it.entry->value == info->vmlinux || it.entry->value == info->root)
			continue; /* no need to search these */
		err = drgn_ctf_find_var(info, name, it.entry->value, addr, ret);
		if (!err || !drgn_error_catch(&err, DRGN_ERROR_LOOKUP))
			return err;
	}
	return &drgn_not_found;
}

static struct drgn_error *
drgn_ctf_find_constant(struct drgn_ctf_info *info, const char *name, ctf_dict_t *dict,
		       struct drgn_object *ret)
{
	struct drgn_ctf_enums_iterator it = drgn_ctf_enums_search(&info->enums, &name);
	struct drgn_ctf_enumnode *node = it.entry ? &it.entry->value : NULL;
	struct drgn_error *err;

	for (; node; node = node->next) {
		if (dict && node->dict != dict)
			continue;
		/* A match! Construct an object. */
		struct drgn_qualified_type qt = {0};

		/* While we know this is an enum, we should use
		 * drgn_type_from_ctf_id() so that we leverage our cache of types */
		err = drgn_type_from_ctf_id(info, node->dict, node->id, &qt, false);
		if (err)
			return err;
		return drgn_object_set_signed(ret, qt, node->val, 0);
	}
	return &drgn_not_found;
}

static struct drgn_error *
drgn_ctf_find_object(const char *name, size_t name_len,
		     const char *filename,
		     enum drgn_find_object_flags flags, void *arg,
		     struct drgn_object *ret)
{
	struct drgn_error *err = NULL;
	struct drgn_ctf_info *info = arg;
	ctf_dict_t *dict = NULL;
	_cleanup_free_ char *name_copy = strndup(name, name_len);

	/*
	 * Linux kernel CTF archives don't use filenames as dictionary names:
	 * they are named by kernel module. Userspace CTF, on the other hand,
	 * does use filenames.
	 *
	 * For the kernel, we'd like to allow users to run prog.type("name",
	 * "module") for CTF in order to restrict lookup to a given module.
	 * However, for existing code which uses filenames to disambiguate, we
	 * can't interpret these filenames as modules, since lookup will always
	 * fail, breaking existing code. So, silently ignore the filename
	 * parameter when it looks like a filename, and we're debugging the
	 * kernel.
	 *
	 * TODO: in the future, filtering symbols by the given kernel module
	 * name would be helpful too.
	 */
	if (filename && !((info->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
			  looks_like_filename(filename))) {
		err = drgn_ctf_get_dict(info, filename, &dict);
		if (err)
			return err;
	}

	if (flags & DRGN_FIND_OBJECT_CONSTANT) {
		err = drgn_ctf_find_constant(info, name_copy, NULL, ret);
		if (!err || !drgn_error_catch(&err, DRGN_ERROR_LOOKUP))
			return err;
	}
	if (flags & (DRGN_FIND_OBJECT_VARIABLE | DRGN_FIND_OBJECT_FUNCTION)) {
		uint64_t addr;
		struct drgn_symbol *sym = NULL;
		err = drgn_program_find_symbol_by_name(info->prog, name, &sym);
		if (err)
			return err;
		addr = sym->address;
		drgn_symbol_destroy(sym);
		if (dict) {
			err = drgn_ctf_find_var(info, name_copy, dict, addr, ret);
			if (!err || !drgn_error_catch(&err, DRGN_ERROR_LOOKUP))
				return err;
		} else {
			err = drgn_ctf_find_var_all_dicts(info, name_copy, addr, ret);
			if( !err || !drgn_error_catch(&err, DRGN_ERROR_LOOKUP))
				return err;
		}
	}
	return &drgn_not_found;
}

struct drgn_ctf_arg {
	struct drgn_ctf_info *info;
	ctf_dict_t *dict;
	const char *dict_name;
	ctf_id_t type;
	struct drgn_error *err;
	unsigned long count;
};

static int process_enumerator(const char *name, int val, void *void_arg)
{
	struct drgn_ctf_arg *arg = void_arg;
	struct drgn_ctf_enums_iterator it;
	struct drgn_ctf_enums_entry entry;
	struct hash_pair hp;

	hp = drgn_ctf_enums_hash(&name);
	it = drgn_ctf_enums_search_hashed(&arg->info->enums, &name, hp);
	if (it.entry) {
		/* Insert at the head of the list, which means allocating a node
		 * for the current head to reside at. */
		struct drgn_ctf_enumnode *node = calloc(1, sizeof(*node));
		if (!node) {
			arg->err = &drgn_enomem;
			return -1;
		}
		*node = it.entry->value;
		it.entry->value.dict = arg->dict;
		it.entry->value.id = arg->type;
		it.entry->value.val = val;
		it.entry->value.next = node;
	} else {
		entry.key = name;
		entry.value.dict = arg->dict;
		entry.value.id = arg->type;
		entry.value.val = val;
		entry.value.next = NULL;
		if (drgn_ctf_enums_insert_searched(&arg->info->enums, &entry, hp, NULL) < 0) {
			arg->err = &drgn_enomem;
			return -1;
		}
	}
	arg->count++;
	return 0;
}

static struct drgn_error *
canonical_atom(struct drgn_ctf_info *info, const char *name, ctf_dict_t *dict, ctf_id_t id)
{
	struct drgn_ctf_names_iterator it;
	struct drgn_ctf_names_entry entry;
	struct hash_pair hp;
	int kind = ctf_type_kind(dict, id);

	/* CTF BUG: for CTF generated without slices, int/float types are
	 * duplicated when they are contained within a bitfield. While the
	 * integers & floats themselves are hidden, any typedefs pointing at
	 * them will be public, so we'll get lots of duplicates. Detect when a
	 * typedef points at a bitfield, and if so, skip it. */
	if (kind == CTF_K_TYPEDEF) {
		ctf_id_t resolved = ctf_type_resolve(dict, id);
		if (resolved != CTF_ERR) {
			ctf_encoding_t enc;
			size_t size = ctf_type_size(dict, resolved);
			if (ctf_type_encoding(dict, resolved, &enc) == 0) {
				if (enc.cte_bits != size * 8 || enc.cte_offset)
					return NULL;
			}
		}
	}

	hp = drgn_ctf_names_hash(&name);
	it = drgn_ctf_names_search_hashed(&info->names, &name, hp);
	if (it.entry) {
		struct drgn_ctf_names_node *iter = &it.entry->value;

		/* Adding to the end of the linked list is slower if there are
		 * long lists. But, it allows us to check for duplicates of the
		 * same type kind, name, and dict. */

		while (iter->next) {
			if (iter->dict == dict && ctf_type_kind(iter->dict, iter->id) == kind)
				return NULL;
			iter = iter->next;
		}
		if (iter->dict == dict && ctf_type_kind(iter->dict, iter->id) == kind)
			return NULL;

		struct drgn_ctf_names_node *node = calloc(1, sizeof(*node));
		if (!node)
			return &drgn_enomem;
		node->dict = dict;
		node->id = id;

		iter->next = node;
	} else {
		entry.key = name;
		entry.value.dict = dict;
		entry.value.id = id;
		entry.value.next = NULL;
		if (drgn_ctf_names_insert_searched(&info->names, &entry, hp, NULL) < 0)
			return &drgn_enomem;
	}
	return NULL;
}

static int process_type(ctf_id_t type, void *void_arg)
{
	struct drgn_ctf_arg *arg = void_arg;
	int kind = ctf_type_kind(arg->dict, type);
	ctf_id_t dst;
	int ret = 0;
	const char *name;
	switch (kind) {
	case CTF_K_ENUM:
		if (ctf_type_reference(arg->dict, type) != CTF_ERR)
			return 0; /* It's a SLICE! */
		arg->type = type;
		ret = ctf_enum_iter(arg->dict, type, process_enumerator, void_arg);
		/* For CTF errors, set a drgn error immediately */
		if (ret != 0 && !arg->err) {
			arg->err = drgn_error_ctf(get_ctf_errno(arg->dict));
		}
		if (ret)
			return ret;

		arg->type = 0;
		break;
	case CTF_K_INTEGER:
	case CTF_K_FLOAT:
		if (ctf_type_reference(arg->dict, type) != CTF_ERR)
			return 0; /* It's a SLICE! */
		break;
	case CTF_K_TYPEDEF:
		dst = ctf_type_reference(arg->dict, type);
		if (ctf_type_kind(arg->dict, dst) == CTF_K_TYPEDEF
		    && strcmp(ctf_type_name_raw(arg->dict, type),
			      ctf_type_name_raw(arg->dict, dst)) == 0)
			return 0; /* It's a SLICE! */
		break;
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		break;
	default:
		return 0;
	}
	name = ctf_type_name_raw(arg->dict, type);
	if (name && *name) {
		arg->err = canonical_atom(arg->info, name,
						arg->dict, type);
		ret = arg->err ? -1 : 0;
	}
	return ret;
}

static int process_dict(ctf_dict_t *unused, const char *name, void *void_arg)
{
	struct drgn_ctf_arg *arg = void_arg;
	ctf_dict_t *dict;

	/* The CTF archive iterator will close the dict handle it gives us once
	 * we return. So ignore the argument and open a new handle which we will
	 * cache. */
	arg->err = drgn_ctf_get_dict(arg->info, name, &dict);
	if (arg->err)
		return -1;

	if (strcmp(name, "shared_ctf") == 0) {
		arg->info->root = dict;
	} else if (strcmp(name, "vmlinux") == 0) {
		if (arg->info->vmlinux)
			return 0; /* already visited */
		arg->info->vmlinux = dict;
	}

	arg->dict = dict;
	arg->dict_name = name;

	int ret = ctf_type_iter(dict, process_type, void_arg);
	/* For CTF errors, set a drgn error immediately */
	if (ret != 0 && !arg->err)
		arg->err = drgn_error_ctf(get_ctf_errno(dict));

	arg->dict = NULL;
	arg->dict_name = NULL;

	return ret;
}

#ifndef WITH_LIBBFD
/*
 * libctf contains an awfully convenient "ctf_open" which seems to "do what you
 * mean". Unfortunately, it is not present when you compile with -lctf-nobfd.
 * And avoiding linking to BFD can be very useful. So let's do what we need.
 */
static struct drgn_error *read_ctf_buf(const char *file, char **buf_ret, size_t *size_ret)
{
	long size, amt;
	char *buf;
	FILE *f = fopen(file, "r");

	if (!f)
		return drgn_error_create_os("Error opening CTF file", errno, file);

	if (fseek(f, 0, SEEK_END) == -1) {
		fclose(f);
		return drgn_error_create_os("Error seeking to end of CTF file", errno, file);
	}
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(size + 1);
	if (!buf) {
		fclose(f);
		return &drgn_enomem;
	}
	amt = fread(buf, 1, size, f);
	if (amt != size) {
		free(buf);
		fclose(f);
		return drgn_error_create_os("Error reading CTF file", errno, file);
	}
	fclose(f);
	buf[size] = '\0';
	*buf_ret = buf;
	*size_ret = size;
	return NULL;
}
#endif

static void
drgn_ctf_enums_free_all(struct drgn_ctf_enums *enums)
{
	struct drgn_ctf_enums_iterator it = drgn_ctf_enums_first(enums);
	while (it.entry) {
		struct drgn_ctf_enumnode *node = &it.entry->value;
		node = node->next;
		while (node) {
			struct drgn_ctf_enumnode *tmp = node->next;
			free(node);
			node = tmp;
		}
		// the string key is owned by CTF, leave it alone
		it = drgn_ctf_enums_delete_iterator(enums, it);
	}
}

static void
drgn_ctf_names_free_all(struct drgn_ctf_names *enums)
{
	struct drgn_ctf_names_iterator it = drgn_ctf_names_first(enums);
	while (it.entry) {
		struct drgn_ctf_names_node *node = &it.entry->value;
		node = node->next;
		while (node) {
			struct drgn_ctf_names_node *tmp = node->next;
			free(node);
			node = tmp;
		}
		// the string key is owned by CTF, leave it alone
		it = drgn_ctf_names_delete_iterator(enums, it);
	}
}

static void
drgn_ctf_dicts_close_all(struct drgn_ctf_dicts *dicts)
{
	struct drgn_ctf_dicts_iterator it = drgn_ctf_dicts_first(dicts);
	while (it.entry) {
		// dict name key, and dict, both need cleanup, but we cannot
		// free the name until we've deleted from the hash table, since
		// it will be hashed one last time in the delete function.
		char *tmp = (char *)it.entry->key;
		ctf_dict_close(it.entry->value);
		it = drgn_ctf_dicts_delete_iterator(dicts, it);
		free(tmp);
	}
}

static void drgn_ctf_destroy(struct drgn_ctf_info *info)
{
	if (!info)
		return;
	/* Any cached types are managed by drgn, but we own the tables */
	drgn_ctf_type_map_deinit(&info->types);
	drgn_ctf_names_free_all(&info->names);
	drgn_ctf_names_deinit(&info->names);
	drgn_ctf_enums_free_all(&info->enums);
	drgn_ctf_enums_deinit(&info->enums);
	drgn_ctf_dicts_close_all(&info->dicts);
	drgn_ctf_dicts_deinit(&info->dicts);
	ctf_arc_close(info->archive);
	free(info->ctf_data);
	free(info);
}

static void drgn_ctf_decref(void *arg)
{
	struct drgn_ctf_info *info = arg;
	if (--info->refcount)
		return;
	drgn_ctf_destroy(info);
}

struct drgn_error *
drgn_program_load_ctf(struct drgn_program *prog, const char *file)
{
	struct drgn_error *err;
	int errnum = 0;
	struct drgn_ctf_info *info = calloc(1, sizeof(*info));

	if (!info)
		return &drgn_enomem;

	info->tfind.destroy = drgn_ctf_decref;
	info->tfind.find = drgn_type_from_ctf;
	info->ofind.destroy = drgn_ctf_decref;
	info->ofind.find = drgn_ctf_find_object;

#ifdef WITH_LIBBFD
	info->archive = ctf_open(file, NULL, &errnum);
	if (!info->archive) {
		free(info);
		return drgn_error_format(DRGN_ERROR_OTHER, "ctf_open \"%s\": %s",
					 file, ctf_errmsg(errnum));
	}
#else
	ctf_sect_t data = {0};
	char *ctf_contents;

	err = read_ctf_buf(file, &ctf_contents, &data.cts_size);
	if (err)
		return err;
	data.cts_data = ctf_contents;

	info->ctf_data = ctf_contents;
	info->ctf_size = data.cts_size;
	info->archive = ctf_arc_bufopen(&data, NULL, NULL, &errnum);
	if (!info->archive) {
		free(info);
		return drgn_error_format(DRGN_ERROR_OTHER, "ctf_arc_bufopen \"%s\": %s",
					 file, ctf_errmsg(errnum));
	}
#endif
	info->prog = prog;
	/* In the future, we will set this based on a flag provided by libctf.
	 * It is not currently available, and all known CTF data uses the
	 * reversed array indices. */
	info->bug_reversed_array_indices = true;
	drgn_ctf_dicts_init(&info->dicts);
	drgn_ctf_enums_init(&info->enums);
	drgn_ctf_names_init(&info->names);
	drgn_ctf_type_map_init(&info->types);

	/*
	 * libctf offers the function "ctf_lookup_by_name()" which seems like a
	 * reasonable and efficient type lookup function. However, it doesn't
	 * really suit our cases for a few reasons:
	 *
	 * 1. Name lookup requires including the tag type (enum, struct, union).
	 *    If we want to search for types of any tag type, then we must
	 *    repeat the search several times.
	 * 2. Lookups search the child dict, and then they search the parent if
	 *    the type isn't found in the child. If you want to search all
	 *    dicts, there is no shortcut method, and this means you must redo
	 *    the search in the parent dict potentially hundreds of times.
	 * 3. There is no mechanism to return several matches. CTF does
	 *    sometimes have name collisions (especially with older versions
	 *    that don't handle bitfields using slices). It seems libctf doesn't
	 *    give guarantees about which result gets returned in those cases:
	 *    it's better for us to handle it manually.
	 *
	 * For these reasons, we will iterate over every dictionary and create a
	 * map of each type name to the type ID. libctf already has the type
	 * names allocated in memory, but we must create a hash table to contain
	 * roughly 60k named elements.
	 *
	 * While we iterate over each dictionary, we will also index enumerators
	 * (libctf doesn't contain an efficient lookup mechanism for these
	 * either).
	 */
	struct drgn_ctf_arg arg = {0};
	arg.info = info;

	/* Try to process vmlinux first so it's at the beginning of the hash
	 * lists */
	ctf_dict_t *d = ctf_dict_open(info->archive, "vmlinux", &errnum);
	if (d) {
		errnum = process_dict(d, "vmlinux", &arg);
		ctf_dict_close(d);
		if (errnum != 0) {
			err = arg.err;
			goto error;
		}
	}


	/* Now process the remaining dictionaries */
	errnum = ctf_archive_iter(info->archive, process_dict, &arg);
	if (errnum != 0) {
		if (!arg.err)
			arg.err = drgn_error_ctf(errnum);
		err = arg.err;
		goto error;
	}

	err = drgn_program_register_type_finder(prog, "ctf", &info->tfind, info,
						DRGN_HANDLER_REGISTER_ENABLE_LAST);
	if (err)
		goto error;
	info->refcount += 1;

	err = drgn_program_register_object_finder(prog, "ctf", &info->ofind, info,
						  DRGN_HANDLER_REGISTER_ENABLE_LAST);
	if (err)
		// Rare, but if we fail to register the object finder, after
		// already registering the type finder, then we're stuck.
		// We cannot unregister the type finder. The type finder's
		// destroy() callback will free the CTF info eventually, but in
		// the meantime we're in an in-between state. Log a warning.
		drgn_error_log_warning(prog, err, "failed to register object finder, but"
				       "type finder is already attached");
	else
		info->refcount += 1;

	return NULL;
error:
	drgn_ctf_destroy(info);
	return err;
}
