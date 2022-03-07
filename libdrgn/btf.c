// Copyright (c) 2022 Oracle and/or its affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "btf.h"
#include "drgn.h"
#include "lazy_object.h"
#include "memory_reader.h"
#include "program.h"

DEFINE_VECTOR(type_vector, struct btf_type *);

struct drgn_prog_btf {
	struct drgn_program *prog;

	/**
	 * Length of the BTF buffer in bytes.
	 */
	size_t len;

	/**
	 * BTF buffer.
	 */
	union {
		void *ptr;
		struct btf_header *hdr;
	};

	/**
	 * Pointer within the buffer to the "type" section.
	 */
	union {
		void *type;
		struct btf_type *tp;
	};

	/**
	 * Pointer within the buffer to the "strings" section.
	 */
	char *str;

	/**
	 * Array allowing us to map BTF type_id indexes to their location within
	 * the "type" section. This could certainly be compressed or optimized,
	 * but for now it is fine.
	 */
	struct type_vector index;

	struct drgn_type **cache;
};

const size_t DRGN_BTF_INDEX_INIT = 4096;

static inline uint32_t btf_kind(uint32_t info)
{
	return (info & 0x1F000000) >> 24;
}

static inline uint16_t btf_vlen(uint32_t info)
{
	return info & 0xFFFF;
}

static inline uint32_t btf_kind_flag(uint32_t info)
{
	return info & (1 << 31);
}

/**
 * Return the next btf_type entry after this one. In order to do this we must
 * add the offset of any supplemental data which follows this entry.
 */
static struct btf_type *btf_next(struct btf_type *tp)
{
	void *next = (void *)tp + sizeof(struct btf_type);

	switch (btf_kind(tp->info)) {
	case BTF_KIND_INT:
		return next + sizeof(uint32_t);

	case BTF_KIND_ARRAY:
		return next + sizeof(struct btf_array);

	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return next + btf_vlen(tp->info) * sizeof(struct btf_member);

	case BTF_KIND_ENUM:
		return next + btf_vlen(tp->info) * sizeof(struct btf_enum);

	case BTF_KIND_FUNC_PROTO:
		return next + btf_vlen(tp->info) * sizeof(struct btf_param);

	case BTF_KIND_VAR:
		return next + sizeof(struct btf_var);

	case BTF_KIND_DATASEC:
		return next + btf_vlen(tp->info) * sizeof(struct btf_var_secinfo);

	case BTF_KIND_DECL_TAG:
		return next + sizeof(struct btf_decl_tag);

	case BTF_KIND_PTR:
	case BTF_KIND_FWD:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		return next;

	default:
		UNREACHABLE();
	}
}

/**
 * Return true if this type pointer is past the end of the BTF type buffer.
 */
static inline bool btf_type_end(struct drgn_prog_btf *bf, struct btf_type *tp)
{
	return ((void *)tp - bf->type) >= bf->hdr->type_len;
}

/**
 * Index the BTF data for quick access.
 */
static struct drgn_error *drgn_btf_index(struct drgn_prog_btf *bf)
{
	struct btf_type *tp;
	for (tp = bf->tp; !btf_type_end(bf, tp); tp = btf_next(tp))
		if (!type_vector_append(&bf->index, &tp))
			return &drgn_enomem;
	return NULL;
}

const char *btf_str(struct drgn_prog_btf *bf, uint32_t off)
{
	if (off >= bf->hdr->str_len) {
		fprintf(stderr, "btf_str: BAD Offset: %d (str_len=%d)\n", off, bf->hdr->str_len);
		return "(BAD offset)";
	}
	return (const char *)&bf->str[off];
}

static uint32_t drgn_btf_lookup(struct drgn_prog_btf *bf, const char *name,
				size_t name_len, int desired_btf_kind)
{
	struct btf_type *tp;
	for (uint32_t i = 1; i < bf->index.size; i++) {
		tp = bf->index.data[i];
		if (btf_kind(tp->info) == desired_btf_kind &&
		    tp->name_off &&
		    strncmp(btf_str(bf, tp->name_off), name, name_len+1) == 0) {
			return i;
		}
	}
	return 0; /* void anyway */
}

static enum drgn_qualifiers
drgn_btf_resolve_qualifiers(struct drgn_prog_btf *bf, uint32_t idx, uint32_t *ret)
{
	enum drgn_qualifiers qual = 0;

	while (idx) {
		struct btf_type *tp = bf->index.data[idx];
		switch (btf_kind(tp->info)) {
		case BTF_KIND_CONST:
			qual |= DRGN_QUALIFIER_CONST;
			break;
		case BTF_KIND_RESTRICT:
			qual |= DRGN_QUALIFIER_RESTRICT;
			break;
		case BTF_KIND_VOLATILE:
			qual |= DRGN_QUALIFIER_VOLATILE;
			break;
		default:
			goto out;
		}
		idx = tp->type;
	}
out:
	*ret = idx;
	return qual;
}

static struct drgn_error *
drgn_btf_type_create(struct drgn_prog_btf *bf, uint32_t idx,
		     struct drgn_qualified_type *ret);

static struct drgn_error *
drgn_int_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
		       struct drgn_type **ret)
{
	uint32_t info;
	bool _signed, is_bool;
	struct drgn_error *rv;
	const char *name = btf_str(bf, tp->name_off);

	info = *(uint32_t *)(tp + 1);
	if (BTF_INT_OFFSET(info))
		return drgn_error_create(DRGN_ERROR_OTHER, "int encoding at non-zero offset not supported");
	_signed = BTF_INT_SIGNED & BTF_INT_ENCODING(info);
	is_bool = BTF_INT_BOOL & BTF_INT_ENCODING(info);
	if (is_bool)
		return drgn_bool_type_create(bf->prog, name, tp->size, DRGN_PROGRAM_ENDIAN, &drgn_language_c, ret);
	else
		return drgn_int_type_create(bf->prog, name, tp->size, _signed, DRGN_PROGRAM_ENDIAN, &drgn_language_c, ret);
}

static struct drgn_error *
drgn_pointer_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
			   struct drgn_type **ret)
{
	struct drgn_qualified_type pointed;
	struct drgn_error *err = NULL;

	err = drgn_btf_type_create(bf, tp->type, &pointed);

	if (err)
		return err;

	// TODO can't hardcode 8
	return drgn_pointer_type_create(bf->prog, pointed, 8, DRGN_PROGRAM_ENDIAN, &drgn_language_c, ret);
}

static struct drgn_error *
drgn_typedef_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
			   struct drgn_type **ret)
{
	struct drgn_qualified_type aliased;
	struct drgn_error *err;
	const char *name = btf_str(bf, tp->name_off);

	err = drgn_btf_type_create(bf, tp->type, &aliased);
	if (err)
		return err;

	return drgn_typedef_type_create(bf->prog, name, aliased, &drgn_language_c, ret);
}

struct drgn_btf_member_thunk_arg {
	struct btf_member *member;
	struct drgn_prog_btf *bf;
	uint64_t bit_field_size;
};

static uint64_t drgn_btf_lookup_bit_size(struct drgn_prog_btf *bf, uint32_t idx, uint64_t *offset)
{
	drgn_btf_resolve_qualifiers(bf, idx, &idx);
	struct btf_type *tp = bf->index.data[idx];
	uint32_t val;
	if (btf_kind(tp->info) != BTF_KIND_INT)
		return 0;

	// Integers themselves may encode bit size and offset
	val = *(uint32_t *)&tp[1];
	if (BTF_INT_OFFSET(val))
		*offset += BTF_INT_OFFSET(val);
	return BTF_INT_BITS(val);
}

static struct drgn_error *
drgn_btf_member_thunk_fn(struct drgn_object *res, void *arg_)
{
	struct drgn_btf_member_thunk_arg *arg = arg_;
	struct drgn_error *err;

	if (res) {
		struct drgn_qualified_type qualified_type;
		printf("THUNK: create type %d\n", arg->member->type);
		err = drgn_btf_type_create(arg->bf, arg->member->type, &qualified_type);
		if (err)
			return err;
		if (!arg->bit_field_size) {
			arg->bit_field_size = 8 * drgn_type_size(qualified_type.type);
		}
		err = drgn_object_set_absent(res, qualified_type, arg->bit_field_size);
		if (err)
			return err;
	}
	free(arg);
	return NULL;
}

static struct drgn_error *
drgn_compound_type_from_btf(struct drgn_prog_btf *bf, struct btf_type *tp,
			    struct drgn_type **ret)
{
	struct drgn_compound_type_builder builder;
	struct btf_member *members = (struct btf_member *)&tp[1];
	size_t vlen = btf_vlen(tp->info);
	enum drgn_type_kind kind = DRGN_TYPE_STRUCT;
	bool flag_bitfield_size_in_offset = btf_kind_flag(tp->info);
	struct drgn_error *err;
	const char *tag = NULL;

	if (btf_kind(tp->info) == BTF_KIND_UNION)
		kind = DRGN_TYPE_UNION;

	if (tp->name_off)
		tag = btf_str(bf, tp->name_off);

	drgn_compound_type_builder_init(&builder, bf->prog, kind);
	for (size_t i = 0; i < vlen; i++) {
		struct drgn_btf_member_thunk_arg *thunk_arg =
			malloc(sizeof(*thunk_arg));
		uint64_t bit_offset;
		const char *name = NULL;
		if (!thunk_arg)
			return &drgn_enomem;
		thunk_arg->member = &members[i];
		thunk_arg->bf = bf;
		if (flag_bitfield_size_in_offset) {
			bit_offset = BTF_MEMBER_BIT_OFFSET(members[i].offset);
			thunk_arg->bit_field_size = BTF_MEMBER_BITFIELD_SIZE(members[i].offset);
		} else {
			bit_offset = members[i].offset;
			thunk_arg->bit_field_size = drgn_btf_lookup_bit_size(bf, members[i].type, &bit_offset);
		}
		if (members[i].name_off)
			name = btf_str(bf, members[i].name_off);

		union drgn_lazy_object member_object;
		drgn_lazy_object_init_thunk(&member_object, bf->prog,
					    drgn_btf_member_thunk_fn, thunk_arg);

		err = drgn_compound_type_builder_add_member(&builder, &member_object,
							    name, bit_offset);
		if (err) {
			drgn_lazy_object_deinit(&member_object);
			return err;
		}
		printf(" added struct member %s ofset %lu!\n", name ? name : "(anonymous)", bit_offset);
	}
	return drgn_compound_type_create(&builder, tag, tp->size, true, &drgn_language_c, ret);
}

static struct drgn_error *
drgn_btf_type_create(struct drgn_prog_btf *bf, uint32_t idx,
		     struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	enum drgn_qualifiers qual = drgn_btf_resolve_qualifiers(bf, idx, &idx);
	struct btf_type *tp = bf->index.data[idx];

	printf("drgn_btf_type_create: %d\n", idx);

	if (bf->cache[idx]) {
		ret->qualifiers = qual;
		ret->type = bf->cache[idx];
		return NULL;
	}

	if (idx == 0) {
		ret->type = drgn_void_type(bf->prog, &drgn_language_c);
		ret->qualifiers = qual;
		bf->cache[idx] = ret->type;
		return NULL;
	}

	switch (btf_kind(tp->info)) {
	case BTF_KIND_INT:
		err = drgn_int_type_from_btf(bf, tp, &ret->type);
		break;
	case BTF_KIND_PTR:
		err = drgn_pointer_type_from_btf(bf, tp, &ret->type);
		break;
	case BTF_KIND_TYPEDEF:
		err = drgn_typedef_type_from_btf(bf, tp, &ret->type);
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		err = drgn_compound_type_from_btf(bf, tp, &ret->type);
		break;

	default:
		return &drgn_not_found;
	}
	if (!err) {
		ret->qualifiers = qual;
		bf->cache[idx] = ret->type;
	}
	return err;
}

static int drgn_btf_kind(enum drgn_type_kind kind)
{
	switch (kind) {
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
		return BTF_KIND_INT;
	case DRGN_TYPE_TYPEDEF:
		return BTF_KIND_TYPEDEF;
	case DRGN_TYPE_STRUCT:
		return BTF_KIND_STRUCT;
	case DRGN_TYPE_UNION:
		return BTF_KIND_UNION;
	case DRGN_TYPE_POINTER:
		return BTF_KIND_PTR;
	default:
		return -1;
	}
}

static struct drgn_error *
drgn_type_from_btf(enum drgn_type_kind kind, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret)
{
	uint32_t idx;
	struct drgn_prog_btf *bf = arg;
	int btf_kind = drgn_btf_kind(kind);

	if (btf_kind < 0)
		return &drgn_not_found;

	printf("drgn_type_from_btf: kind: %d name: %s\n", kind, name);
	idx = drgn_btf_lookup(bf, name, name_len, btf_kind);
	if (!idx)
		return &drgn_not_found;

	struct drgn_error *err = drgn_btf_type_create(bf, idx, ret);
	if (!err)
		printf("drgn_type_from_btf: return kind %d\n", ret->type->_private.kind);
	return err;
}

struct drgn_error *drgn_btf_init(struct drgn_program *prog, uint64_t start, uint64_t bytes)
{
	struct drgn_prog_btf *pbtf;
	struct drgn_error *err = NULL;
	struct btf_type *tp = NULL;

	pbtf = calloc(1, sizeof(*pbtf));
	if (!pbtf) {
		err = &drgn_enomem;
		goto out_free;
	}

	type_vector_init(&pbtf->index);

	/* Insert NULL entry at index 0 for the void type */
	if (!type_vector_append(&pbtf->index, &tp)) {
		err = &drgn_enomem;
		goto out_free;
	}

	pbtf->ptr = malloc(bytes);
	if (!pbtf->ptr) {
		err = &drgn_enomem;
		goto out_free;
	}

	err = drgn_memory_reader_read(&prog->reader, pbtf->ptr, start, bytes, false);
	if (err)
		goto out_free;


	if (pbtf->hdr->magic != BTF_MAGIC) {
		err = drgn_error_create(DRGN_ERROR_OTHER, "BTF header magic incorrect");
		goto out_free;
	}
	if (pbtf->hdr->hdr_len != sizeof(*pbtf->hdr)) {
		err = drgn_error_create(DRGN_ERROR_OTHER, "BTF header size mismatch");
		goto out_free;
	}
	if (pbtf->hdr->str_off + pbtf->hdr->str_len > bytes ||
	    pbtf->hdr->type_off + pbtf->hdr->type_len > bytes) {
		err = drgn_error_create(DRGN_ERROR_OTHER, "BTF offsets out of bounds");
		goto out_free;
	}
	pbtf->type = pbtf->ptr + pbtf->hdr->hdr_len + pbtf->hdr->type_off;
	pbtf->str = pbtf->ptr + pbtf->hdr->hdr_len + pbtf->hdr->str_off;
	pbtf->prog = prog;
	err = drgn_btf_index(pbtf);
	if (err)
		goto out_free;

	pbtf->cache = calloc(pbtf->index.size, sizeof(pbtf->cache));
	if (!pbtf->cache) {
		err = &drgn_enomem;
		goto out_free;
	}

	err = drgn_program_add_type_finder(prog, drgn_type_from_btf, pbtf);
	if (err)
		goto out_free;
	return err;
out_free:
	free(pbtf->cache);
	free(pbtf->ptr);
	type_vector_deinit(&pbtf->index);
	free(pbtf);
	return err;
}
