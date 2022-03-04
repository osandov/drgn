// Copyright (c) 2022 Oracle and/or its affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drgn.h"
#include "program.h"
#include "memory_reader.h"
#include "btf.h"

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

static struct btf_type *drgn_btf_lookup(struct drgn_prog_btf *bf, const char *name,
					size_t name_len, int desired_btf_kind)
{
	struct btf_type *tp;
	for (size_t i = 1; i < bf->index.size; i++) {
		tp = bf->index.data[i];
		if (btf_kind(tp->info) == desired_btf_kind &&
		    tp->name_off &&
		    strncmp(btf_str(bf, tp->name_off), name, name_len) == 0) {
			return bf->index.data[i];
		}
	}
	return NULL;
}

static struct drgn_error *
drgn_int_type_from_btf(struct drgn_prog_btf *bf, const char *name, size_t name_len,
		       struct drgn_qualified_type *ret)
{
	struct btf_type *tp = drgn_btf_lookup(bf, name, name_len, BTF_KIND_INT);
	uint32_t info;
	bool _signed, is_bool;

	if (!tp) {
		printf("drgn_int_type_from_btf: not found\n");
		return &drgn_not_found;
	}

	info = *(uint32_t *)(tp + 1);
	if (BTF_INT_OFFSET(info))
		return drgn_error_create(DRGN_ERROR_OTHER, "int encoding at non-zero offset not supported");
	_signed = BTF_INT_SIGNED & BTF_INT_ENCODING(info);
	is_bool = BTF_INT_BOOL & BTF_INT_ENCODING(info);
	if (is_bool)
		return drgn_bool_type_create(bf->prog, name, tp->size, DRGN_PROGRAM_ENDIAN, &drgn_language_c, &ret->type);
	else
		return drgn_int_type_create(bf->prog, name, tp->size, _signed, DRGN_PROGRAM_ENDIAN, &drgn_language_c, &ret->type);
}

static struct drgn_error *
drgn_type_from_btf(enum drgn_type_kind kind, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret)
{
	struct btf_type *tp;
	struct drgn_prog_btf *bf = arg;

	printf("drgn_type_from_btf: %d, \"%s\", %p\n", kind, name, ret);

	switch (kind) {
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
		return drgn_int_type_from_btf(bf, name, name_len, ret);
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
		break;
	default:
		break;
	}
	printf("drgn_type_from_btf: not found\n");
	return &drgn_not_found;
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

	err = drgn_program_add_type_finder(prog, drgn_type_from_btf, pbtf);
	if (err)
		goto out_free;
	return err;
out_free:
	free(pbtf->ptr);
	type_vector_deinit(&pbtf->index);
	free(pbtf);
	return err;
}
