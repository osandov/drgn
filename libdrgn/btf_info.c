// Copyright (c) 2026 Oracle and/or its affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <errno.h>
#include <gelf.h>
#include <libelf.h>
#include <linux/btf.h>
#include <bpf/btf.h>
#include <stdint.h>

#include "btf_info.h"
#include "cleanup.h"
#include "debug_info.h"
#include "drgn.h"
#include "drgn_internal.h"
#include "elf_file.h"
#include "elf_symtab.h"
#include "error.h"
#include "hash_table.h"
#include "lazy_object.h"
#include "log.h"
#include "program.h"
#include "symbol.h"
#include "type.h"
#include "util.h"
#include "vector.h"

DEFINE_VECTOR_FUNCTIONS(drgn_btf_index_bucket);
DEFINE_HASH_MAP_FUNCTIONS(drgn_btf_index, c_string_key_hash_pair, c_string_key_eq);

// To allow compatibility with older libbpf versions, such as the 0.5.x version
// in Ubuntu 22.04 LTS, add this definition which we rely upon. This value has
// always been defined as a enum by the kernel, but is provided as a macro by
// libbpf since 1.0. Prior to that, we can provide it.
#ifndef BTF_KIND_ENUM64
#define BTF_KIND_ENUM64 19
#endif

// We can't detect whether btf_enum64 structures are present in the kernel
// headers, and for sufficiently old libbpf, we also cannot rely on helpers like
// btf_enum64(). Provide our own declaration.
struct drgn_btf_enum64 {
	struct btf_enum orig;
	uint32_t hi32;
};

static struct drgn_error *drgn_new_split_btf(const void *btf_data, uint32_t btf_data_size,
					     struct btf *base, struct btf **ret)
{
	// For many releases, libbpf declared but did not implement
	//   btf__new_split()
	// https://github.com/libbpf/libbpf/commit/5b7613e
	//
	// Despite it being trivial to implement, it cannot be easily done from
	// a libbpf client. As a result, we need this hack. Use it
	// unconditionally rather than detecting the missing function, so that
	// we get uniform behavior and easier testing.
	char template[] = "/tmp/drgn-btf-XXXXXX";
	int fd = mkstemp(template);
	int error;
	if (fd < 0)
		return drgn_error_create_os("cannot create BTF temp file", errno, NULL);

	_cleanup_fclose_ FILE *f = fdopen(fd, "w");
	if (!f) {
		error = errno;
		unlink(template);
		close(fd);
		return drgn_error_create_os("fopen", error, NULL);
	}

	if (fwrite(btf_data, 1, btf_data_size, f) != btf_data_size || fflush(f) != 0) {
		error = errno;
		unlink(template);
		return drgn_error_create_os("error writing BTF tmpfile", error, NULL);
	}

	struct btf *data = btf__parse_raw_split(template, base);
	error = errno;
	unlink(template);
	if (!data)
		return drgn_error_create_os("error parsing BTF", error, NULL);
	*ret = data;
	return NULL;
}

static inline struct drgn_error *drgn_new_btf(const void *btf_data, uint32_t btf_data_size,
					      struct btf **ret)
{
	struct btf *btf = btf__new(btf_data, (uint32_t)btf_data_size);
	if (!btf)
		return drgn_error_create_os("error parsing BTF", errno, NULL);
	*ret = btf;
	return NULL;
}

#if defined(LIBBPF_MAJOR_VERSION) && LIBBPF_MAJOR_VERSION >= 1
// In libbpf 1.0, btf__get_nr_types was replaced with btf__type_cnt().
// Let's define the old version and use it, so that we can compile on older
// libbpf versions.
static inline uint32_t btf__get_nr_types(const struct btf *btf)
{
	return btf__type_cnt(btf);
}
#endif

static inline uint32_t btf_kind_flag(uint32_t info)
{
	return info & (1 << 31);
}

static inline struct drgn_program *MBI_PROG(struct drgn_module_btf_info *mbi)
{
	return container_of(mbi, struct drgn_module, btf)->prog;
}

static inline struct drgn_program *BI_PROG(struct drgn_btf_info *bi)
{
	return container_of(bi, struct drgn_debug_info, btf)->prog;
}

static bool index_name(struct drgn_module *module, const char *name,
		       struct drgn_btf_index_item *value)
{
	struct hash_pair hp = drgn_btf_index_hash(&name);
	struct drgn_btf_index_iterator it =
		drgn_btf_index_search_hashed(&module->prog->dbinfo.btf.htab, &name, hp);
	if (it.entry && !drgn_btf_index_bucket_append(&it.entry->value, value)) {
		return false;
	} else if (!it.entry) {
		struct drgn_btf_index_entry entry;
		entry.key = name;
		drgn_btf_index_bucket_init(&entry.value);
		if (!drgn_btf_index_bucket_append(&entry.value, value) ||
		    drgn_btf_index_insert_searched(&module->prog->dbinfo.btf.htab,
						   &entry, hp, NULL) == -1) {
			drgn_btf_index_bucket_deinit(&entry.value);
			return false;
		}
	}
	return true;
}

static bool fixup_var(struct drgn_program *prog, const char *name,
		      uint32_t type_id, uint64_t addr)
{
	struct hash_pair hp = drgn_btf_index_hash(&name);
	struct drgn_btf_index_iterator it =
		drgn_btf_index_search_hashed(&prog->dbinfo.btf.htab, &name, hp);
	if (it.entry) {
		struct drgn_btf_index_bucket *l = &it.entry->value;
		for (uint32_t i = 0; i < drgn_btf_index_bucket_size(l); i++) {
			struct drgn_btf_index_item *e = drgn_btf_index_bucket_at(l, i);
			if (e->type_id == type_id) {
				e->addr = addr;
				e->is_present = 1;
				return true;
			}
		}
	}
	return false;
}

static char *vmlinux_section_symbol_name(const char *name)
{
	if (strcmp(name, ".data..percpu") == 0)
		return strdup("__per_cpu_start");
	else if (strcmp(name, ".data") == 0)
		return strdup("_sdata");
	else if (strcmp(name, ".bss") == 0)
		return strdup("__bss_start");
	else if (strcmp(name, ".brk") == 0)
		return strdup("_brk_start");

	char *new = malloc(strlen(name) + sizeof("__start_"));
	if (!new)
		return NULL;

	strcpy(new, "__start_");
	int out = sizeof("__start_") - 1;
	int in = 0;
	while (name[in] == '.')
		in++;
	while (name[in]) {
		if (name[in] == '.')
			new[out] = '_';
		else
			new[out] = name[in];
		out++;
		in++;
	}
	new[out] = '\0';
	return new;
}

static struct drgn_error *find_section_base(struct drgn_module *module,
					    const char *name,
					    uint64_t *ret)
{
	struct drgn_error *err;

	if (module->kind == DRGN_MODULE_MAIN
	    && (module->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
		_cleanup_free_ char *section = vmlinux_section_symbol_name(name);
		if (!section)
			return &drgn_enomem;

		_cleanup_symbol_ struct drgn_symbol *sym = NULL;
		err = drgn_program_find_symbol_by_name(module->prog, section, &sym);
		if (err)
			return err;

		*ret = sym->address;
		return NULL;
	} else if (module->kind == DRGN_MODULE_RELOCATABLE) {
		return drgn_module_get_section_address(module, name, ret);
	} else {
		UNREACHABLE();
	}
}

static struct drgn_error *find_symbol_addr(struct drgn_module *module,
                                           const char *name, uint64_t *ret)
{
	struct drgn_error *err;
	_cleanup_symbol_ struct drgn_symbol *sym = NULL;

	// If we have a loaded file, bypass the pluggable symbol finder and
	// directly access the module's symbols. This has the lowest chance of a
	// name conflict.
	if (module->loaded_file || module->debug_file) {
		enum drgn_find_symbol_flags flags =
			DRGN_FIND_SYMBOL_NAME | DRGN_FIND_SYMBOL_ONE;
		struct drgn_symbol_result_builder builder;
		drgn_symbol_result_builder_init(&builder, true);
		err = drgn_module_elf_symbols_search(module, name, 0, flags, &builder);
		if (err && !drgn_error_catch(&err, DRGN_ERROR_STOP))
			return err;
		if (!drgn_symbol_result_builder_count(&builder))
			return &drgn_not_found;
		sym = drgn_symbol_result_builder_single(&builder);
		*ret = sym->address;
		return NULL;
	}

	// Otherwise, use the global symbol finder
	err = drgn_program_find_symbol_by_name(module->prog, name, &sym);
	if (!err)
		*ret = sym->address;
	return err;
}

static struct drgn_error *index_enumerator(struct drgn_module *module,
					   uint32_t type_id,
					   const struct btf_type *tp)
{
	struct btf_enum *enum32 = btf_enum(tp);
	struct drgn_btf_enum64 *enum64 = (struct drgn_btf_enum64 *)enum32;
	struct drgn_btf_index_item value = {};
	value.is_enum = 1;
	value.type_id = type_id;
	value.module = module;
	bool is_enum64 = btf_kind(tp) == BTF_KIND_ENUM64;
	for (int i = 0; i < btf_vlen(tp); i++) {
		const char *enumname;
		if (is_enum64)
			enumname = btf__str_by_offset(module->btf.btf, enum64[i].orig.name_off);
		else
			enumname = btf__str_by_offset(module->btf.btf, enum32[i].name_off);
		value.index = i;
		if (!index_name(module, enumname, &value))
			return &drgn_enomem;
	}
	return NULL;
}

static struct drgn_error *index_datasec(struct drgn_module *module,
					uint32_t type_id,
					const struct btf_type *tp,
					const char *name)
{
	struct btf_var_secinfo *si = btf_var_secinfos(tp);
	uint64_t base;
	struct drgn_error *err = find_section_base(module, name, &base);

	// Not all sections base addresses will be found with a
	// corresponding symbol. Set a heuristic that it will be
	// an error if it is not an "init" section, or if the
	// section contains fewer than 10 variables.
	if (err == &drgn_not_found &&
		(btf_vlen(tp) < 10 || strstr(name, "init")))
		return NULL;
	else if (err)
		return err;

	for (int i = 0; i < btf_vlen(tp); i++) {
		const struct btf_type *var = btf__type_by_id(module->btf.btf, si[i].type);
		const char *varname = btf__str_by_offset(module->btf.btf, var->name_off);
		if (!fixup_var(module->prog, varname, si[i].type, base + si[i].offset))
			return drgn_error_format(
				DRGN_ERROR_OTHER,
				"cannot find variable from DATASEC '%s' (id: %u) (section '%s')",
				varname, si[i].type, name);
	}
	return NULL;
}

static struct drgn_error *index_btf(struct drgn_module *module)
{
	uint32_t start = 1;
	const struct btf *base = btf__base_btf(module->btf.btf);
	if (base)
		start = btf__get_nr_types(base);

	struct drgn_btf_info *dbi = &module->prog->dbinfo.btf;
	if (dbi->ofind_mode == DRGN_BTF_OFIND_UNSET) {
		if (module->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
			dbi->ofind_mode = DRGN_BTF_OFIND_DATASEC;
		else
			dbi->ofind_mode = DRGN_BTF_OFIND_SYMTAB;
	}

	for (uint32_t i = start; i < btf__get_nr_types(module->btf.btf); i++) {
		const struct btf_type *tp = btf__type_by_id(module->btf.btf, i);
		const char *name = btf__str_by_offset(module->btf.btf, tp->name_off);
		uint8_t kind = btf_kind(tp);

		// Hash the name -> type mapping
		if (name && name[0] && kind != BTF_KIND_DATASEC) {
			struct drgn_btf_index_item value = {};
			value.module = module;
			value.kind = btf_kind(tp);
			value.type_id = i;
			if (!index_name(module, name, &value))
				return &drgn_enomem;
		}

		// Hash enumerator and variable names
		if (kind == BTF_KIND_ENUM || kind == BTF_KIND_ENUM64) {
			struct drgn_error *err = index_enumerator(module, i, tp);
			if (err)
				return err;
		}
	}
	// Now, for each DATASEC, fix up the references to VARs with their
	// proper address. We have to do this in a second pass because a DATASEC
	// may reference VARs with type_ids greater than their own. Skip this
	// pass unless we're actually using the datasec for object finding.
	if (dbi->ofind_mode != DRGN_BTF_OFIND_DATASEC)
		return NULL;
	for (uint32_t i = start; i < btf__get_nr_types(module->btf.btf); i++) {
		const struct btf_type *tp = btf__type_by_id(module->btf.btf, i);
		const char *name = btf__str_by_offset(module->btf.btf, tp->name_off);
		uint8_t kind = btf_kind(tp);

		if (kind == BTF_KIND_DATASEC) {
			struct drgn_error *err = index_datasec(module, i, tp, name);
			if (err)
				return err;
		}
	}
	return NULL;
}

static void clear_btf_on_failure(struct drgn_module *module)
{
	struct drgn_btf_index_iterator it = drgn_btf_index_first(&module->prog->dbinfo.btf.htab);
	while (it.entry) {
		while (drgn_btf_index_bucket_size(&it.entry->value) &&
		       drgn_btf_index_bucket_last(&it.entry->value)->module == module)
			drgn_btf_index_bucket_pop(&it.entry->value);
		it = drgn_btf_index_next(it);
	}
}

static bool kind_match(uint64_t drgn_flags, const struct btf_type *tp)
{
	int kind = btf_kind(tp);
	uint32_t int_info;
	switch (kind) {
	case BTF_KIND_INT:
		int_info = *(uint32_t *)(tp + 1);
		if (BTF_INT_BOOL & int_info)
			return drgn_flags & (1 << DRGN_TYPE_BOOL);
		else
			return drgn_flags & (1 << DRGN_TYPE_INT);
	case BTF_KIND_PTR:
		return drgn_flags & (1 << DRGN_TYPE_POINTER);
	case BTF_KIND_ARRAY:
		return drgn_flags & (1 << DRGN_TYPE_ARRAY);
	case BTF_KIND_STRUCT:
		return drgn_flags & (1 << DRGN_TYPE_STRUCT);
	case BTF_KIND_UNION:
		return drgn_flags & (1 << DRGN_TYPE_UNION);
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		return drgn_flags & (1 << DRGN_TYPE_ENUM);
	case BTF_KIND_TYPEDEF:
		return drgn_flags & (1 << DRGN_TYPE_TYPEDEF);
	default:
		return false;
	}
}

/**
 * Follow the linked list of BTF qualifiers, combining them into a single
 * drgn_qualifiers, ending at the first non-qualifier type entry.
 * @param idx Starting index, which may be a qualifier
 * @param[out] ret Location to store the index of the first non-qualifier
 * @returns drgn_qualifiers with all relevant bits set
 */
static enum drgn_qualifiers
drgn_btf_resolve_qualifiers(struct btf *btf, uint32_t idx, uint32_t *ret)
{
	enum drgn_qualifiers qual = 0;

	while (idx) {
		const struct btf_type *tp = btf__type_by_id(btf, idx);
		switch (btf_kind(tp)) {
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
drgn_btf_type_create(struct drgn_module_btf_info *mbi, uint32_t idx,
		     struct drgn_qualified_type *ret);
static struct drgn_error *
drgn_type_from_btf(uint64_t flags, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret);

static struct drgn_error *
drgn_int_type_from_btf(struct drgn_module_btf_info *mbi, const struct btf_type *tp,
		       struct drgn_type **ret)
{
	uint32_t info;
	bool _signed, is_bool;
	const char *name = btf__str_by_offset(mbi->btf, tp->name_off);

	info = *(uint32_t *)(tp + 1);
	if (BTF_INT_OFFSET(info))
		return drgn_error_create(
			DRGN_ERROR_OTHER,
			"int encoding at non-zero offset not supported"
		);
	_signed = BTF_INT_SIGNED & BTF_INT_ENCODING(info);
	is_bool = BTF_INT_BOOL & BTF_INT_ENCODING(info);
	if (is_bool)
		return drgn_bool_type_create(MBI_PROG(mbi), name, tp->size,
					     DRGN_PROGRAM_ENDIAN,
					     &drgn_language_c, ret);
	else
		return drgn_int_type_create(MBI_PROG(mbi), name, tp->size, _signed,
					    DRGN_PROGRAM_ENDIAN,
					    &drgn_language_c, ret);
}

static struct drgn_error *
drgn_pointer_type_from_btf(struct drgn_module_btf_info *mbi, const struct btf_type *tp,
			   struct drgn_type **ret)
{
	struct drgn_qualified_type pointed;
	struct drgn_error *err = NULL;

	err = drgn_btf_type_create(mbi, tp->type, &pointed);

	if (err)
		return err;

	int pointer_size = btf__pointer_size(mbi->btf);
	return drgn_pointer_type_create(MBI_PROG(mbi), pointed, pointer_size,
					DRGN_PROGRAM_ENDIAN, &drgn_language_c,
					ret);
}

static struct drgn_error *
drgn_typedef_type_from_btf(struct drgn_module_btf_info *mbi, const struct btf_type *tp,
			   struct drgn_type **ret)
{
	struct drgn_qualified_type aliased;
	struct drgn_error *err;
	const char *name = btf__str_by_offset(mbi->btf, tp->name_off);

	err = drgn_btf_type_create(mbi, tp->type, &aliased);
	if (err)
		return err;

	return drgn_typedef_type_create(MBI_PROG(mbi), name, aliased,
					&drgn_language_c, ret);
}

struct drgn_btf_member_thunk_arg {
	struct btf_member *member;
	struct drgn_module_btf_info *mbi;
	uint64_t bit_field_size;
};

static struct drgn_error *
drgn_btf_member_thunk_fn(struct drgn_object *res, void *arg_)
{
	struct drgn_btf_member_thunk_arg *arg = arg_;
	struct drgn_error *err;

	if (res) {
		struct drgn_qualified_type qualified_type;
		err = drgn_btf_type_create(arg->mbi, arg->member->type,
					   &qualified_type);
		if (err)
			return err;
		err = drgn_object_set_absent(res, qualified_type,
					     DRGN_ABSENCE_REASON_OTHER,
					     arg->bit_field_size);
		if (err)
			return err;
	}
	free(arg);
	return NULL;
}

static struct drgn_error *
drgn_compound_type_from_btf(struct drgn_module_btf_info *mbi, const struct btf_type *tp,
			    struct drgn_type **ret)
{
	struct drgn_compound_type_builder builder;
	struct btf_member *members = btf_members(tp);
	size_t vlen = btf_vlen(tp);
	enum drgn_type_kind kind = DRGN_TYPE_STRUCT;
	struct drgn_error *err;
	const char *tag = NULL;

	if (btf_kind(tp) == BTF_KIND_UNION)
		kind = DRGN_TYPE_UNION;

	if (tp->name_off)
		tag = btf__str_by_offset(mbi->btf, tp->name_off);

	drgn_compound_type_builder_init(&builder, MBI_PROG(mbi), kind);
	for (size_t i = 0; i < vlen; i++) {
		struct drgn_btf_member_thunk_arg *thunk_arg =
			malloc(sizeof(*thunk_arg));
		const char *name = NULL;
		uint32_t bit_offset = btf_member_bit_offset(tp, i);
		if (!thunk_arg) {
			err = &drgn_enomem;
			goto out;
		}
		thunk_arg->member = &members[i];
		thunk_arg->mbi = mbi;
		thunk_arg->bit_field_size = btf_member_bitfield_size(tp, i);
		if (members[i].name_off)
			name = btf__str_by_offset(mbi->btf, members[i].name_off);

		union drgn_lazy_object member_object;
		drgn_lazy_object_init_thunk(&member_object, MBI_PROG(mbi),
					    drgn_btf_member_thunk_fn, thunk_arg);

		err = drgn_compound_type_builder_add_member(&builder,
							    &member_object,
							    name, bit_offset);
		if (err) {
			drgn_lazy_object_deinit(&member_object);
			goto out;
		}
	}
	err = drgn_compound_type_create(&builder, tag, tp->size, true,
					&drgn_language_c, ret);
	if (!err)
		return NULL;
out:
	drgn_compound_type_builder_deinit(&builder);
	return err;
}

static struct drgn_error *
drgn_array_type_from_btf(struct drgn_module_btf_info *mbi, const struct btf_type *tp,
			 struct drgn_type **ret)
{
	struct btf_array *arr = btf_array(tp);
	struct drgn_error *err;
	struct drgn_qualified_type qt;

	err = drgn_btf_type_create(mbi, arr->type, &qt);
	if (err)
		return err;

	if (arr->nelems)
		return drgn_array_type_create(MBI_PROG(mbi), qt, arr->nelems,
					      &drgn_language_c, ret);
	else
		return drgn_incomplete_array_type_create(MBI_PROG(mbi), qt,
							 &drgn_language_c, ret);
}

static struct drgn_error *
compatible_int(struct drgn_program *prog, bool signed_, uint64_t size, struct drgn_type **ret)
{
	// drgn won't allow an anonymous type, but BTF doesn't give us the
	// underlying type ID for an enum. So we need to make one up, and we
	// need to invent a name for it. Since BTF is kernel-specific, we'll use
	// the "{su}{8,16,32,64}" names. However, in reality, those are typedefs
	// in the kernel. This shouldn't really cause confusion, since you can't
	// lookup these integers by name.
	static const char *names[] = {
		"u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64",
	};
	int name_index = signed_ ? 4 : 0;
	switch (size) {
	case 1:
		name_index += 0;
		break;
	case 2:
		name_index += 1;
		break;
	case 4:
		name_index += 2;
		break;
	case 8:
		name_index += 3;
		break;
	default:
		return drgn_error_format(
			DRGN_ERROR_OTHER, "invalid BTF enum size: %" PRIu64, size);
	}
	return drgn_int_type_create(prog, names[name_index], size, signed_, DRGN_PROGRAM_ENDIAN,
				    &drgn_language_c, ret);
}

static struct drgn_error *
drgn_enum_type_from_btf(struct drgn_module_btf_info *mbi, const struct btf_type *tp,
			struct drgn_type **ret)
{
	struct drgn_error *err;
	struct drgn_enum_type_builder builder;
	const char *name = NULL;
	size_t count = btf_vlen(tp);
	bool signed_ = BTF_INFO_KFLAG(tp->info);
	struct drgn_type *type;

	if (tp->name_off)
		name = btf__str_by_offset(mbi->btf, tp->name_off);

	if (!count)
		/* no enumerators, incomplete type */
		return drgn_incomplete_enum_type_create(MBI_PROG(mbi), name,
							&drgn_language_c, ret);

	drgn_enum_type_builder_init(&builder, MBI_PROG(mbi));
	struct btf_enum *enum32 = btf_enum(tp);
	struct drgn_btf_enum64 *enum64 = (struct drgn_btf_enum64 *)enum32;
	bool is_enum64 = btf_kind(tp) == BTF_KIND_ENUM64;
	for (size_t i = 0; i < count; i++) {
		const char *mname;
		union {uint64_t u; int64_t s; } val;
		if (is_enum64) {
			mname = btf__str_by_offset(mbi->btf, enum64[i].orig.name_off);
			// Sign extension is already done, just assemble this
			// into the unsigned integer field and let the union
			// reinterpret it as necessary.
			val.u = (uint64_t)enum64[i].hi32 << 32;
			val.u |= (uint64_t)enum64[i].orig.val;
		} else {
			mname = btf__str_by_offset(mbi->btf, enum32[i].name_off);
			// For a signed value, do sign extension. For unsigned
			// values, don't.
			if (signed_)
				val.s = enum32[i].val;
			else
				val.u = enum32[i].val;
		}
		if (signed_)
			err = drgn_enum_type_builder_add_signed(&builder,
								mname,
								val.s);
		else
			err = drgn_enum_type_builder_add_unsigned(&builder,
								  mname,
								  val.u);
		if (err)
			goto out;
	}
	err = compatible_int(MBI_PROG(mbi), signed_, tp->size, &type);
	if (err)
		goto out;

	err = drgn_enum_type_create(&builder, name, type,
				    &drgn_language_c, ret);
	if (!err)
		return NULL;
out:
	drgn_enum_type_builder_deinit(&builder);
	return err;
}

struct drgn_btf_param_thunk_arg {
	struct btf_param *param;
	struct drgn_module_btf_info *mbi;
};

static struct drgn_error *
drgn_btf_param_thunk_fn(struct drgn_object *res, void *arg_)
{
	struct drgn_btf_param_thunk_arg *arg = arg_;
	struct drgn_error *err;

	if (res) {
		struct drgn_qualified_type qualified_type;

		err = drgn_btf_type_create(arg->mbi, arg->param->type,
					   &qualified_type);
		if (err)
			return err;

		err = drgn_object_set_absent(res, qualified_type,
					     DRGN_ABSENCE_REASON_OTHER, 0);
		if (err)
			return err;
	}
	free(arg);
	return NULL;
}

static struct drgn_error *
drgn_func_proto_type_from_btf(struct drgn_module_btf_info *mbi, const struct btf_type *tp,
			      struct drgn_type **ret)
{
	struct drgn_error *err = NULL;
	struct drgn_function_type_builder builder;
	bool is_variadic = false;
	struct drgn_qualified_type return_type;
	size_t num_params = btf_vlen(tp);
	struct btf_param *params = btf_params(tp);

	err = drgn_btf_type_create(mbi, tp->type, &return_type);
	if (err)
		return err;

	drgn_function_type_builder_init(&builder, MBI_PROG(mbi));
	for (size_t i = 0; i < num_params; i++) {
		const char *name = NULL;
		union drgn_lazy_object param_object;
		struct drgn_btf_param_thunk_arg *arg;

		if (i + 1 == num_params && !params[i].name_off
		    && !params[i].type) {
			is_variadic = true;
			break;
		}
		name = btf__str_by_offset(mbi->btf, params[i].name_off);

		arg = malloc(sizeof(*arg));
		if (!arg) {
			err = &drgn_enomem;
			goto out;
		}
		arg->mbi = mbi;
		arg->param = &params[i];
		drgn_lazy_object_init_thunk(&param_object, MBI_PROG(mbi),
					    drgn_btf_param_thunk_fn, arg);
		err = drgn_function_type_builder_add_parameter(&builder,
							       &param_object,
							       name);
		if (err) {
			free(arg);
			goto out;
		}
	}
	err = drgn_function_type_create(&builder, return_type, is_variadic,
					&drgn_language_c, ret);
	if (!err)
		return NULL;
out:
	drgn_function_type_builder_deinit(&builder);
	return err;
}

/**
 * Create a BTF type given its index within the the type buffer.
 *
 * This is the main workhorse function for loading BTF types into drgn. It
 * assumes you've already looked up the name for a type and resolved it into a
 * type_id / idx.
 *
 * All struct drgn_type created by this function are cached, but qualifiers are
 * not, since they are trivial to resolve each time.
 *
 * @param bf Pointer to BTF registry
 * @param idx Index of type in the type section
 * @param[out] ret On success, set to the qualified type
 * @returns NULL on success, or an error pointer
 */
static struct drgn_error *
drgn_btf_type_create(struct drgn_module_btf_info *mbi, uint32_t idx,
		     struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	enum drgn_qualifiers qual = drgn_btf_resolve_qualifiers(mbi->btf, idx, &idx);
	const struct btf_type *tp = btf__type_by_id(mbi->btf, idx);

	if (mbi->cache[idx]) {
		ret->qualifiers = qual;
		ret->type = mbi->cache[idx];
		return NULL;
	}

	if (idx == 0) {
		ret->type = drgn_void_type(MBI_PROG(mbi), &drgn_language_c);
		ret->qualifiers = qual;
		mbi->cache[idx] = ret->type;
		return NULL;
	}

	switch (btf_kind(tp)) {
	case BTF_KIND_INT:
		err = drgn_int_type_from_btf(mbi, tp, &ret->type);
		break;
	case BTF_KIND_PTR:
		err = drgn_pointer_type_from_btf(mbi, tp, &ret->type);
		break;
	case BTF_KIND_TYPEDEF:
		err = drgn_typedef_type_from_btf(mbi, tp, &ret->type);
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		err = drgn_compound_type_from_btf(mbi, tp, &ret->type);
		break;
	case BTF_KIND_ARRAY:
		err = drgn_array_type_from_btf(mbi, tp, &ret->type);
		break;
	case BTF_KIND_ENUM:
		err = drgn_enum_type_from_btf(mbi, tp, &ret->type);
		break;
	case BTF_KIND_FUNC_PROTO:
		err = drgn_func_proto_type_from_btf(mbi, tp, &ret->type);
		break;
	default:
		return &drgn_not_found;
	}
	if (!err) {
		ret->qualifiers = qual;
		mbi->cache[idx] = ret->type;
	}
	return err;
}

/**
 * The drgn type finder for BTF.
 *
 * In order to lookup a type by name, we translate the type kind into a BTF type
 * kind, search for a type entry of the same name and kind, and then use the
 * general purpose drgn_btf_type_create() function to do the heavy lifting.
 * Since BTF encodes no information about compilation units or source filenames,
 * we always ignore @a filename.
 *
 * @param flags Bits set for each type kind drgn may want
 * @param name Type name to search
 * @param name_len Length of @a name (not including nul terminator)
 * @param filename Source filename of type (ignored)
 * @param arg Pointer to struct drgn_prog_btf of this program.
 * @param ret Output a qualified type
 * @returns NULL on success. On error, an appropriate struct drgn_error.
 */
static struct drgn_error *
drgn_type_from_btf(uint64_t flags, const char *name,
		   size_t name_len, const char *filename,
		   void *arg, struct drgn_qualified_type *ret)
{
	struct drgn_btf_info *bf = arg;

	_cleanup_free_ char *name_copy = strndup(name, name_len);
	struct drgn_btf_index_iterator it =
		drgn_btf_index_search(&bf->htab, (const char **)&name_copy);
	if (!it.entry)
		return &drgn_not_found;

	struct drgn_btf_index_bucket *l = &it.entry->value;
	for (int i = 0; i < drgn_btf_index_bucket_size(l); i++) {
		struct drgn_btf_index_item *entry = drgn_btf_index_bucket_at(l, i);
		const struct btf_type *tp = btf__type_by_id(entry->module->btf.btf,
							    entry->type_id);

		if (!tp->name_off)
			continue;
		if (!kind_match(flags, tp))
			continue;

		return drgn_btf_type_create(&entry->module->btf, entry->type_id, ret);
	}
	return &drgn_not_found;
}

static struct drgn_error *
make_constant(struct drgn_btf_index_item *entry, struct drgn_object *ret)
{
	struct drgn_module_btf_info *mbi = &entry->module->btf;
	struct drgn_qualified_type qt;
	const struct btf_type *tp = btf__type_by_id(mbi->btf, entry->type_id);
	union {uint64_t u; int64_t s; } val;
	bool signed_;

	signed_ = BTF_INFO_KFLAG(tp->info);
	if (btf_kind(tp) == BTF_KIND_ENUM) {
		struct btf_enum *enum32 = (struct btf_enum *)&tp[1];
		if (signed_)
			val.s = enum32[entry->index].val;
		else
			val.u = enum32[entry->index].val;
	} else if (btf_kind(tp) == BTF_KIND_ENUM64) {
		struct drgn_btf_enum64 *enum64 = (struct drgn_btf_enum64 *)&tp[1];
		val.u = (uint64_t)enum64[entry->index].hi32 << 32;
		val.u |= (uint64_t)enum64[entry->index].orig.val;
	} else {
		assert(false);
	}
	struct drgn_error *err = drgn_btf_type_create(mbi, entry->type_id, &qt);
	if (err)
		return err;
	if (signed_)
		return drgn_object_set_signed(ret, qt, val.s, 0);
	else
		return drgn_object_set_unsigned(ret, qt, val.u, 0);
}

static struct drgn_error *
make_function(const char *name, struct drgn_btf_index_item *entry, struct drgn_object *ret)
{
	struct drgn_module_btf_info *mbi = &entry->module->btf;
	const struct btf_type *tp = btf__type_by_id(mbi->btf, entry->type_id);
	uint64_t addr;

	struct drgn_error *err =
		find_symbol_addr(entry->module, name, &addr);
	if (err)
		return err;

	struct drgn_qualified_type qt;
	err = drgn_btf_type_create(mbi, tp->type, &qt);
	if (err) {
		return err;
	}
	return drgn_object_set_reference(ret, qt, addr, 0, 0);
}

static struct drgn_error *
make_variable(struct drgn_btf_info *dbi, const char *name,
              struct drgn_btf_index_item *entry, struct drgn_object *ret)
{
	struct drgn_module *mod = entry->module;
	struct drgn_error *err;
	uint64_t address;

	if (dbi->ofind_mode == DRGN_BTF_OFIND_DATASEC) {
		if (!entry->is_present)
			return drgn_error_format(DRGN_ERROR_OTHER,
						"address information for \"%s\" is not present in a BTF DATASEC",
						name);
		else
			address = entry->addr;
	} else if (dbi->ofind_mode == DRGN_BTF_OFIND_SYMTAB) {
		err = find_symbol_addr(mod, name, &address);
		if (err)
			return err;
	} else {
		return &drgn_not_found;
	}
	const struct btf_type *tp = btf__type_by_id(mod->btf.btf, entry->type_id);
	struct drgn_qualified_type qt;
	err = drgn_btf_type_create(&mod->btf, tp->type, &qt);
	if (err)
		return err;
	return drgn_object_set_reference(ret, qt, address, 0, 0);
}

static struct drgn_error *drgn_btf_object_find(
	const char *name, size_t name_len, const char *filename,
	enum drgn_find_object_flags flags, void *arg, struct drgn_object *ret)
{
	struct drgn_btf_info *bi = arg;
	_cleanup_free_ char *name_copy = strndup(name, name_len);
	struct drgn_btf_index_iterator it =
		drgn_btf_index_search(&bi->htab, (const char **)&name_copy);
	if (!it.entry)
		return &drgn_not_found;

	struct drgn_btf_index_bucket *l = &it.entry->value;
	for (int i = 0; i < drgn_btf_index_bucket_size(l); i++) {
		struct drgn_btf_index_item *entry = drgn_btf_index_bucket_at(l, i);
		if (entry->is_enum && (flags & DRGN_FIND_OBJECT_CONSTANT)) {
			return make_constant(entry, ret);
		} else if (entry->kind == BTF_KIND_VAR &&
			   (flags & DRGN_FIND_OBJECT_VARIABLE)) {
			return make_variable(bi, name, entry, ret);
		} else if (entry->kind == BTF_KIND_FUNC &&
			   (flags & DRGN_FIND_OBJECT_FUNCTION)) {
			return make_function(name, entry, ret);
		}
	}
	return &drgn_not_found;
}

void drgn_module_btf_info_deinit(struct drgn_module *module)
{
	free(module->btf.cache);
	btf__free(module->btf.btf);
	module->btf.btf = NULL;
	module->btf.cache = NULL;
}

static struct drgn_error *
find_btf_section(struct drgn_elf_file *file, const void **data_ret, size_t *size_ret)
{
	Elf_Scn *scn = NULL;
	size_t shstrndx;

	if (elf_getshdrstrndx(file->elf, &shstrndx))
		return drgn_error_libelf();

	while ((scn = elf_nextscn(file->elf, scn))) {
		GElf_Shdr shdr_mem, *shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			return drgn_error_libelf();
		const char *scnname = elf_strptr(file->elf, shstrndx, shdr->sh_name);
		if (!scnname)
			return drgn_error_libelf();
		if (strcmp(scnname, ".BTF") != 0)
			continue;
		Elf_Data *btf_contents;
		struct drgn_error *err = read_elf_section(scn, &btf_contents);
		if (err)
			return err;
		*data_ret = btf_contents->d_buf;
		*size_ret = btf_contents->d_size;
		return NULL;
	}
	return &drgn_not_found;
}

struct drgn_error *
drgn_module_load_btf(struct drgn_module *module, const void *btf_data,
                     size_t btf_data_size, bool main_module_base)
{
	struct drgn_program *prog = module->prog;
	if (module->btf.btf)
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "BTF is already loaded for this module");

	struct btf *base = NULL;
	if (main_module_base) {
		if (!prog->dbinfo.main_module || !prog->dbinfo.main_module->btf.btf)
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "BTF is not loaded for the main module");
		base = prog->dbinfo.main_module->btf.btf;
	}

	// When BTF data is not provided, we can search for it in the loaded and
	// debug files. This could be useful for kernel or userspace programs.
	bool checked_loaded, checked_debug;
	const char *source = btf_data ? "user input" : NULL;
	struct drgn_error *err;
	if (!btf_data && !(module->loaded_file || module->debug_file))
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
		                         "%s: no BTF data provided and no loaded/debug file present",
		                         module->name);
	if (!btf_data && module->loaded_file) {
		checked_loaded = true;
		err = find_btf_section(module->loaded_file, &btf_data, &btf_data_size);
		if (err && !drgn_error_catch(&err, DRGN_ERROR_LOOKUP))
			return err;
		if (btf_data)
			source = "loaded file";
	}
	if (!btf_data && module->debug_file) {
		checked_debug = true;
		err = find_btf_section(module->debug_file, &btf_data, &btf_data_size);
		if (err && !drgn_error_catch(&err, DRGN_ERROR_LOOKUP))
			return err;
		if (btf_data)
			source = "debug file";
	}
	if (!btf_data)
		return drgn_error_format(DRGN_ERROR_MISSING_DEBUG_INFO,
		                         "%s: no .BTF section found (checked:%s%s%s)",
		                         module->name,
		                         checked_loaded ? " loaded" : "",
		                         (checked_loaded && checked_debug) ? " and" : "",
		                         checked_debug ? " debug" : "");

	if (btf_data_size > UINT32_MAX)
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
		                         "%s: BTF too large: %zu",
		                         module->name, btf_data_size);

	struct btf *btf = NULL;
	if (base)
		err = drgn_new_split_btf(btf_data, (uint32_t) btf_data_size, base, &btf);
	else
		err = drgn_new_btf(btf_data, (uint32_t)btf_data_size, &btf);
	if (err)
		return err;

	struct drgn_type **cache =
		calloc(btf__get_nr_types(btf), sizeof(*cache));
	if (!cache) {
		btf__free(btf);
		return &drgn_enomem;
	}

	module->btf.btf = btf;
	module->btf.cache = cache;
	err = index_btf(module);
	if (err) {
		clear_btf_on_failure(module);
		drgn_module_btf_info_deinit(module);
		return err;
	}
	drgn_log_debug(prog, "%s: loaded BTF from %s", module->name, source);
	return NULL;
}

void drgn_btf_info_init(struct drgn_debug_info *dbi)
{
	drgn_btf_index_init(&dbi->btf.htab);
	const struct drgn_type_finder_ops type_finder_ops = {
		.find = drgn_type_from_btf,
	};
	drgn_program_register_type_finder_impl(dbi->prog, &dbi->btf.type_finder,
					"btf", &type_finder_ops,
					&dbi->btf, 0);
	const struct drgn_object_finder_ops object_finder_ops = {
		.find = drgn_btf_object_find,
	};
	drgn_program_register_object_finder_impl(dbi->prog, &dbi->btf.object_finder,
						"btf", &object_finder_ops,
						&dbi->btf, 0);
}

void drgn_btf_info_deinit(struct drgn_debug_info *dbi)
{
	// The name map values are a dynamically allocated vector of entries,
	// free them before deinit.
	struct drgn_btf_index_iterator it = drgn_btf_index_first(&dbi->btf.htab);
	while (it.entry) {
		drgn_btf_index_bucket_deinit(&it.entry->value);
		it = drgn_btf_index_next(it);
	}
	drgn_btf_index_deinit(&dbi->btf.htab);
}
