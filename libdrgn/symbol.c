// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <elf.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "binary_search.h"
#include "drgn_internal.h"
#include "string_builder.h"
#include "symbol.h"
#include "util.h"

DEFINE_VECTOR_FUNCTIONS(symbol_vector);

LIBDRGN_PUBLIC void drgn_symbol_destroy(struct drgn_symbol *sym)
{
	if (sym && sym->lifetime == DRGN_LIFETIME_STATIC)
		return;
	if (sym && sym->name_lifetime == DRGN_LIFETIME_OWNED)
		/* Cast here is necessary - we want symbol users to
		 * never modify sym->name, but when we own the name,
		 * we must modify it by freeing it. */
		free((char *)sym->name);
	free(sym);
}

LIBDRGN_PUBLIC void drgn_symbols_destroy(struct drgn_symbol **syms,
					 size_t count)
{
	for (size_t i = 0; i < count; i++)
		drgn_symbol_destroy(syms[i]);
	free(syms);
}

void drgn_symbol_from_elf(const char *name, uint64_t address,
			  const GElf_Sym *elf_sym, struct drgn_symbol *ret)
{
	ret->name = name;
	ret->name_lifetime = DRGN_LIFETIME_STATIC;
	ret->lifetime = DRGN_LIFETIME_OWNED;
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

struct drgn_error *
drgn_symbol_copy(struct drgn_symbol *dst, struct drgn_symbol *src)
{
	if (src->name_lifetime == DRGN_LIFETIME_STATIC) {
		dst->name = src->name;
		dst->name_lifetime = DRGN_LIFETIME_STATIC;
	} else {
		dst->name = strdup(src->name);
		if (!dst->name)
			return &drgn_enomem;
		dst->name_lifetime = DRGN_LIFETIME_OWNED;
	}
	dst->address = src->address;
	dst->size = src->size;
	dst->kind = src->kind;
	dst->binding = src->binding;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_symbol_create(const char *name, uint64_t address, uint64_t size,
		   enum drgn_symbol_binding binding, enum drgn_symbol_kind kind,
		   enum drgn_lifetime name_lifetime, struct drgn_symbol **ret)
{
	struct drgn_symbol *sym = malloc(sizeof(*sym));
	if (!sym)
		return &drgn_enomem;
	sym->name = name;
	sym->address = address;
	sym->size = size;
	sym->binding = binding;
	sym->kind = kind;
	sym->name_lifetime = name_lifetime;
	sym->lifetime = DRGN_LIFETIME_OWNED;
	*ret = sym;
	return NULL;
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

DEFINE_VECTOR_FUNCTIONS(symbolp_vector);

LIBDRGN_PUBLIC bool
drgn_symbol_result_builder_add(struct drgn_symbol_result_builder *builder,
			       struct drgn_symbol *symbol)
{
	if (builder->one) {
		if (builder->single)
			drgn_symbol_destroy(builder->single);
		builder->single = symbol;
	} else if (!symbolp_vector_append(&builder->vector, &symbol)) {
		return false;
	}
	return true;
}

LIBDRGN_PUBLIC size_t
drgn_symbol_result_builder_count(const struct drgn_symbol_result_builder *builder)
{
	if (builder->one)
		return builder->single ? 1 : 0;
	else
		return symbolp_vector_size(&builder->vector);
}

void drgn_symbol_result_builder_init(struct drgn_symbol_result_builder *builder,
				     bool one)
{
	memset(builder, 0, sizeof(*builder));
	builder->one = one;
	if (!one)
		symbolp_vector_init(&builder->vector);
}

void drgn_symbol_result_builder_abort(struct drgn_symbol_result_builder *builder)
{
	if (builder->one) {
		drgn_symbol_destroy(builder->single);
	} else {
		vector_for_each(symbolp_vector, symbolp, &builder->vector)
			drgn_symbol_destroy(*symbolp);
		symbolp_vector_deinit(&builder->vector);
	}
}

struct drgn_symbol *
drgn_symbol_result_builder_single(struct drgn_symbol_result_builder *builder)
{
	return builder->single;
}

void drgn_symbol_result_builder_array(struct drgn_symbol_result_builder *builder,
				      struct drgn_symbol ***syms_ret, size_t *count_ret)
{
	symbolp_vector_shrink_to_fit(&builder->vector);
	symbolp_vector_steal(&builder->vector, syms_ret, count_ret);
}

static int name_compar(const void *lhs, const void *rhs, void *arg)
{
	struct drgn_symbol_index *ix = arg;
	uint32_t left_ix = *(const uint32_t *)lhs;
	uint32_t right_ix = *(const uint32_t *)rhs;
	return strcmp(ix->symbols[left_ix].name, ix->symbols[right_ix].name);
}

static int addr_compar(const void *lhs, const void *rhs)
{
	const struct drgn_symbol *left = lhs;
	const struct drgn_symbol *right = rhs;
	// returning a simple subtraction would not work well since these are
	// unsigned
	if (left->address < right->address)
		return -1;
	else if (left->address > right->address)
		return 1;
	else
		return 0;
}

struct drgn_error *
drgn_symbol_index_init(struct drgn_symbol *symbols, uint32_t count,
		       char *buffer, struct drgn_symbol_index *ret)
{
	ret->symbols = symbols;
	ret->num_syms = count;
	ret->strings = buffer;
	ret->name_sort = NULL;
	ret->max_addrs = NULL;
	drgn_symbol_name_table_init(&ret->htab);
	ret->name_sort = malloc_array(count, sizeof(ret->name_sort[0]));
	if (!ret->name_sort)
		goto enomem;
	ret->max_addrs = malloc_array(count, sizeof(ret->max_addrs[0]));
	if (!ret->max_addrs)
		goto enomem;

	// In many cases (e.g kallsyms), symbols are already sorted by address,
	// but not always.  Check whether sorted, and if not, sort.
	for (uint32_t i = 1; i < ret->num_syms; i++) {
		if (ret->symbols[i - 1].address > ret->symbols[i].address) {
			qsort(ret->symbols, count, sizeof(ret->symbols[0]), addr_compar);
			break;
		}
	}

	// Kallsyms doesn't include symbol lengths, so symbols are
	// non-overlapping. But this is not true in general! Symbols may
	// overlap, which makes address lookup complicated. Rather than using a
	// complex range data structure, we can use two binary searches, one to
	// find the first symbol which could overlap with an address, and one to
	// find the last symbol, and then linearly search that array. This
	// performs poorly if there are symbols which span many others, but
	// that's a rare case. In order to do this strategy, we need an array
	// that contains the maximum address spanned by any symbol at or before
	// that index.
	if (ret->num_syms > 0) // in case num_syms == 0
		ret->max_addrs[0] = ret->symbols[0].address + ret->symbols[0].size;
	for (uint32_t i = 1; i < ret->num_syms; i++) {
		uint64_t max_addr = ret->symbols[i].address + ret->symbols[i].size;
		ret->max_addrs[i] = max(ret->max_addrs[i - 1], max_addr);
	}

	// Sort the "name_sort" array by name so we get runs of symbols with the
	// same name
	for (uint32_t i = 0; i < ret->num_syms; i++)
		ret->name_sort[i] = i;
	qsort_arg(ret->name_sort, ret->num_syms, sizeof(ret->name_sort[0]),
		  name_compar, ret);

	// For each unique symbol name, insert the range of symbol indexes
	// into the hash table for fast name lookup
	struct drgn_symbol_name_table_entry entry;
	uint32_t current = 0;
	while (current < ret->num_syms) {
		const char *current_str = ret->symbols[ret->name_sort[current]].name;
		uint32_t next = current + 1;
		while (next < ret->num_syms) {
			const char *next_str = ret->symbols[ret->name_sort[next]].name;
			if (strcmp(current_str, next_str) != 0)
				break;
			next++;
		}

		entry.key = current_str;
		entry.value.start = current;
		entry.value.end = next;
		if (drgn_symbol_name_table_insert(&ret->htab, &entry, NULL) < 0)
			goto enomem;

		current = next;
	}
	return NULL;

enomem:
	drgn_symbol_index_deinit(ret);
	return &drgn_enomem;
}

void
drgn_symbol_index_deinit(struct drgn_symbol_index *index)
{
	// The symbol array is contiguous and all names come from strings
	free(index->symbols);
	free(index->max_addrs);
	drgn_symbol_name_table_deinit(&index->htab);
	free(index->strings);
	free(index->name_sort);
	// Simplify error handling by ensuring deinit is safe to call twice
	memset(index, 0, sizeof(*index));
}

static void address_search_range(struct drgn_symbol_index *index, uint64_t address,
				 uint32_t *start_ret, uint32_t *end_ret)
{
	// First, identify the maximum symbol index which could possibly contain
	// this address. Think of this as:
	//   end_ret = bisect_right([s.address for s in symbols], address)
	#define less_than_start(a, b) (*(a) < (b)->address)
	*end_ret = binary_search_gt(index->symbols, index->num_syms, &address,
				    less_than_start);
	#undef less_than_start

	// Second, identify first symbol index which could possibly contain this
	// address. We need to use "max_addrs" for this task:
	//    bisect_right(max_addrs, address)
	#define less_than_end(a, b) (*(a) < *(b))
	*start_ret = binary_search_gt(index->max_addrs, index->num_syms, &address,
				    less_than_end);
	#undef less_than_end
}

struct drgn_error *
drgn_symbol_index_find(const char *name, uint64_t address,
		       enum drgn_find_symbol_flags flags, void *arg,
		       struct drgn_symbol_result_builder *builder)
{
	struct drgn_symbol_index *index = arg;

	// Unlike the ELF symbol finder, we don't have any particular rules
	// about which symbols get priority when looking up a single symbol.
	// If we decide this logic is critical, it would probably make sense to
	// move it into the symbol finder's API via the result builder, rather
	// than reimplementing it here.

	if (flags & DRGN_FIND_SYMBOL_ADDR) {
		uint32_t start, end;
		address_search_range(index, address, &start, &end);
		for (uint32_t i = start; i < end; i++) {
			struct drgn_symbol *s = &index->symbols[i];
			if (s->address > address || address >= s->address + s->size)
				continue;
			if ((flags & DRGN_FIND_SYMBOL_NAME) &&
			    strcmp(s->name, name) != 0)
				continue;
			if (!drgn_symbol_result_builder_add(builder, s))
				return &drgn_enomem;
			if (flags & DRGN_FIND_SYMBOL_ONE)
				break;
		}
	} else if (flags & DRGN_FIND_SYMBOL_NAME) {
		struct drgn_symbol_name_table_iterator it =
			drgn_symbol_name_table_search(&index->htab, &name);
		if (!it.entry)
			return NULL;
		for (uint32_t i = it.entry->value.start; i < it.entry->value.end; i++) {
			struct drgn_symbol *s = &index->symbols[index->name_sort[i]];
			if (!drgn_symbol_result_builder_add(builder, s))
				return &drgn_enomem;
			if (flags & DRGN_FIND_SYMBOL_ONE)
				break;
		}
	} else {
		for (int i = 0; i < index->num_syms; i++) {
			struct drgn_symbol *s = &index->symbols[i];
			if (!drgn_symbol_result_builder_add(builder, s))
				return &drgn_enomem;
			if (flags & DRGN_FIND_SYMBOL_ONE)
				break;
		}
	}
	return NULL;
}

void
drgn_symbol_index_builder_init(struct drgn_symbol_index_builder *builder)
{
	builder->names = (struct string_builder)STRING_BUILDER_INIT;
	symbol_vector_init(&builder->symbols);
}

void
drgn_symbol_index_builder_deinit(struct drgn_symbol_index_builder *builder)
{
	string_builder_deinit(&builder->names);
	symbol_vector_deinit(&builder->symbols);
}

bool
drgn_symbol_index_builder_add(struct drgn_symbol_index_builder *builder,
			      const struct drgn_symbol *ptr)
{
	struct drgn_symbol copy = *ptr;

	// Temporarily store the index into the name
	copy.name = (char *)builder->names.len;
	return string_builder_append(&builder->names, ptr->name)
		&& string_builder_appendc(&builder->names, '\0')
		&& symbol_vector_append(&builder->symbols, &copy);
}

struct drgn_error *
drgn_symbol_index_init_from_builder(struct drgn_symbol_index *index,
				    struct drgn_symbol_index_builder *builder)
{
	size_t names_len = builder->names.len;
	char *names = string_builder_steal(&builder->names);
	char *tmp_names = realloc(names, names_len);
	if (tmp_names)
		names = tmp_names;

	symbol_vector_shrink_to_fit(&builder->symbols);
	struct drgn_symbol *symbols;
	size_t num_syms;
	symbol_vector_steal(&builder->symbols, &symbols, &num_syms);

	// Now that the name array is finalized, resolve the names to real
	// pointers. Update the name lifetime to static, reflecting that the
	// symbol name is owned by the finder whose lifetime is bound to the
	// program's once it is attached. The same goes for the symbol. Using
	// static lifetimes helps avoid unnecessary copying.
	for (size_t i = 0; i < num_syms; i++) {
		size_t string_index = (size_t)symbols[i].name;
		symbols[i].name = &names[string_index];
		symbols[i].name_lifetime = DRGN_LIFETIME_STATIC;
		symbols[i].lifetime = DRGN_LIFETIME_STATIC;
	}

	if (num_syms > UINT32_MAX) {
		free(names);
		free(symbols);
		return drgn_error_format(DRGN_ERROR_OUT_OF_BOUNDS,
					 "too many symbols provided: %zu > %" PRIu32,
					 num_syms, UINT32_MAX);
	}

	return drgn_symbol_index_init(symbols, num_syms, names, index);
}
