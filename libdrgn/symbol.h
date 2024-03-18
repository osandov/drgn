// Copyright (c) Meta Platforms, Inc. and affiliates.
// Copyright (c) 2024, Oracle and/or its affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_SYMBOL_H
#define DRGN_SYMBOL_H

#include <gelf.h>

#include "cleanup.h"
#include "drgn_internal.h"
#include "handler.h"
#include "hash_table.h"
#include "string_builder.h"
#include "vector.h"

struct drgn_symbol {
	const char *name;
	uint64_t address;
	uint64_t size;
	enum drgn_symbol_binding binding;
	enum drgn_symbol_kind kind;
	enum drgn_lifetime name_lifetime;
	enum drgn_lifetime lifetime;
};

struct drgn_symbol_finder {
	struct drgn_handler handler;
	struct drgn_symbol_finder_ops ops;
	void *arg;
};

DEFINE_VECTOR_TYPE(symbolp_vector, struct drgn_symbol *);

struct drgn_symbol_result_builder {
	bool one;
	union {
		struct symbolp_vector vector;
		struct drgn_symbol *single;
	};
};

#define _cleanup_symbol_ _cleanup_(drgn_symbol_cleanup)
static inline void drgn_symbol_cleanup(struct drgn_symbol **p)
{
	drgn_symbol_destroy(*p);
}

/** Initialize a @ref drgn_symbol from an ELF symbol. */
void drgn_symbol_from_elf(const char *name, uint64_t address,
			  const GElf_Sym *elf_sym, struct drgn_symbol *ret);

/** Destroy the contents of the result builder */
void drgn_symbol_result_builder_abort(struct drgn_symbol_result_builder *builder);

/** Initialize result builder */
void drgn_symbol_result_builder_init(struct drgn_symbol_result_builder *builder,
				     bool one);

/** Return single result */
struct drgn_symbol *
drgn_symbol_result_builder_single(struct drgn_symbol_result_builder *builder);

/** Return array result */
void drgn_symbol_result_builder_array(struct drgn_symbol_result_builder *builder,
				      struct drgn_symbol ***syms_ret, size_t *count_ret);

struct drgn_error *
drgn_symbol_copy(struct drgn_symbol *dst, struct drgn_symbol *src);

DEFINE_HASH_MAP(drgn_symbol_name_table, const char *,
		struct { uint32_t start; uint32_t end; },
		c_string_key_hash_pair, c_string_key_eq);

/**
 * An index of symbols, supporting efficient lookup by name or address
 *
 * While the dynamic symbol finding callback is a very flexible API, many use
 * cases can be served best by simply providing drgn with a known symbol table
 * to index. Drgn can efficiently implement the name and address lookup
 * functions once, and provide a symbol finder implementation, so that clients
 * need not redo this boilerplate.
 *
 * In the interest of simplicity, the index is immutable once created. This
 * allows us to use simple data structures. If the symbol table needs frequent
 * updates, then registering a custom symbol finder should be preferred.
 */
struct drgn_symbol_index {
	/** Array of symbols, in sorted order by address */
	struct drgn_symbol *symbols;

	/** Array of max_addr, to aid address lookup */
	uint64_t *max_addrs;

	/** Number of symbols */
	uint32_t num_syms;

	/** The buffer containing all symbol names */
	char *strings;

	/** Array of symbol indices, sorted by name. Used by the htab. */
	uint32_t *name_sort;

	/** Map of symbol names to index */
	struct drgn_symbol_name_table htab;
};

/**
 * Create a symbol index from an array of symbols
 *
 * This takes ownership of the symbol array and the individual symbols. The @a
 * buffer argument allows us to provide a single backing buffer for all strings
 * (in which case the lifetimes of each symbol name should be static). On error
 * @a symbols and @a buffer are already freed, since the builder took ownership
 * of them.
 */
struct drgn_error *
drgn_symbol_index_init(struct drgn_symbol *symbols, uint32_t count,
		       char *buffer, struct drgn_symbol_index *ret);

/** Deinitialize the symbol index. Safe to call multiple times. */
void drgn_symbol_index_deinit(struct drgn_symbol_index *index);

DEFINE_VECTOR_TYPE(symbol_vector, struct drgn_symbol);

struct drgn_symbol_index_builder {
	struct string_builder names;
	struct symbol_vector symbols;
};

/**
 * Create a symbol builder which will efficiently pack string names next
 * to each other in memory, rather than allocating many small strings.
 */
void
drgn_symbol_index_builder_init(struct drgn_symbol_index_builder *builder);

/**
 * For destroying a builder on error conditions. It is safe to call this
 * multiple times, including after drgn_symbol_index_init_from_builder().
 */
void
drgn_symbol_index_builder_deinit(struct drgn_symbol_index_builder *builder);

/**
 * Add symbol to the builder: the builder does not take ownership of @a ptr,
 * instead making a copy.
 */
bool
drgn_symbol_index_builder_add(struct drgn_symbol_index_builder *builder,
			      const struct drgn_symbol *ptr);

/**
 * Convert the builder to a symbol index, destroying the builder.
 * On error, the builder and symbol index are both deinitialized, requiring no
 * further cleanup.
 */
struct drgn_error *
drgn_symbol_index_init_from_builder(struct drgn_symbol_index *index,
				    struct drgn_symbol_index_builder *builder);

/**
 * The actual implementation of the Symbol Finder API.
 */
struct drgn_error *
drgn_symbol_index_find(const char *name, uint64_t address,
		       enum drgn_find_symbol_flags flags, void *arg,
		       struct drgn_symbol_result_builder *builder);

#endif /* DRGN_SYMBOL_H */
