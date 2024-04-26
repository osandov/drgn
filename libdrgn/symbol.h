// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_SYMBOL_H
#define DRGN_SYMBOL_H

#include <gelf.h>

#include "cleanup.h"
#include "drgn.h"
#include "handler.h"
#include "vector.h"

struct drgn_symbol {
	const char *name;
	uint64_t address;
	uint64_t size;
	enum drgn_symbol_binding binding;
	enum drgn_symbol_kind kind;
	enum drgn_lifetime name_lifetime;
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

#endif /* DRGN_SYMBOL_H */
