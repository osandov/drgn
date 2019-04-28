// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Symbol lookup.
 *
 * See @ref SymbolIndex.
 */

#ifndef DRGN_SYMBOL_INDEX_H
#define DRGN_SYMBOL_INDEX_H

#include <elfutils/libdw.h>

#include "drgn.h"

/**
 * @ingroup Internals
 *
 * @defgroup SymbolIndex Symbol index
 *
 * Symbol lookup.
 *
 * @ref drgn_symbol_index provides a common interface for finding symbols (e.g.,
 * variables, constants, and functions) in a program.
 *
 * @{
 */

/**
 * An indexed symbol in a program.
 *
 * This is the result of a lookup in a @ref drgn_symbol_index. It is typically
 * converted to a @ref drgn_object.
 */
struct drgn_symbol {
	/** The type of the symbol. */
	struct drgn_qualified_type qualified_type;
	/**
	 * Whether the symbol is an enumerator.
	 *
	 * If this is @c true, then @ref drgn_symbol::qualified_type must be an
	 * enumerated type, and either @ref drgn_symbol::svalue or @ref
	 * drgn_symbol::uvalue is set (based on the signedness of @ref
	 * drgn_symbol::qualified_type). Otherwise, @ref drgn_symbol::address is
	 * set.
	 */
	bool is_enumerator;
	/** Whether the symbol is little-endian. */
	bool little_endian;
	union {
		/** If not an enumerator, the address of the symbol. */
		uint64_t address;
		/** If a signed enumerator, the value. */
		int64_t svalue;
		/** If an unsigned enumerator, the value. */
		uint64_t uvalue;
	};
};

struct drgn_symbol_index;

/** Symbol index operations. */
struct drgn_symbol_index_ops {
	/** Implements @ref drgn_symbol_index_destroy(). */
	void (*destroy)(struct drgn_symbol_index *sindex);
	/** Implements @ref drgn_symbol_index_find(). */
	struct drgn_error *(*find)(struct drgn_symbol_index *sindex,
				   const char *name, const char *filename,
				   enum drgn_find_object_flags flags,
				   struct drgn_symbol *ret);
};

/**
 * Abstract symbol index.
 *
 * A symbol index is used to find symbols (symbols and constants) by name. It is
 * usually backed by debugging information (@ref drgn_dwarf_symbol_index). It
 * can also be backed by manually-created symbols for testing (@ref
 * drgn_mock_symbol_index). It is destroyed with @ref
 * drgn_symbol_index_destroy().
 *
 * @ref drgn_symbol_index_find() searches for an symbol.
 */
struct drgn_symbol_index {
	/** Operation dispatch table. */
	const struct drgn_symbol_index_ops *ops;
};

/**
 * Free a @ref drgn_symbol_index.
 *
 * @param[in] sindex Symbol index to destroy.
 */
static inline void
drgn_symbol_index_destroy(struct drgn_symbol_index *sindex)
{
	if (sindex)
		sindex->ops->destroy(sindex);
}

/**
 * Find a symbol in a @ref drgn_symbol_index.
 *
 * @param[in] sindex Symbol index.
 * @param[in] name Name of the symbol.
 * @param[in] filename Exact filename containing the symbol definition, or @c
 * NULL for any definition.
 * @param[in] flags Bitmask of @ref drgn_find_object_flags.
 * @param[out] ret Returned symbol.
 * @return @c NULL on success, non-@c NULL on error.
 */
static inline struct drgn_error *
drgn_symbol_index_find(struct drgn_symbol_index *sindex, const char *name,
		       const char *filename, enum drgn_find_object_flags flags,
		       struct drgn_symbol *ret)
{
	if ((flags & ~DRGN_FIND_OBJECT_ANY) || !flags) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid find object flags");
	}

	return sindex->ops->find(sindex, name, filename, flags, ret);
}

/**
 * Initialize a @ref drgn_symbol with an enumerated type.
 *
 * This is a helper for implementations of @ref drgn_symbol_index_ops::find().
 *
 * @c sym->qualified_type should already be initialized. This will initialize @c
 * sym->svalue or @c sym->uvalue to the value of the enumerator with the given
 * name in that type.
 *
 * @param[in,out] sym Symbol to initialize.
 * @param[in] name Name of enumerator to find.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_symbol_from_enumerator(struct drgn_symbol *sym,
					       const char *name);

/**
 * Create a @ref drgn_error for a symbol which could not be found in a @ref
 * drgn_symbol_index.
 *
 * This is a helper for implementations of @ref drgn_symbol_index_ops::find().
 *
 * @param[in] name Name of the symbol.
 * @param[in] filename Filename that was searched in or @c NULL.
 * @param[in] flags Flags that were passed to @ref
 * drgn_symbol_index_ops::find().
 */
struct drgn_error *
drgn_symbol_index_not_found_error(const char *name, const char *filename,
				  enum drgn_find_object_flags flags)
	__attribute__((returns_nonnull));

/** Symbol indexed in a @ref drgn_mock_symbol_index. */
struct drgn_mock_symbol {
	/** Name of the symbol. */
	const char *name;
	/**
	 * Name of the file that the symbol is defined in.
	 *
	 * This may be @c NULL, in which case no filename will match it.
	 */
	const char *filename;
	/** See @ref drgn_symbol::qualified_type. */
	struct drgn_qualified_type qualified_type;
	/** See @ref drgn_symbol::is_enumerator. */
	bool is_enumerator;
	/** See @ref drgn_symbol::little_endian. */
	bool little_endian;
	/** See @ref drgn_symbol::address. */
	uint64_t address;
};

/**
 * Symbol index backed by manually-defined symbols.
 *
 * This is mostly useful for testing. It is created with @ref
 * drgn_mock_symbol_index_create().
 */
struct drgn_mock_symbol_index {
	/** Abstract symbol index. */
	struct drgn_symbol_index sindex;
	/** Indexed symbols. */
	struct drgn_mock_symbol *symbols;
};

/**
 * Create a @ref drgn_mock_symbol_index.
 *
 * @param[in] symbols Symbols to index, terminated by an element with @ref
 * drgn_mock_symbol::name set to @c NULL. This will not be freed when the symbol
 * index is destroyed.
 * @param[out] ret Returned symbol index.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_mock_symbol_index_create(struct drgn_mock_symbol *symbols,
			      struct drgn_mock_symbol_index **ret);

struct drgn_program;

/** Symbol index backed by DWARF debugging information. */
struct drgn_dwarf_symbol_index {
	/** Abstract symbol index. */
	struct drgn_symbol_index sindex;
	/** Debugging information cache. */
	struct drgn_dwarf_info_cache *dicache;
};

/**
 * Create a @ref drgn_dwarf_symbol_index.
 *
 * @param[in] dtindex DWARF type index.
 * @param[out] ret Returned symbol index.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_dwarf_symbol_index_create(struct drgn_dwarf_info_cache *dcache,
			       struct drgn_dwarf_symbol_index **ret);

/** @} */

#endif /* DRGN_SYMBOL_INDEX_H */
