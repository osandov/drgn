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

/** Kind of symbol. */
enum drgn_symbol_kind {
	/**
	 * A symbol with an address in the program. @ref drgn_symbol::address is
	 * set to the address.
	 */
	DRGN_SYMBOL_ADDRESS,
	/**
	 * A symbol with a constant value. One of @ref drgn_symbol::svalue, @ref
	 * drgn_symbol::uvalue, or @ref drgn_symbol::fvalue is set, depending on
	 * @ref drgn_symbol::type.
	 */
	DRGN_SYMBOL_CONSTANT,
	/**
	 * An enumerator. No address or value is set.
	 *
	 * A symbol with this kind may be returned by a @ref
	 * drgn_symbol_find_fn(), but it is always converted to a constant
	 * before being returned by @ref drgn_symbol_index_find().
	 */
	DRGN_SYMBOL_ENUMERATOR,
} __attribute__((packed));

/**
 * An indexed symbol in a program.
 *
 * This is the result of a lookup in a @ref drgn_symbol_index. It is typically
 * converted to a @ref drgn_object.
 */
struct drgn_symbol {
	/** Type of this symbol. */
	struct drgn_type *type;
	/** Qualifiers on @ref drgn_symbol::type. */
	enum drgn_qualifiers qualifiers;
	/** Kind of this symbol. */
	enum drgn_symbol_kind kind;
	/**
	 * Whether the symbol is little-endian.
	 *
	 * This is ignored for constants and enumerators.
	 */
	bool little_endian;
	union {
		/**
		 * If not a constant or enumerator, the address of the symbol.
		 */
		uint64_t address;
		/** If a signed constant, the value. */
		int64_t svalue;
		/** If an unsigned constant, the value. */
		uint64_t uvalue;
		/** If a floating-point constant, the value. */
		double fvalue;
	};
};

/**
 * Callback for finding a symbol.
 *
 * If the symbol is found, this should fill in @p ret and return @c NULL. If
 * not, this should set <tt>ret->type</tt> to @c NULL return @c NULL.
 *
 * @param[in] name Name of symbol. This is @em not null-terminated.
 * @param[in] name_len Length of @p name.
 * @param[in] filename Filename containing the symbol definition or @c NULL.
 * This should be matched with @ref path_ends_with().
 * @param[in] arg Argument passed to @ref drgn_symbol_index_add_finder().
 * @param[out] ret Returned symbol.
 * @return @c NULL on success, non-@c NULL on error.
 */
typedef struct drgn_error *
(*drgn_symbol_find_fn)(const char *name, size_t name_len, const char *filename,
		       enum drgn_find_object_flags flags, void *arg,
		       struct drgn_symbol *ret);

/** Registered callback in a @ref drgn_symbol_index. */
struct drgn_symbol_finder {
	/** The callback. */
	drgn_symbol_find_fn fn;
	/** Argument to pass to @ref drgn_symbol_finder::fn. */
	void *arg;
	/** Next callback to try. */
	struct drgn_symbol_finder *next;
};

/**
 * Symbol index.
 *
 * A symbol index is used to find symbols (variables, constants, and functions)
 * by name. The types are found using callbacks which are registered with @ref
 * drgn_symbol_index_add_finder(). @ref drgn_symbol_index_find() searches for an
 * symbol.
 */
struct drgn_symbol_index {
	/** Callbacks for finding symbols. */
	struct drgn_symbol_finder *finders;
};

/** Initialize a @ref drgn_symbol_index. */
void drgn_symbol_index_init(struct drgn_symbol_index *sindex);

/** Deinitialize a @ref drgn_symbol_index. */
void drgn_symbol_index_deinit(struct drgn_symbol_index *sindex);

/**
 * Register a symbol finding callback.
 *
 * Callbacks are called in reverse order of the order they were added in until
 * the symbol is found. So, more recently added callbacks take precedence.
 *
 * @param[in] fn The callback.
 * @param[in] arg Argument to pass to @p fn.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_symbol_index_add_finder(struct drgn_symbol_index *sindex,
			     drgn_symbol_find_fn fn, void *arg);

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
struct drgn_error *drgn_symbol_index_find(struct drgn_symbol_index *sindex,
					  const char *name,
					  const char *filename,
					  enum drgn_find_object_flags flags,
					  struct drgn_symbol *ret);

/** Symbol index entry for testing. */
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

/** @} */

#endif /* DRGN_SYMBOL_INDEX_H */
