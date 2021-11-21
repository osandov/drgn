// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * DWARF and .eh_frame support.
 *
 * See @ref DebugInfo.
 */

#ifndef DRGN_DEBUG_INFO_DWARF_H
#define DRGN_DEBUG_INFO_DWARF_H

/**
 * @ingroup DebugInfo
 *
 * @{
 */

#include <elfutils/libdw.h>

#include "cfi.h"
#include "drgn.h"
#include "hash_table.h"
#include "vector.h"

struct drgn_debug_info;
struct drgn_debug_info_module;
struct drgn_register_state;

/** DWARF Frame Description Entry. */
struct drgn_dwarf_fde {
	uint64_t initial_location;
	uint64_t address_range;
	/* CIE for this FDE as an index into drgn_debug_info_module::cies. */
	size_t cie;
	const char *instructions;
	size_t instructions_size;
};

/** DWARF debugging information for a @ref drgn_debug_info_module. */
struct drgn_dwarf_module_info {
	/** Base for `DW_EH_PE_pcrel`. */
	uint64_t pcrel_base;
	/** Base for `DW_EH_PE_textrel`. */
	uint64_t textrel_base;
	/** Base for `DW_EH_PE_datarel`. */
	uint64_t datarel_base;
	/** Array of DWARF Common Information Entries. */
	struct drgn_dwarf_cie *cies;
	/**
	 * Array of DWARF Frame Description Entries sorted by initial_location.
	 */
	struct drgn_dwarf_fde *fdes;
	/** Number of elements in @ref drgn_debug_info_module::fdes. */
	size_t num_fdes;
};

void drgn_dwarf_module_info_deinit(struct drgn_debug_info_module *module);

DEFINE_VECTOR_TYPE(drgn_dwarf_index_pending_die_vector,
		   struct drgn_dwarf_index_pending_die)

/**
 * Index of DWARF information for a namespace by entity name.
 *
 * This effectively maps a name to a list of DIEs with that name in a namespace.
 * DIEs with the same name and tag and declared in the same file are
 * deduplicated.
 */
struct drgn_namespace_dwarf_index {
	/**
	 * Index shards.
	 *
	 * Indexing is parallelized, so this is sharded to reduce lock
	 * contention.
	 */
	struct drgn_dwarf_index_shard *shards;
	/** Debugging information cache that owns this index. */
	struct drgn_debug_info *dbinfo;
	/** DIEs we have not indexed yet. */
	struct drgn_dwarf_index_pending_die_vector pending_dies;
	/** Saved error from a previous index. */
	struct drgn_error *saved_err;
};

/** DIE with a `DW_AT_specification` attribute. */
struct drgn_dwarf_specification {
	/**
	 * Address of non-defining declaration DIE referenced by
	 * `DW_AT_specification`.
	 */
	uintptr_t declaration;
	/** Module containing DIE. */
	struct drgn_debug_info_module *module;
	/** Address of DIE. */
	uintptr_t addr;
};

DEFINE_HASH_TABLE_TYPE(drgn_dwarf_specification_map,
		       struct drgn_dwarf_specification)

DEFINE_VECTOR_TYPE(drgn_dwarf_index_cu_vector, struct drgn_dwarf_index_cu)

/** Cached type in a @ref drgn_debug_info. */
struct drgn_dwarf_type {
	struct drgn_type *type;
	enum drgn_qualifiers qualifiers;
	/**
	 * Whether this is an incomplete array type or a typedef of one.
	 *
	 * This is used to work around a GCC bug; see @ref
	 * drgn_type_from_dwarf_internal().
	 */
	bool is_incomplete_array;
};

DEFINE_HASH_MAP_TYPE(drgn_dwarf_type_map, const void *, struct drgn_dwarf_type)

/** DWARF debugging information for a program/@ref drgn_debug_info. */
struct drgn_dwarf_info {
	/** Global namespace index. */
	struct drgn_namespace_dwarf_index global;
	/**
	 * Map from address of DIE referenced by DW_AT_specification to DIE that
	 * references it. This is used to resolve DIEs with DW_AT_declaration to
	 * their definition.
	 *
	 * This is populated while indexing new DWARF information. Unlike the
	 * name index, it is not sharded because there typically aren't enough
	 * of these in a program to cause contention.
	 */
	struct drgn_dwarf_specification_map specifications;
	/** Indexed compilation units. */
	struct drgn_dwarf_index_cu_vector index_cus;

	/**
	 * Cache of parsed types.
	 *
	 * The key is the address of the DIE (@c Dwarf_Die::addr). The value is
	 * a @ref drgn_dwarf_type.
	 */
	struct drgn_dwarf_type_map types;
	/**
	 * Cache of parsed types which appear to be incomplete array types but
	 * can't be.
	 *
	 * See @ref drgn_type_from_dwarf_internal().
	 */
	struct drgn_dwarf_type_map cant_be_incomplete_array_types;

	/** Current parsing recursion depth. */
	int depth;
};

void drgn_dwarf_info_init(struct drgn_debug_info *dbinfo);
void drgn_dwarf_info_deinit(struct drgn_debug_info *dbinfo);

DEFINE_VECTOR_TYPE(drgn_dwarf_index_pending_cu_vector,
		   struct drgn_dwarf_index_pending_cu)

/**
 * State tracked while indexing new DWARF information in a @ref drgn_dwarf_info.
 */
struct drgn_dwarf_index_state {
	struct drgn_debug_info *dbinfo;
	/** Per-thread arrays of CUs to be indexed. */
	struct drgn_dwarf_index_pending_cu_vector *cus;
	size_t max_threads;
};

/**
 * Initialize state for indexing new DWARF information.
 *
 * @return @c true on success, @c false on failure to allocate memory.
 */
bool drgn_dwarf_index_state_init(struct drgn_dwarf_index_state *state,
				 struct drgn_debug_info *dbinfo);

/** Deinitialize state for indexing new DWARF information. */
void drgn_dwarf_index_state_deinit(struct drgn_dwarf_index_state *state);

/** Read a @ref drgn_debug_info_module to index its DWARF information. */
struct drgn_error *
drgn_dwarf_index_read_module(struct drgn_dwarf_index_state *state,
			     struct drgn_debug_info_module *module);

/**
 * Index new DWARF information.
 *
 * This should be called once all modules have been read with @ref
 * drgn_dwarf_index_read_module() to finish indexing those modules.
 */
struct drgn_error *
drgn_dwarf_info_update_index(struct drgn_dwarf_index_state *state);

/**
 * Find the DWARF DIEs in a @ref drgn_debug_info_module for the scope containing
 * a given program counter.
 *
 * @param[in] module Module containing @p pc.
 * @param[in] pc Program counter.
 * @param[out] bias_ret Returned difference between addresses in the loaded
 * module and addresses in the returned DIEs.
 * @param[out] dies_ret Returned DIEs. `(*dies_ret)[*length_ret - 1]` is the
 * innermost DIE containing @p pc, `(*dies_ret)[*length_ret - 2]` is its parent
 * (which may not contain @p pc itself), `(*dies_ret)[*length_ret - 3]` is its
 * grandparent, etc. Must be freed with @c free().
 * @param[out] length_ret Returned length of @p dies_ret.
 */
struct drgn_error *
drgn_debug_info_module_find_dwarf_scopes(struct drgn_debug_info_module *module,
					 uint64_t pc, uint64_t *bias_ret,
					 Dwarf_Die **dies_ret,
					 size_t *length_ret)
	__attribute__((__nonnull__(1, 3, 4, 5)));

/**
 * Find the ancestors of a DWARF DIE.
 *
 * This finds the parent, grandparent, etc., of a DWARF DIE in the tree of DIEs.
 *
 * @param[in] module Module containing @p die.
 * @param[in] die DIE to find.
 * @param[out] dies_ret Returned DIEs. `(*dies_ret)[*length_ret]` is the DIE,
 * `(*dies_ret)[*length_ret - 1]` is its parent, `(*dies_ret)[*length_ret - 2]`
 * is its grandparent, etc., and `(*dies_ret)[0]` is the top-level unit DIE.
 * @param[out] length_ret Returned number of ancestors in @p dies_ret.
 */
struct drgn_error *drgn_find_die_ancestors(Dwarf_Die *die, Dwarf_Die **dies_ret,
					  size_t *length_ret)
	__attribute__((__nonnull__(2, 3)));

/**
 * Find an object DIE in an array of DWARF scopes.
 *
 * @param[in] scopes Array of scopes, from outermost to innermost.
 * @param[in] num_scopes Number of scopes in @p scopes.
 * @param[out] die_ret Returned object DIE.
 * @param[out] type_ret If @p die_ret is a `DW_TAG_enumerator` DIE, its parent.
 * Otherwise, undefined.
 */
struct drgn_error *drgn_find_in_dwarf_scopes(Dwarf_Die *scopes,
					     size_t num_scopes,
					     const char *name,
					     Dwarf_Die *die_ret,
					     Dwarf_Die *type_ret);

/**
 * Create a @ref drgn_object from a `Dwarf_Die`.
 *
 * @param[in] die Object DIE (e.g., `DW_TAG_subprogram`, `DW_TAG_variable`,
 * `DW_TAG_formal_parameter`, `DW_TAG_enumerator`,
 * `DW_TAG_template_value_parameter`).
 * @param[in] type_die DIE of object's type. If @c NULL, use the `DW_AT_type`
 * attribute of @p die. If @p die is a `DW_TAG_enumerator` DIE, this should be
 * its parent.
 * @param[in] function_die DIE of current function. @c NULL if not in function
 * context.
 * @param[in] regs Registers of current stack frame. @c NULL if not in stack
 * frame context.
 * @param[out] ret Returned object.
 */
struct drgn_error *
drgn_object_from_dwarf(struct drgn_debug_info *dbinfo,
		       struct drgn_debug_info_module *module,
		       Dwarf_Die *die, Dwarf_Die *type_die,
		       Dwarf_Die *function_die,
		       const struct drgn_register_state *regs,
		       struct drgn_object *ret);

struct drgn_error *
drgn_debug_info_find_dwarf_cfi(struct drgn_debug_info_module *module,
			       uint64_t unbiased_pc,
			       struct drgn_cfi_row **row_ret,
			       bool *interrupted_ret,
			       drgn_register_number *ret_addr_regno_ret);

struct drgn_error *
drgn_eval_cfi_dwarf_expression(struct drgn_program *prog,
			       const struct drgn_cfi_rule *rule,
			       const struct drgn_register_state *regs,
			       void *buf, size_t size);

/** @} */

#endif /* DRGN_DEBUG_INFO_DWARF_H */
