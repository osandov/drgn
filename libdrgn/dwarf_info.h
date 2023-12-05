// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

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
struct drgn_elf_file;
struct drgn_module;
struct drgn_register_state;

/** DWARF Frame Description Entry. */
struct drgn_dwarf_fde {
	uint64_t initial_location;
	uint64_t address_range;
	/* CIE for this FDE as an index into drgn_dwarf_cfi::cies. */
	size_t cie;
	const char *instructions;
	size_t instructions_size;
};

/** DWARF Call Frame Information. */
struct drgn_dwarf_cfi {
	/** Array of DWARF Common Information Entries. */
	struct drgn_dwarf_cie *cies;
	/**
	 * Array of DWARF Frame Description Entries sorted by initial_location.
	 */
	struct drgn_dwarf_fde *fdes;
	/** Number of elements in @ref drgn_dwarf_cfi::fdes. */
	size_t num_fdes;
};

/** DWARF debugging information for a @ref drgn_module. */
struct drgn_module_dwarf_info {
	/** Call Frame Information from .debug_frame. */
	struct drgn_dwarf_cfi debug_frame;
	/** Call Frame Information from .eh_frame. */
	struct drgn_dwarf_cfi eh_frame;
	/** Base for `DW_EH_PE_pcrel`. */
	uint64_t pcrel_base;
	/** Base for `DW_EH_PE_textrel`. */
	uint64_t textrel_base;
	/** Base for `DW_EH_PE_datarel`. */
	uint64_t datarel_base;
};

void drgn_module_dwarf_info_deinit(struct drgn_module *module);

DEFINE_VECTOR_TYPE(drgn_dwarf_index_die_vector, uintptr_t,
		   vector_inline_minimal, uint32_t);
DEFINE_HASH_MAP_TYPE(drgn_dwarf_index_die_map, struct nstring,
		     struct drgn_dwarf_index_die_vector);

DEFINE_HASH_TABLE_TYPE(drgn_namespace_table,
		       struct drgn_namespace_dwarf_index *);

/* DWARF tags that act as namespaces. */
#define DRGN_DWARF_INDEX_NAMESPACE_TAGS	\
	X(structure_type)		\
	X(class_type)			\
	X(union_type)			\
	X(namespace)

/* DWARF tags that we index. */
#define DRGN_DWARF_INDEX_TAGS							\
	/*									\
	 * These must be first for a few places where we only care about	\
	 * namespace-like tags (e.g., drgn_namespace_dwarf_index::dies_indexed).\
	 */									\
	DRGN_DWARF_INDEX_NAMESPACE_TAGS						\
	X(enumeration_type)							\
	X(typedef)								\
	X(enumerator)								\
	X(subprogram)								\
	X(variable)								\
	X(base_type)

enum drgn_dwarf_index_tag {
#define X(name) DRGN_DWARF_INDEX_##name,
	DRGN_DWARF_INDEX_TAGS
#undef X
};

#define X(_) + 1
enum { DRGN_DWARF_INDEX_NUM_NAMESPACE_TAGS = DRGN_DWARF_INDEX_NAMESPACE_TAGS };
enum { DRGN_DWARF_INDEX_NUM_TAGS = DRGN_DWARF_INDEX_TAGS };
#undef X
_Static_assert(DRGN_DWARF_INDEX_base_type == DRGN_DWARF_INDEX_NUM_TAGS - 1,
	       "base_type must be last");
enum { DRGN_DWARF_INDEX_MAP_SIZE = DRGN_DWARF_INDEX_NUM_TAGS - 1 };

/**
 * DWARF information for a namespace or nested definitions in a class, struct,
 * or union.
 */
struct drgn_namespace_dwarf_index {
	/** Debugging information cache that owns this index. */
	struct drgn_debug_info *dbinfo;
	/** (Null-terminated) name of this namespace. */
	const char *name;
	/** Length of @ref name. */
	size_t name_len;
	/** Parent namespace, or @c NULL if it is the global namespace. */
	struct drgn_namespace_dwarf_index *parent;
	/** Children namespaces indexed by name. */
	struct drgn_namespace_table children;
	/**
	 * Mapping for each @ref drgn_dwarf_index_tag from name to a list of
	 * matching DIE addresses.
	 *
	 * This has a few quirks:
	 *
	 * - `base_type` DIEs are in @ref drgn_dwarf_info::base_types, not here.
	 * - `enumerator` entries store the addresses of the parent
	 *   `enumeration_type` DIEs instead.
	 * - `namespace` entries also include the addresses of `class_type`,
	 *   `structure_type`, and `union_type` DIEs that have children and
	 *   `DW_AT_declaration`. This is because class, struct, and union
	 *   declaration DIEs can contain nested definitions, so we want to
	 *   index the children of those declarations, but we don't want to
	 *   encounter the declarations when looking for the actual type.
	 * - Otherwise, this does not include DIEs with `DW_AT_declaration`.
	 */
	struct drgn_dwarf_index_die_map map[DRGN_DWARF_INDEX_MAP_SIZE];
	/**
	 * Number of CUs that were indexed the last time that this namespace was
	 * indexed.
	 */
	size_t cus_indexed;
	/**
	 * Number of DIEs for each namespace-like tag in the parent's index that
	 * were indexed the last time that this namespace was indexed.
	 */
	uint32_t dies_indexed[DRGN_DWARF_INDEX_NUM_NAMESPACE_TAGS];
	/** Saved error from a previous index. */
	struct drgn_error *saved_err;
};

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

DEFINE_HASH_MAP_TYPE(drgn_dwarf_base_type_map, struct nstring, uintptr_t);
DEFINE_HASH_MAP_TYPE(drgn_dwarf_specification_map, uintptr_t, uintptr_t);
DEFINE_VECTOR_TYPE(drgn_dwarf_index_cu_vector, struct drgn_dwarf_index_cu);
DEFINE_HASH_MAP_TYPE(drgn_dwarf_type_map, const void *, struct drgn_dwarf_type);

/** DWARF debugging information for a program/@ref drgn_debug_info. */
struct drgn_dwarf_info {
	/** Global namespace index. */
	struct drgn_namespace_dwarf_index global;
	/**
	 * Mapping from name to `DW_TAG_base_type` DIE address with that name.
	 *
	 * Unlike user-defined types and variables, there can only be one base
	 * type with a given name in the entire program, so we don't store them
	 * in a @ref drgn_dwarf_index_die_map.
	 */
	struct drgn_dwarf_base_type_map base_types;
	/**
	 * Map from the address of a (usually non-defining) DIE to the address
	 * of a DIE with a DW_AT_specification attribute that references it.
	 * This is used to resolve DIEs with DW_AT_declaration to their
	 * definition.
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

/**
 * State tracked while indexing new DWARF information in a @ref drgn_dwarf_info.
 */
struct drgn_dwarf_index_state {
	struct drgn_debug_info *dbinfo;
	/** Per-thread arrays of CUs to be indexed. */
	struct drgn_dwarf_index_cu_vector *cus;
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

/** Read a @ref drgn_elf_file to index its DWARF information. */
struct drgn_error *
drgn_dwarf_index_read_file(struct drgn_dwarf_index_state *state,
			   struct drgn_elf_file *file);

/**
 * Index new DWARF information.
 *
 * This should be called once all files have been read with @ref
 * drgn_dwarf_index_read_file() to finish indexing those files.
 */
struct drgn_error *
drgn_dwarf_info_update_index(struct drgn_dwarf_index_state *state);

/**
 * Find the DWARF DIEs in a @ref drgn_module for the scope containing a given
 * program counter.
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
struct drgn_error *drgn_module_find_dwarf_scopes(struct drgn_module *module,
						 uint64_t pc,
						 uint64_t *bias_ret,
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
 * Get an array of names of `DW_TAG_variable` and `DW_TAG_formal_parameter` DIEs
 * in local scopes.
 *
 * @param[out] names_ret Returned array of names. On success, must be freed with
 * @c free(). The individual strings should not be freed.
 * @param[out] count_ret Returned number of names in @p names_ret.
 */
struct drgn_error *drgn_dwarf_scopes_names(Dwarf_Die *scopes,
					   size_t num_scopes,
					   const char ***names_ret,
					   size_t *count_ret);

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
		       struct drgn_elf_file *file, Dwarf_Die *die,
		       Dwarf_Die *type_die, Dwarf_Die *function_die,
		       const struct drgn_register_state *regs,
		       struct drgn_object *ret);

struct drgn_error *
drgn_module_find_dwarf_cfi(struct drgn_module *module, uint64_t pc,
			   struct drgn_cfi_row **row_ret, bool *interrupted_ret,
			   drgn_register_number *ret_addr_regno_ret);

struct drgn_error *
drgn_module_find_eh_cfi(struct drgn_module *module, uint64_t pc,
			struct drgn_cfi_row **row_ret, bool *interrupted_ret,
			drgn_register_number *ret_addr_regno_ret);

struct drgn_error *
drgn_eval_cfi_dwarf_expression(struct drgn_program *prog,
			       struct drgn_elf_file *file,
			       const struct drgn_cfi_rule *rule,
			       const struct drgn_register_state *regs,
			       void *buf, size_t size);

/** @} */

#endif /* DRGN_DEBUG_INFO_DWARF_H */
