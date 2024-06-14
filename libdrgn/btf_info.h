#ifndef BTF_INFO_H_
#define BTF_INFO_H_

#include <stdint.h>

#include "hash_table.h"
#include "object.h"
#include "type.h"
#include "vector.h"

struct drgn_program;
struct drgn_debug_info;

/**
 * Represents an BTF item which can be indexed by name: a variable, a named
 * type, or an enumerator.
 */
struct drgn_btf_index_item {
	/** Drgn module associated with the type ID */
	struct drgn_module *module;
	union {
		/** For variables: the address of the variable */
		uint64_t addr;
		/** For enumerators: the enumerator index */
		uint64_t index;
	};
	/** The indexed type, variable type, or enumerator type */
	uint32_t type_id;
	uint8_t kind;
	unsigned int is_enum : 1;
	unsigned int is_present : 1;
};

DEFINE_VECTOR_TYPE(drgn_btf_index_bucket, struct drgn_btf_index_item);
DEFINE_HASH_MAP_TYPE(drgn_btf_index, const char *, struct drgn_btf_index_bucket);

/** How to determine the address of variables. */
enum drgn_btf_ofind_mode {
	/** Not yet set */
	DRGN_BTF_OFIND_UNSET = 0,
	/** Disable the BTF object finder for variables */
	DRGN_BTF_OFIND_NOVAR,
	/** Use var_secinfo in DATASEC to resolve addresses. */
	DRGN_BTF_OFIND_DATASEC,
	/** Use the symbol table (ELF or global fallback) */
	DRGN_BTF_OFIND_SYMTAB,
};

/** BTF type information for the entire program */
struct drgn_btf_info {
	struct drgn_type_finder type_finder;
	struct drgn_object_finder object_finder;
	struct drgn_btf_index htab;
	enum drgn_btf_ofind_mode ofind_mode;
	bool modules_searched;
};

/** BTF type information for a module */
struct drgn_module_btf_info {
	/** Handle from libbpf */
	struct btf *btf;
	/** Map from type ID to the drgn_type */
	struct drgn_type **cache;
	/** Cached results from searching the btf_modules list */
	uint64_t btf_data_len;
	uint64_t btf_data_addr;
};

#if WITH_BPF
void drgn_btf_info_init(struct drgn_debug_info *);
void drgn_btf_info_deinit(struct drgn_debug_info *);
void drgn_module_btf_info_deinit(struct drgn_module *);
struct drgn_error *
drgn_module_load_btf(struct drgn_module *, const void *btf_data,
                     size_t btf_data_size, bool main_module_base);
#else
static inline void drgn_btf_info_init(struct drgn_debug_info *dbi) {}
static inline void drgn_btf_info_deinit(struct drgn_debug_info *dbi) {}
static inline void drgn_module_btf_info_deinit(struct drgn_module *mod) {}
static inline struct drgn_error *
drgn_module_load_btf(struct drgn_module *mod, const void *btf_data,
                     size_t btf_data_size, bool main_module_base)
{
	return drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
				 "drgn was not built with libbpf support");
}
#endif
#endif // BTF_INFO_H_
