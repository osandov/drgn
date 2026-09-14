#ifndef BTF_INFO_H_
#define BTF_INFO_H_

#include <stdint.h>

#include "hash_table.h"
#include "object.h"
#include "type.h"
#include "vector.h"

struct drgn_program;
struct drgn_debug_info;

enum drgn_tristate {
	DRGN_TRISTATE_DEFAULT = -1,
	DRGN_TRISTATE_FALSE,
	DRGN_TRISTATE_TRUE,
};

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
	unsigned int addr_valid : 1;
};

DEFINE_VECTOR_TYPE(drgn_btf_index_bucket, struct drgn_btf_index_item, 1);
DEFINE_HASH_MAP_TYPE(drgn_btf_index, const char *, struct drgn_btf_index_bucket);

/** BTF type information for the entire program */
struct drgn_btf_info {
	struct drgn_type_finder type_finder;
	struct drgn_object_finder object_finder_symbol, object_finder_datasec;
	struct drgn_btf_index htab;
};

/** BTF type information for a module */
struct drgn_module_btf_info {
	/** Handle from libbpf */
	struct btf *btf;
	/** Map from type ID to the drgn_type */
	struct drgn_type **cache;
};

#if defined(WITH_LIBBPF)
void drgn_btf_info_init(struct drgn_debug_info *);
void drgn_btf_info_deinit(struct drgn_debug_info *);
void drgn_module_btf_info_deinit(struct drgn_module *);
struct drgn_error *
drgn_module_load_btf(struct drgn_module *, const void *btf_data,
                     size_t btf_data_size, enum drgn_tristate main_module_base);
#else
static inline void drgn_btf_info_init(struct drgn_debug_info *dbi) {}
static inline void drgn_btf_info_deinit(struct drgn_debug_info *dbi) {}
static inline void drgn_module_btf_info_deinit(struct drgn_module *mod) {}
static inline struct drgn_error *
drgn_module_load_btf(struct drgn_module *mod, const void *btf_data,
                     size_t btf_data_size, enum drgn_tristate main_module_base)
{
	return drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
				 "drgn was not built with libbpf support");
}
#endif
#endif // BTF_INFO_H_
