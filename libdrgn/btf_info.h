#ifndef BTF_INFO_H_
#define BTF_INFO_H_

#include <stdbool.h>
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

enum drgn_btf_kind {
	// Keep up-to-date with Module_add_btf()
	DRGN_BTF_MAIN,
	DRGN_BTF_GLOBAL,
	DRGN_BTF__NR,
};

/** Contains section base address and type ID for each DATASEC */
struct drgn_btf_datasec {
	uint64_t base;
	uint32_t type_id;
	/** Whether the section base address was found. */
	bool base_valid;
};

/** Container for each BTF archive and its drgn type cache */
struct drgn_btf {
	/** Handle from libbpf */
	struct btf *btf;
	/** Cache for local type IDs, excluding IDs in the parent BTF. */
	struct drgn_type **cache;
	/** Parent BTF link */
	struct drgn_btf *parent;
	/** Drgn module this BTF is associated with */
	struct drgn_module *module;
	/** Array of DATASEC entries that map section base & type ID */
	struct drgn_btf_datasec *datasecs;
	uint32_t num_datasecs;
};

/** Index item for name lookups */
struct drgn_btf_index_item {
	struct drgn_btf *btf;
	union {
		/** For enums, named types, and functions, the type ID */
		uint32_t type_id;
		/** For variables, index into drgn_btf.datasecs */
		uint32_t datasec_index;
	};
	/** For enums and variables */
	uint32_t member_index;
};

DEFINE_VECTOR_TYPE(drgn_btf_index_bucket, struct drgn_btf_index_item, 1);
DEFINE_HASH_MAP_TYPE(drgn_btf_index, const char *, struct drgn_btf_index_bucket);

/** BTF type information for each module */
struct drgn_module_btf_info {
	struct drgn_btf btfs[DRGN_BTF__NR];
};

/** BTF type information for the entire program */
struct drgn_btf_info {
	struct drgn_type_finder type_finder;
	struct drgn_object_finder object_finder_symbol, object_finder_datasec;

	/** Named types and functions. */
	struct drgn_btf_index types;
	struct drgn_btf_index constants;
	struct drgn_btf_index variables;
};

#if defined(WITH_LIBBPF)
void drgn_btf_info_init(struct drgn_debug_info *);
void drgn_btf_info_deinit(struct drgn_debug_info *);
void drgn_module_btf_info_deinit(struct drgn_module *);
struct drgn_error *
drgn_module_add_btf(struct drgn_module *, enum drgn_btf_kind kind,
                    const void *btf_data, size_t btf_data_size,
                    enum drgn_tristate main_module_base);
#else
static inline void drgn_btf_info_init(struct drgn_debug_info *dbi) {}
static inline void drgn_btf_info_deinit(struct drgn_debug_info *dbi) {}
static inline void drgn_module_btf_info_deinit(struct drgn_module *mod) {}
static inline struct drgn_error *
drgn_module_add_btf(struct drgn_module *, enum drgn_btf_kind kind,
                    const void *btf_data, size_t btf_data_size,
                    enum drgn_tristate main_module_base)
{
	return drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
				 "drgn was not built with libbpf support");
}
#endif
#endif // BTF_INFO_H_
