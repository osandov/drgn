// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <gelf.h>
#include <libelf.h>
#ifdef WITH_LZMA
#include <lzma.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#include "cleanup.h"
#include "debug_info.h"
#include "elf_file.h"
#include "elf_symtab.h"
#include "error.h"
#include "log.h"
#include "minmax.h"
#include "serialize.h"
#include "string_builder.h"
#include "util.h"

static struct drgn_error *find_elf_file_symtab(struct drgn_elf_file *file,
					       uint64_t bias,
					       struct drgn_elf_file **file_ret,
					       uint64_t *bias_ret,
					       Elf_Scn **scn_ret,
					       GElf_Word *strtab_idx_ret,
					       GElf_Word *num_local_symbols_ret,
					       bool *full_symtab_ret,
					       Elf_Scn **gnu_debugdata_ret)
{
	Elf_Scn *scn = NULL;
	size_t shstrndx;
	if (elf_getshdrstrndx(file->elf, &shstrndx))
		return drgn_error_libelf();
	while ((scn = elf_nextscn(file->elf, scn))) {
		GElf_Shdr shdr_mem, *shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			return drgn_error_libelf();

		const char *scnname = elf_strptr(file->elf, shstrndx, shdr->sh_name);
		if (scnname && gnu_debugdata_ret && shdr->sh_type == SHT_PROGBITS
		    && strcmp(".gnu_debugdata", scnname) == 0)
			*gnu_debugdata_ret = scn;

		if (shdr->sh_type == SHT_SYMTAB
		    || shdr->sh_type == SHT_DYNSYM) {
			*file_ret = file;
			*bias_ret = bias;
			*scn_ret = scn;
			*strtab_idx_ret = shdr->sh_link;
			*num_local_symbols_ret = shdr->sh_info;
			if (shdr->sh_type == SHT_SYMTAB) {
				*full_symtab_ret = true;
				return NULL;
			}
		}
	}
	return NULL;
}

#ifdef WITH_LZMA
static struct drgn_error *
drgn_error_lzma(lzma_ret code)
{
	switch (code) {
		case LZMA_MEM_ERROR:
			return &drgn_enomem;
		case LZMA_OPTIONS_ERROR:
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "lzma: invalid options");
		case LZMA_FORMAT_ERROR:
		case LZMA_DATA_ERROR:
		case LZMA_BUF_ERROR:
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "lzma: format error (%d)", code);
		default:
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "lzma: unknown error (%d)", code);
	}
}

static struct drgn_error *
load_gnu_debugdata_file(struct drgn_module *module, Elf_Scn *gnu_debugdata_scn,
			struct drgn_elf_file **file_ret)
{
	Elf_Data *gnu_debugdata_data;
	struct drgn_error *err;
	err = read_elf_section(gnu_debugdata_scn, &gnu_debugdata_data);
	if (err)
		return err;

	_cleanup_(lzma_end) lzma_stream stream = LZMA_STREAM_INIT;
	lzma_ret ret = lzma_stream_decoder(&stream, UINT64_MAX, 0);
	if (ret != LZMA_OK)
		return drgn_error_lzma(ret);

	stream.next_in = gnu_debugdata_data->d_buf;
	stream.avail_in = gnu_debugdata_data->d_size;

	// Use the input buffer size as the initial capacity. We'll expand it as
	// needed.
	size_t capacity = gnu_debugdata_data->d_size;
	_cleanup_free_ void *data = malloc(capacity);
	if (!data)
		return &drgn_enomem;

	stream.next_out = data;
	stream.avail_out = capacity;

	size_t bytes_decoded;
	while (1) {
		ret = lzma_code(&stream, LZMA_RUN);
		if (ret != LZMA_OK && ret != LZMA_STREAM_END)
			return drgn_error_lzma(ret);

		bytes_decoded = (char *)stream.next_out - (char *)data;
		if (ret == LZMA_STREAM_END) {
			void *tmp = realloc(data, bytes_decoded);
			if (tmp)
				data = tmp;
			break;
		} else if (__builtin_mul_overflow(capacity, 2U, &capacity)) {
			return &drgn_enomem;
		} else {
			void *tmp = realloc(data, capacity);
			if (!tmp)
				return &drgn_enomem;
			data = tmp;
			stream.next_out = (uint8_t *)data + bytes_decoded;
			stream.avail_out = capacity - bytes_decoded;
		}
	}

	STRING_BUILDER(path);
	if (!string_builder_appendf(&path, "%s[.gnu_debugdata]", module->loaded_file->path)
	    || !string_builder_null_terminate(&path))
		return &drgn_enomem;

	Elf *elf = elf_memory(data, bytes_decoded);
	if (!elf)
		return drgn_error_libelf();

	err = drgn_elf_file_create(module, path.str, -1, data, elf, file_ret);
	if (err)
		elf_end(elf);
	else
		data = NULL;
	return err;
}
#else
static struct drgn_error *
load_gnu_debugdata_file(struct drgn_module *module, Elf_Scn *gnu_debugdata_scn,
			struct drgn_elf_file **ret)
{
	drgn_log_info(module->prog,
		      "module \"%s\": .gnu_debugdata is available, but drgn was built without liblzma support",
		      module->name);
	return NULL;
}
#endif

static struct drgn_error *
set_elf_symtab(struct drgn_elf_symbol_table *symtab, struct drgn_elf_file *file,
	       uint64_t bias, Elf_Scn *symtab_scn, GElf_Word strtab_idx,
	       GElf_Word num_local_symbols)
{
	Elf_Scn *strtab_scn = elf_getscn(file->elf, strtab_idx);
	if (!strtab_scn)
		return drgn_error_libelf();

	struct drgn_error *err;
	Elf_Data *data, *strtab_data;
	if ((err = read_elf_section(symtab_scn, &data))
	    || (err = read_elf_section(strtab_scn, &strtab_data)))
		return err;

	truncate_elf_string_data(strtab_data);

	Elf_Data *shndx_data = NULL;
	int shndx_idx = elf_scnshndx(symtab_scn);
	if (shndx_idx > 0) {
		Elf_Scn *shndx_scn = elf_getscn(file->elf, shndx_idx);
		if (!shndx_scn)
			return drgn_error_libelf();
		err = read_elf_section(shndx_scn, &shndx_data);
		if (err)
			return err;
	}

	symtab->file = file;
	symtab->bias = bias;
	symtab->data = data->d_buf;
	symtab->num_symbols =
		data->d_size
		/ (drgn_elf_file_is_64_bit(file)
		   ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym));
	if (num_local_symbols < 1)
		num_local_symbols = 1;
	if (num_local_symbols > symtab->num_symbols)
		num_local_symbols = symtab->num_symbols;
	symtab->num_local_symbols = num_local_symbols;
	symtab->strtab = strtab_data;
	symtab->shndx = shndx_data;
	return NULL;
}

static void
cleanup_elf_file(struct drgn_elf_file **pfile)
{
	if (*pfile) {
		drgn_elf_file_destroy(*pfile);
	}
}

static struct drgn_error *
find_module_elf_symtab(struct drgn_module *module)
{
	struct drgn_error *err;

	if (!module->elf_symtab_pending_files)
		return NULL;

	if (module->have_full_symtab) {
		module->elf_symtab_pending_files = 0;
		return NULL;
	}

	// The goal is to have the most complete symbol information, which we
	// can get from the following, in order of preference:
	// 1. A .symtab from the loaded or debug file (i.e. module->full_symtab
	//    is true)
	// 2. A .dynsym from the loaded file, as well as the .symtab from an
	//    embedded .gnu_debugdata file. (The .gnu_debugdata usually only
	//    contains complete function symbols, so we prefer #1 where
	//    possible)
	// 3. A .dynsym and no .gnu_debugdata

	struct drgn_elf_file *file = NULL;
	uint64_t bias;
	Elf_Scn *symtab_scn;
	GElf_Word strtab_idx, num_local_symbols;
	bool full_symtab = false;

	if (module->elf_symtab_pending_files & DRGN_MODULE_FILE_MASK_DEBUG) {
		err = find_elf_file_symtab(module->debug_file,
					   module->debug_file_bias, &file,
					   &bias, &symtab_scn, &strtab_idx,
					   &num_local_symbols, &full_symtab,
					   NULL);
		if (err)
			return err;
	}

	Elf_Scn *gnu_debugdata_scn = NULL;
	if (!full_symtab &&
	    (module->elf_symtab_pending_files & DRGN_MODULE_FILE_MASK_LOADED)) {
		err = find_elf_file_symtab(module->loaded_file,
					   module->loaded_file_bias, &file,
					   &bias, &symtab_scn, &strtab_idx,
					   &num_local_symbols, &full_symtab,
					   &gnu_debugdata_scn);
		if (err)
			return err;
	}

	if (!file && !gnu_debugdata_scn) {
		drgn_log_debug(module->prog, "%s: no ELF symbol table",
			       module->name);
		module->elf_symtab_pending_files = 0;
		return NULL;
	}

	// If we've found a dynamic symbol table, but we already saw a dynamic
	// table, don't bother replacing it, unless the new file contains
	// .gnu_debugdata (and thus the old one didn't).
	if (module->elf_symtab.num_symbols && !full_symtab && !gnu_debugdata_scn) {
		module->elf_symtab_pending_files = 0;
		return NULL;
	}

	if (file) {
		err = set_elf_symtab(&module->elf_symtab, file, bias, symtab_scn,
				     strtab_idx, num_local_symbols);
		if (err)
			return err;

		module->have_full_symtab = full_symtab;
		drgn_log_debug(module->prog,
			"%s: found ELF %ssymbol table with %zu symbols",
			module->name, full_symtab ? "" : "dynamic ",
			module->elf_symtab.num_symbols);
	}

	if (full_symtab && module->gnu_debugdata_symtab.num_symbols) {
		// With a full symbol table (likely from the debug file), there
		// is no need to keep around the gnu_debugdata symbol table.
		// We cannot free the memory associated with it, because we may
		// have returned symbols that refer to the strings in this file.
		// Stop using the symbol table, but delay freeing until the
		// program is freed.
		memset(&module->gnu_debugdata_symtab, 0,
		       sizeof(module->gnu_debugdata_symtab));
	} else if (!full_symtab && gnu_debugdata_scn) {
		// We only search for .gnu_debugdata in the loaded file, not the
		// debug file. Once attached to a module, files can't be
		// detached, so there should be no case where we load
		// .gnu_debugdata twice. Let's assert that precondition here.
		assert(module->gnu_debugdata_file == NULL);

		_cleanup_(cleanup_elf_file) struct drgn_elf_file *gnu_debugdata_file = NULL;

		err = load_gnu_debugdata_file(module, gnu_debugdata_scn,
					      &gnu_debugdata_file);
		if (err)
			return err;

		if (gnu_debugdata_file) {
			file = NULL;
			err = find_elf_file_symtab(gnu_debugdata_file,
						   module->loaded_file_bias, &file,
						   &bias, &symtab_scn, &strtab_idx,
						   &num_local_symbols, &full_symtab,
						   NULL);
			if (err)
				return err;

			if (file) {
				err = set_elf_symtab(&module->gnu_debugdata_symtab,
						     file, bias, symtab_scn,
						     strtab_idx, num_local_symbols);
				if (err)
					return err;

				module->gnu_debugdata_file = no_cleanup_ptr(gnu_debugdata_file);
				drgn_log_debug(module->prog,
					"%s: found ELF .gnu_debugdata symbol table with %zu symbols",
					module->name, module->gnu_debugdata_symtab.num_symbols);
			}
		}
	}

	module->elf_symtab_pending_files = 0;
	return NULL;
}

static size_t elf_symbol_shndx(struct drgn_elf_symbol_table *symtab,
			       size_t sym_idx, const GElf_Sym *sym)
{
	if (sym->st_shndx < SHN_LORESERVE)
		return sym->st_shndx;
	if (sym->st_shndx == SHN_XINDEX
	    && symtab->shndx
	    && sym_idx < symtab->shndx->d_size / sizeof(uint32_t)) {
		uint32_t tmp;
		memcpy(&tmp,
		       (const char *)symtab->shndx->d_buf
		       + sym_idx * sizeof(uint32_t),
		       sizeof(uint32_t));
		if (drgn_elf_file_bswap(symtab->file))
			tmp = bswap_32(tmp);
		return tmp;
	}
	return SHN_UNDEF;
}

static bool elf_symbol_address(struct drgn_elf_symbol_table *symtab,
			       size_t sym_idx, const GElf_Sym *sym, uint64_t *ret)
{
	uint64_t addr = sym->st_value;

	// On 32-bit Arm, the least significant bit of st_value in an STT_FUNC
	// symbol indicates whether it addresses a Thumb instruction. Clear it.
	//
	// P.S. If we need any more architecture-specific hacks, then we should
	// add a callback to drgn_architecture_info. Note that we don't
	// currently support V1 of the 64-bit PowerPC ELF ABI where st_value is
	// the address of a "function descriptor" instead of the function entry
	// point.
	if (symtab->file->platform.arch->arch == DRGN_ARCH_ARM
	    && GELF_ST_TYPE(sym->st_info) == STT_FUNC)
		addr &= ~1;

	// If the address is not in the module's address range, then it's
	// probably something special like a Linux per-CPU variable (which isn't
	// actually a variable address but an offset). Don't apply the bias in
	// that case.
	if (drgn_module_contains_address(symtab->file->module,
					 addr + symtab->bias))
		addr += symtab->bias;
	if (symtab->file->is_relocatable) {
		size_t shndx = elf_symbol_shndx(symtab, sym_idx, sym);
		if (shndx == SHN_UNDEF)
			return false;
		Elf_Scn *scn = elf_getscn(symtab->file->elf, shndx);
		if (!scn)
			return false;
		GElf_Shdr shdr_mem, *shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			return false;
		addr += shdr->sh_addr;
	}
	*ret = addr;
	return true;
}

// When searching for one symbol, if there are multiple matches, we break ties
// based on the symbol binding. The order of precedence is:
// GLOBAL = UNIQUE > WEAK > LOCAL = everything else
static int drgn_symbol_binding_precedence(const struct drgn_symbol *sym)
{
	SWITCH_ENUM(sym->binding) {
	case DRGN_SYMBOL_BINDING_GLOBAL:
	case DRGN_SYMBOL_BINDING_UNIQUE:
		return 3;
	case DRGN_SYMBOL_BINDING_WEAK:
		return 2;
	case DRGN_SYMBOL_BINDING_LOCAL:
	case DRGN_SYMBOL_BINDING_UNKNOWN:
		return 1;
	default:
		UNREACHABLE();
	}
}

static int elf_symbol_binding_precedence(const GElf_Sym *sym)
{
	switch (GELF_ST_BIND(sym->st_info)) {
	case STB_GLOBAL:
	case STB_GNU_UNIQUE:
		return 3;
	case STB_WEAK:
		return 2;
	default:
		return 1;
	}
}

// This assumes that both symbols contain the search address.
static bool better_addr_match(const GElf_Sym *a, uint64_t a_addr,
			      const struct drgn_symbol *b)
{
	// Prefer the symbol that starts closer to the search address.
	if (a_addr > b->address)
		return true;
	if (a_addr < b->address)
		return false;

	// If the symbols have the same start address, prefer the one that ends
	// closer to the search address.
	if (a->st_size < b->size)
		return true;
	if (a->st_size > b->size)
		return false;

	// If the symbols have the same start and end addresses, prefer the one
	// with the higher binding precedence.
	return elf_symbol_binding_precedence(a)
	       > drgn_symbol_binding_precedence(b);
}

// This assumes that both symbols start before the search address and have size
// 0.
static bool better_sizeless_addr_match(const GElf_Sym *a, uint64_t a_addr,
				       const GElf_Sym *b, uint64_t b_addr)
{
	// Prefer the symbol that starts closer to the search address.
	if (a_addr > b_addr)
		return true;
	if (a_addr < b_addr)
		return false;

	// If the symbols have the same start address, prefer the one with the
	// higher binding precedence.
	return elf_symbol_binding_precedence(a)
	       > elf_symbol_binding_precedence(b);
}

static bool addr_in_sym_section(struct drgn_elf_symbol_table *symtab,
				size_t sym_idx, const GElf_Sym *sym,
				uint64_t unbiased_addr)
{
	size_t shndx = elf_symbol_shndx(symtab, sym_idx, sym);
	if (shndx == SHN_UNDEF)
		return false;
	Elf_Scn *scn = elf_getscn(symtab->file->elf, shndx);
	if (!scn)
		return false;
	GElf_Shdr shdr_mem, *shdr = gelf_getshdr(scn, &shdr_mem);
	if (!shdr)
		return false;
	return unbiased_addr >= shdr->sh_addr
	       && (unbiased_addr - shdr->sh_addr < shdr->sh_size);
}

struct elf_symtab_search_state {
	// Handwritten assembly functions may have a symbol size of 0 even
	// though logically they have a size. The best we can do is assume that
	// such a symbol extends until the next symbol. If we're searching by
	// address and we don't find any symbols containing the address, then we
	// will return a symbol with size 0 that could contain it based on this
	// assumption.
	const char *sizeless_name;
	uint64_t sizeless_addr;
	size_t sizeless_sym_idx;
	struct drgn_elf_symbol_table *sizeless_symtab;
	Elf64_Sym sizeless_sym;

	// If we're searching for one symbol, then we may already have a match,
	// but we still need to search for a better match.
	struct drgn_symbol *best_sym;

	// The maximum end address of any symbol starting before the given
	// address. Any symbol with size 0 starting before this is either
	// contained within another symbol or is assumed to end before this, so
	// it should be ignored.
	uint64_t max_end_addr;
};

static struct drgn_error *
drgn_elf_symbol_table_search(struct drgn_elf_symbol_table *symtab, const char *name,
			     uint64_t addr, enum drgn_find_symbol_flags flags,
			     struct elf_symtab_search_state *state,
			     struct drgn_symbol_result_builder *builder)
{
	const bool is_64_bit = drgn_elf_file_is_64_bit(symtab->file);
	const bool bswap = drgn_elf_file_bswap(symtab->file);
	const size_t sym_size =
		is_64_bit ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);

	// If we already have a match, and we're not searching by address, then
	// we will never prefer a local symbol over that match, so we can skip
	// local symbols. For address searches, we can't skip local addresses,
	// because we prioritize the closest match to the address.
	//
	// Otherwise, skip the undefined symbol at index 0.
	for (size_t i = !(flags & DRGN_FIND_SYMBOL_ADDR) && state->best_sym
		        ? symtab->num_local_symbols : 1;
	     i < symtab->num_symbols; i++) {
		Elf64_Sym elf_sym;
#define visit_elf_sym_members(visit_scalar_member, visit_raw_member) do {	\
	visit_scalar_member(st_name);						\
	visit_scalar_member(st_info);						\
	visit_scalar_member(st_other);						\
	visit_scalar_member(st_shndx);						\
	visit_scalar_member(st_value);						\
	visit_scalar_member(st_size);						\
} while (0)
		deserialize_struct64(&elf_sym, Elf32_Sym, visit_elf_sym_members,
				     symtab->data + i * sym_size,
				     is_64_bit, bswap);
#undef visit_elf_sym_members

		// Ignore undefined symbols.
		if (elf_sym.st_shndx == SHN_UNDEF)
			continue;

		// Ignore symbols with an out-of-bounds name.
		if (elf_sym.st_name >= symtab->strtab->d_size)
			continue;
		const char *elf_sym_name =
			(const char *)symtab->strtab->d_buf
			+ elf_sym.st_name;

		if ((flags & DRGN_FIND_SYMBOL_NAME)
		    && strcmp(elf_sym_name, name) != 0)
			continue;

		if (flags & DRGN_FIND_SYMBOL_ADDR) {
			// Ignore these special symbol types for address
			// searches (before we bother computing the address).
			switch (GELF_ST_TYPE(elf_sym.st_info)) {
			case STT_SECTION:
			case STT_FILE:
			case STT_TLS:
				continue;
			default:
				break;
			}
		} else if (state->best_sym
			   // This is a non-address search for one symbol.
			   // Prefer the symbol with the higher binding
			   // precedence.
			   && elf_symbol_binding_precedence(&elf_sym)
			      <= drgn_symbol_binding_precedence(state->best_sym)) {
			continue;
		}

		uint64_t elf_sym_addr;
		if (!elf_symbol_address(symtab, i, &elf_sym, &elf_sym_addr))
			continue;

		if (flags & DRGN_FIND_SYMBOL_ADDR) {
			if (elf_sym_addr > addr)
				continue;

			state->max_end_addr = max(state->max_end_addr,
						  elf_sym_addr + elf_sym.st_size);

			if (elf_sym.st_size == 0) {
				if (!state->sizeless_name
				    || better_sizeless_addr_match(&elf_sym,
								  elf_sym_addr,
								  &state->sizeless_sym,
								  state->sizeless_addr)) {
					state->sizeless_name = elf_sym_name;
					state->sizeless_addr = elf_sym_addr;
					state->sizeless_sym_idx = i;
					state->sizeless_sym = elf_sym;
					state->sizeless_symtab = symtab;
				}
				continue;
			} else if (addr - elf_sym_addr >= elf_sym.st_size
				   || (state->best_sym
				       && !better_addr_match(&elf_sym,
							     elf_sym_addr,
							     state->best_sym))) {
				continue;
			}
		}

		if (!drgn_symbol_result_builder_add_from_elf(builder,
							     elf_sym_name,
							     elf_sym_addr,
							     &elf_sym))
			return &drgn_enomem;

		if (flags & DRGN_FIND_SYMBOL_ONE) {
			state->best_sym = drgn_symbol_result_builder_single(builder);
			if (!(flags & DRGN_FIND_SYMBOL_ADDR)) {
				// If we're not searching by address and we find
				// a matching global symbol, then we don't need
				// to search anymore.
				if (state->best_sym->binding == DRGN_SYMBOL_BINDING_GLOBAL
				    || state->best_sym->binding == DRGN_SYMBOL_BINDING_UNIQUE)
					return &drgn_stop;
				// Otherwise, if we're not searching by address
				// and we find a matching local symbol, then we
				// can skip past the remaining local symbols.
				if (i < symtab->num_local_symbols)
					i = symtab->num_local_symbols - 1;
			}
		}
	}
	return NULL;
}

struct drgn_error *
drgn_module_elf_symbols_search(struct drgn_module *module, const char *name,
			       uint64_t addr, enum drgn_find_symbol_flags flags,
			       struct drgn_symbol_result_builder *builder)
{
	struct drgn_error *err;

	err = find_module_elf_symtab(module);
	if (err)
		return err;

	struct elf_symtab_search_state state = {0};
	if (flags & DRGN_FIND_SYMBOL_ONE)
		state.best_sym = drgn_symbol_result_builder_single(builder);

	if (module->elf_symtab.num_symbols) {
		err = drgn_elf_symbol_table_search(&module->elf_symtab, name, addr,
						   flags, &state, builder);
		if (err)
			return err;
	}

	if (module->gnu_debugdata_symtab.num_symbols) {
		err = drgn_elf_symbol_table_search(&module->gnu_debugdata_symtab, name,
						   addr, flags, &state, builder);
		if (err)
			return err;
	}

	if (state.sizeless_name
	    && drgn_symbol_result_builder_count(builder) == 0
	    && state.sizeless_addr >= state.max_end_addr
	    && addr_in_sym_section(state.sizeless_symtab, state.sizeless_sym_idx,
				   &state.sizeless_sym, addr - state.sizeless_symtab->bias)
	    && !drgn_symbol_result_builder_add_from_elf(builder, state.sizeless_name,
							state.sizeless_addr,
							&state.sizeless_sym))
		return &drgn_enomem;

	return NULL;
}
