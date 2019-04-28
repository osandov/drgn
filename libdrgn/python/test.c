// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/*
 * Wrapper functions for testing.
 *
 * In order to test a few internal interfaces that don't have Python bindings,
 * we export some wrappers for those interfaces and for some required
 * libelf/libdw helpers. These wrappers are accessed via ctypes.
 */

#include "drgnpy.h"

#include "../internal.h"
#include "../lexer.h"
#include "../serialize.h"

DRGNPY_PUBLIC const char *drgn_test_elf_errmsg(int error)
{
	return elf_errmsg(error);
}

DRGNPY_PUBLIC Elf *drgn_test_elf_memory(char *image, size_t size)
{
	return elf_memory(image, size);
}

DRGNPY_PUBLIC int drgn_test_elf_end(Elf *elf)
{
	return elf_end(elf);
}

DRGNPY_PUBLIC const char *drgn_test_dwarf_errmsg(int error)
{
	return dwarf_errmsg(error);
}

DRGNPY_PUBLIC Dwarf *drgn_test_dwarf_begin_elf(Elf *elf, unsigned int cmd,
					       Elf_Scn *scngrp)
{
	return dwarf_begin_elf(elf, cmd, scngrp);
}

DRGNPY_PUBLIC int drgn_test_dwarf_end(Dwarf *dwarf)
{
	return dwarf_end(dwarf);
}

DRGNPY_PUBLIC int drgn_test_dwarf_nextcu(Dwarf *dwarf, uint64_t off,
					 uint64_t *next_off,
					 size_t *header_sizep,
					 uint64_t *abbrev_offsetp,
					 uint8_t *address_sizep,
					 uint8_t *offset_sizep)
{
	Dwarf_Off dwarf_next_off, dwarf_abbrev_offset;
	int ret;

	ret = dwarf_nextcu(dwarf, off, &dwarf_next_off, header_sizep,
			   &dwarf_abbrev_offset, address_sizep, offset_sizep);
	if (ret)
		return ret;
	if (next_off)
		*next_off = dwarf_next_off;
	if (abbrev_offsetp)
		*abbrev_offsetp = dwarf_abbrev_offset;
	return 0;
}

DRGNPY_PUBLIC Dwarf_Die *drgn_test_dwarf_offdie(Dwarf *dbg, uint64_t offset,
						Dwarf_Die *result)
{
	return dwarf_offdie(dbg, offset, result);
}

DRGNPY_PUBLIC int drgn_test_dwarf_tag(Dwarf_Die *die)
{
	return dwarf_tag(die);
}

DRGNPY_PUBLIC int drgn_test_dwarf_child(Dwarf_Die *die, Dwarf_Die *result)
{
	return dwarf_child(die, result);
}

DRGNPY_PUBLIC int drgn_test_dwarf_siblingof(Dwarf_Die *die, Dwarf_Die *result)
{
	return dwarf_siblingof(die, result);
}

DRGNPY_PUBLIC void drgn_test_lexer_init(struct drgn_lexer *lexer,
					drgn_lexer_func func, const char *str)
{
	return drgn_lexer_init(lexer, func, str);
}

DRGNPY_PUBLIC void drgn_test_lexer_deinit(struct drgn_lexer *lexer)
{
	return drgn_lexer_deinit(lexer);
}

DRGNPY_PUBLIC struct drgn_error *drgn_test_lexer_pop(struct drgn_lexer *lexer,
						     struct drgn_token *token)
{
	return drgn_lexer_pop(lexer, token);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_lexer_push(struct drgn_lexer *lexer, const struct drgn_token *token)
{
	return drgn_lexer_push(lexer, token);
}

DRGNPY_PUBLIC struct drgn_error *drgn_test_lexer_peek(struct drgn_lexer *lexer,
						      struct drgn_token *token)
{
	return drgn_lexer_peek(lexer, token);
}

DRGNPY_PUBLIC struct drgn_error *drgn_test_lexer_func(struct drgn_lexer *lexer,
						      struct drgn_token *token)
{
	token->kind = *lexer->p;
	token->value = lexer->p;
	if (token->kind) {
		token->len = 1;
		lexer->p++;
	} else {
		token->len = 0;
	}
	return NULL;
}

DRGNPY_PUBLIC struct drgn_error *drgn_test_lexer_c(struct drgn_lexer *lexer,
						   struct drgn_token *token)
{
	return drgn_lexer_c(lexer, token);
}

DRGNPY_PUBLIC bool drgn_test_path_iterator_next(struct path_iterator *it,
						const char **component,
						size_t *component_len)
{
	return path_iterator_next(it, component, component_len);
}

DRGNPY_PUBLIC bool drgn_test_path_ends_with(struct path_iterator *haystack,
					    struct path_iterator *needle)
{
	return path_ends_with(haystack, needle);
}

DRGNPY_PUBLIC void drgn_test_serialize_bits(void *buf, uint64_t bit_offset,
					    uint64_t uvalue, uint8_t bit_size,
					    bool little_endian)
{
	return serialize_bits(buf, bit_offset, uvalue, bit_size, little_endian);
}

DRGNPY_PUBLIC uint64_t drgn_test_deserialize_bits(const void *buf,
						  uint64_t bit_offset,
						  uint8_t bit_size,
						  bool little_endian)
{
	return deserialize_bits(buf, bit_offset, bit_size, little_endian);
}
