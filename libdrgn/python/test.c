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
#include "../dwarf_index.h"
#include "../lexer.h"
#include "../memory_reader.h"
#include "../object_index.h"
#include "../serialize.h"
#include "../type_index.h"

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

DRGNPY_PUBLIC struct drgn_error *
drgn_test_dwarf_index_create(int flags, struct drgn_dwarf_index **ret)
{
	return drgn_dwarf_index_create(flags, ret);
}

DRGNPY_PUBLIC void
drgn_test_dwarf_index_destroy(struct drgn_dwarf_index *dindex)
{
	return drgn_dwarf_index_destroy(dindex);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_dwarf_index_open(struct drgn_dwarf_index *dindex, const char *path,
			   Elf **elf)
{
	return drgn_dwarf_index_open(dindex, path, elf);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_dwarf_index_open_elf(struct drgn_dwarf_index *dindex, Elf *elf)
{
	return drgn_dwarf_index_open_elf(dindex, elf);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_dwarf_index_update(struct drgn_dwarf_index *dindex)
{
	return drgn_dwarf_index_update(dindex);
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

DRGNPY_PUBLIC void
drgn_test_memory_reader_destroy(struct drgn_memory_reader *reader)
{
	drgn_memory_reader_destroy(reader);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_memory_reader_read(struct drgn_memory_reader *reader, void *buf,
			     uint64_t address, size_t count, bool physical)
{
	return drgn_memory_reader_read(reader, buf, address, count, physical);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_memory_file_reader_create(int fd, struct drgn_memory_reader **ret)
{
	struct drgn_error *err;
	struct drgn_memory_file_reader *freader;

	err = drgn_memory_file_reader_create(fd, &freader);
	if (err)
		return err;
	*ret = &freader->reader;
	return NULL;
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_memory_file_reader_add_segment(struct drgn_memory_reader *reader,
					 const struct drgn_memory_file_segment *segment)
{
	struct drgn_memory_file_reader *freader;

	freader = container_of(reader, struct drgn_memory_file_reader, reader);
	return drgn_memory_file_reader_add_segment(freader, segment);
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

DRGNPY_PUBLIC void drgn_test_type_index_destroy(struct drgn_type_index *tindex)
{
	return drgn_type_index_destroy(tindex);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_type_index_find(struct drgn_type_index *tindex, const char *name,
			  const char *filename, struct drgn_qualified_type *ret)
{
	return drgn_type_index_find(tindex, name, filename, &drgn_language_c,
				    ret);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_type_from_dwarf(struct drgn_type_index *tindex, Dwarf_Die *die,
			  struct drgn_qualified_type *ret)
{
	struct drgn_dwarf_type_index *dtindex;

	dtindex = container_of(tindex, struct drgn_dwarf_type_index, tindex);
	return drgn_type_from_dwarf(dtindex, die, ret);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_dwarf_type_index_create(struct drgn_dwarf_index *dindex,
				  struct drgn_type_index **ret)
{
	struct drgn_error *err;
	struct drgn_dwarf_type_index *dtindex;

	err = drgn_dwarf_type_index_create(dindex, &dtindex);
	if (err)
		return err;

	*ret = &dtindex->tindex;
	return NULL;
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_mock_type_index_create(uint8_t word_size, bool little_endian,
				 struct drgn_mock_type *types, size_t num_types,
				 struct drgn_type_index **ret)
{
	struct drgn_error *err;
	struct drgn_mock_type_index *mtindex;

	err = drgn_mock_type_index_create(word_size, little_endian, types,
					  num_types, &mtindex);
	if (err)
		return err;

	*ret = &mtindex->tindex;
	return NULL;
}

DRGNPY_PUBLIC void
drgn_test_object_index_destroy(struct drgn_object_index *oindex)
{
	drgn_object_index_destroy(oindex);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_object_index_find(struct drgn_object_index *oindex,
			    const char *name, const char *filename,
			    enum drgn_find_object_flags flags,
			    struct drgn_partial_object *ret)
{
	return drgn_object_index_find(oindex, name, filename, flags, ret);
}

DRGNPY_PUBLIC struct drgn_error *
drgn_test_dwarf_object_index_create(struct drgn_type_index *tindex,
				    struct drgn_object_index **ret)
{
	struct drgn_error *err;
	struct drgn_dwarf_type_index *dtindex;
	struct drgn_dwarf_object_index *doindex;

	dtindex = container_of(tindex, struct drgn_dwarf_type_index, tindex);
	err = drgn_dwarf_object_index_create(dtindex, &doindex);
	if (err)
		return err;
	*ret = &doindex->oindex;
	return NULL;
}
