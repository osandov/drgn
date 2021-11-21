// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Wrapper functions for testing.
 *
 * In order to test a few internal interfaces that don't have Python bindings,
 * we export some wrappers for those interfaces and for some required
 * libelf/libdw helpers. These wrappers are accessed via ctypes.
 */

#include "drgnpy.h"
#include "../lexer.h"
#include "../path.h"
#include "../serialize.h"

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
