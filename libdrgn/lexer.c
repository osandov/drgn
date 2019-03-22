// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "internal.h"
#include "lexer.h"

void drgn_lexer_init(struct drgn_lexer *lexer, drgn_lexer_func func,
		     const char *str)
{
	lexer->func = func;
	lexer->p = str;
	lexer->stack = NULL;
	lexer->stack_len = 0;
	lexer->stack_capacity = 0;
}

void drgn_lexer_deinit(struct drgn_lexer *lexer)
{
	free(lexer->stack);
}

struct drgn_error *drgn_lexer_pop(struct drgn_lexer *lexer,
				  struct drgn_token *token)
{
	if (lexer->stack_len) {
		*token = lexer->stack[--lexer->stack_len];
		return NULL;
	}

	return lexer->func(lexer, token);
}

struct drgn_error *drgn_lexer_push(struct drgn_lexer *lexer,
				   const struct drgn_token *token)
{
	if (lexer->stack_len >= lexer->stack_capacity) {
		size_t new_capacity;

		new_capacity = (lexer->stack_capacity ?
				2 * lexer->stack_capacity : 2);
		if (!resize_array(&lexer->stack, new_capacity))
			return &drgn_enomem;
		lexer->stack_capacity = new_capacity;
	}

	lexer->stack[lexer->stack_len++] = *token;
	return NULL;
}

struct drgn_error *drgn_lexer_peek(struct drgn_lexer *lexer,
				   struct drgn_token *token)
{
	struct drgn_error *err;

	err = drgn_lexer_pop(lexer, token);
	if (!err)
		err = drgn_lexer_push(lexer, token);
	return err;
}
