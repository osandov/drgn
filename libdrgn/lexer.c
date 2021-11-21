// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drgn.h"
#include "lexer.h"

DEFINE_VECTOR_FUNCTIONS(drgn_token_vector)

void drgn_lexer_init(struct drgn_lexer *lexer, drgn_lexer_func func,
		     const char *str)
{
	lexer->func = func;
	lexer->p = str;
	drgn_token_vector_init(&lexer->stack);
}

void drgn_lexer_deinit(struct drgn_lexer *lexer)
{
	drgn_token_vector_deinit(&lexer->stack);
}

struct drgn_error *drgn_lexer_pop(struct drgn_lexer *lexer,
				  struct drgn_token *token)
{
	if (lexer->stack.size) {
		*token = *drgn_token_vector_pop(&lexer->stack);
		return NULL;
	} else {
		return lexer->func(lexer, token);
	}
}

struct drgn_error *drgn_lexer_push(struct drgn_lexer *lexer,
				   const struct drgn_token *token)
{
	if (!drgn_token_vector_append(&lexer->stack, token))
		return &drgn_enomem;
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
