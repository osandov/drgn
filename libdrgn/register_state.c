// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <elfutils/libdwfl.h>
#include <limits.h>

#include "debug_info.h"
#include "register_state.h"

#define drgn_register_state_known_bitset(regs) ({	\
	__auto_type _state = (regs);			\
	&_state->buf[_state->regs_size];		\
})

static inline uint32_t drgn_register_state_bitset_size(uint16_t num_regs)
{
	return ((uint32_t)num_regs + CHAR_BIT + 1) / CHAR_BIT;
}

struct drgn_register_state *drgn_register_state_create_impl(uint32_t regs_size,
							    uint16_t num_regs,
							    bool interrupted)
{
	uint32_t bitset_size = drgn_register_state_bitset_size(num_regs);
	size_t size;
	struct drgn_register_state *regs;
	if (__builtin_add_overflow(regs_size, bitset_size, &size) ||
	    __builtin_add_overflow(size, sizeof(*regs), &size) ||
	    !(regs = malloc(size)))
		return NULL;
	regs->module = NULL;
	regs->regs_size = regs_size;
	regs->num_regs = num_regs;
	regs->interrupted = interrupted;
	memset(drgn_register_state_known_bitset(regs), 0, bitset_size);
	return regs;
}

struct drgn_register_state *
drgn_register_state_dup(const struct drgn_register_state *regs)
{
	size_t size;
	struct drgn_register_state *ret;
	if (__builtin_add_overflow(regs->regs_size,
				   drgn_register_state_bitset_size(regs->num_regs),
				   &size) ||
	    __builtin_add_overflow(size, sizeof(*ret), &size) ||
	    !(ret = malloc(size)))
		return NULL;
	memcpy(ret, regs, size);
	return ret;
}

static bool
drgn_register_state_is_known(const struct drgn_register_state *regs, uint32_t i)
{
	const unsigned char *bitset = drgn_register_state_known_bitset(regs);
	return (bitset[i / CHAR_BIT] & (1 << (i % CHAR_BIT))) != 0;
}

static void drgn_register_state_set_known(struct drgn_register_state *regs,
					  uint32_t i)
{
	unsigned char *bitset = drgn_register_state_known_bitset(regs);
	bitset[i / CHAR_BIT] |= 1 << (i % CHAR_BIT);
}

bool drgn_register_state_has_register(const struct drgn_register_state *regs,
				      drgn_register_number regno)
{
	return (regno < regs->num_regs &&
		drgn_register_state_is_known(regs, (uint32_t)regno + 2));
}

void drgn_register_state_set_has_register(struct drgn_register_state *regs,
					  drgn_register_number regno)
{
	assert(regno < regs->num_regs);
	drgn_register_state_set_known(regs, (uint32_t)regno + 2);
}

void
drgn_register_state_set_has_register_range(struct drgn_register_state *regs,
					   drgn_register_number first_regno,
					   drgn_register_number last_regno)
{
	assert(first_regno <= last_regno);
	assert(last_regno < regs->num_regs);
	for (uint32_t regno = first_regno; regno <= last_regno; regno++)
		drgn_register_state_set_known(regs, regno + 2);
}

struct optional_uint64
drgn_register_state_get_pc(const struct drgn_register_state *regs)
{
	return (struct optional_uint64){
		regs->_pc,
		drgn_register_state_is_known(regs, 0),
	};
}

void drgn_register_state_set_pc(struct drgn_program *prog,
				struct drgn_register_state *regs, uint64_t pc)
{
	pc &= drgn_platform_address_mask(&prog->platform);
	regs->_pc = pc;
	drgn_register_state_set_known(regs, 0);
	Dwfl_Module *dwfl_module = dwfl_addrmodule(prog->dbinfo.dwfl,
						   pc - !regs->interrupted);
	if (dwfl_module) {
		void **userdatap;
		dwfl_module_info(dwfl_module, &userdatap, NULL, NULL,
				 NULL, NULL, NULL, NULL);
		regs->module = *userdatap;
	}
}

struct optional_uint64
drgn_register_state_get_cfa(const struct drgn_register_state *regs)
{
	return (struct optional_uint64){
		regs->_cfa,
		drgn_register_state_is_known(regs, 1),
	};
}

void drgn_register_state_set_cfa(struct drgn_program *prog,
				 struct drgn_register_state *regs, uint64_t cfa)
{
	regs->_cfa = cfa & drgn_platform_address_mask(&prog->platform);
	drgn_register_state_set_known(regs, 1);
}

struct optional_uint64
drgn_register_state_get_u64_impl(struct drgn_program *prog,
				 struct drgn_register_state *regs,
				 drgn_register_number regno,
				 size_t reg_offset, size_t reg_size)
{
	struct optional_uint64 ret = {
		.has_value = drgn_register_state_has_register(regs, regno),
	};
	if (ret.has_value) {
		copy_lsbytes(&ret.value, sizeof(ret.value), HOST_LITTLE_ENDIAN,
			     &regs->buf[reg_offset], reg_size,
			     drgn_platform_is_little_endian(&prog->platform));
	}
	return ret;
}
