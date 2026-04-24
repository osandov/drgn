// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <inttypes.h>

#include "bitmap.h"
#include "hexlify.h"
#include "minmax.h"
#include "register_state.h"
#include "string_builder.h"

#define ERROR_IF_FROZEN(regs)							\
	do {									\
		if ((regs)->frozen) {						\
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,	\
						 "register state cannot be modified");\
		}								\
	} while (0)

struct drgn_register_state *
drgn_register_state_create_internal(struct drgn_program *prog, bool interrupted,
				    size_t buf_capacity)
{
	struct drgn_register_state *regs = drgn_register_state_alloc(prog);
	if (!regs)
		return regs;
	if (buf_capacity > 0) {
		regs->buf = malloc(buf_capacity);
		if (!regs->buf) {
			drgn_register_state_decref(regs);
			return NULL;
		}
		regs->buf_capacity = buf_capacity;
	}
	regs->interrupted = interrupted;
	return regs;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_register_state_create(struct drgn_program *prog,
					      bool interrupted,
					      struct drgn_register_state **ret)
{
	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program architecture is not known");
	}
	struct drgn_register_state *regs =
		drgn_register_state_create_internal(prog, interrupted, 0);
	if (!regs)
		return &drgn_enomem;
	*ret = regs;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_register_state *
drgn_register_state_copy(const struct drgn_register_state *regs)
{
	size_t buf_capacity = 0;
	size_t max_known = drgn_bitmap_last_set(regs->known,
						DRGN_REGISTER_STATE_KNOWN_NUM_BITS);
	if (max_known >= 2 && max_known < DRGN_REGISTER_STATE_KNOWN_NUM_BITS) {
		const struct drgn_register_layout *layout =
			&regs->prog->platform.arch->register_layout[max_known - 2];
		buf_capacity = layout->offset + layout->size;
	}
	struct drgn_register_state *ret =
		drgn_register_state_create_internal(regs->prog,
						    regs->interrupted,
						    buf_capacity);
	if (!ret)
		return NULL;
	memcpy(ret->known, regs->known, sizeof(ret->known));
	ret->_pc = regs->_pc;
	ret->_cfa = regs->_cfa;
	if (buf_capacity > 0)
		memcpy(ret->buf, regs->buf, buf_capacity);
	ret->_module = regs->_module;
	ret->module_cached = regs->module_cached;
	// NB: the copy is not frozen even if the original was.
	return ret;
}

LIBDRGN_PUBLIC const struct drgn_register *
drgn_register_state_register_by_name(const struct drgn_register_state *regs,
				     const char *name)
{
	return drgn_platform_register_by_name(&regs->prog->platform, name);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_format_register_state(const struct drgn_register_state *regs, char **ret)
{
	STRING_BUILDER(sb);

	struct drgn_optional_u64 pc = drgn_register_state_pc(regs);
	if (pc.has_value
	    && !string_builder_appendf(&sb, "PC = 0x%" PRIx64, pc.value))
		return &drgn_enomem;

	struct drgn_optional_u64 cfa = drgn_register_state_cfa(regs);
	if (cfa.has_value
	    && (!string_builder_space_break(&sb)
		|| !string_builder_appendf(&sb, "CFA = 0x%" PRIx64, cfa.value)))
		return &drgn_enomem;

	if (drgn_register_state_interrupted(regs)
	    && (!string_builder_space_break(&sb)
		|| !string_builder_append(&sb, "(interrupted)")))
		return &drgn_enomem;

	const struct drgn_platform *platform = &regs->prog->platform;
	bool little_endian = drgn_platform_is_little_endian(platform);
	size_t num_registers = drgn_platform_num_registers(platform);
	for (size_t i = 0; i < num_registers; i++) {
		const struct drgn_register *reg =
			drgn_platform_register(platform, i);

		if (!drgn_register_state_is_set_internal(regs, reg->regno))
			continue;

		const struct drgn_register_layout *layout =
			&reg->arch->register_layout[reg->regno];

		if (!string_builder_line_break(&sb)
		    || !string_builder_appendf(&sb, "%-7s 0x", reg->names[0])
		    || !string_builder_reserve_for_append(&sb,
							  layout->size * 2))
			return &drgn_enomem;

		if (little_endian) {
			hexlify_reversed(&regs->buf[layout->offset],
					 layout->size, &sb.str[sb.len]);
		} else {
			hexlify(&regs->buf[layout->offset], layout->size,
				&sb.str[sb.len]);
		}
		sb.len += layout->size * 2;
	}

	if (sb.len == 0 && !string_builder_append(&sb, "(empty)"))
		return &drgn_enomem;

	if (!string_builder_null_terminate(&sb))
		return &drgn_enomem;
	*ret = string_builder_steal(&sb);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_register_state_set_interrupted(struct drgn_register_state *regs,
				    bool interrupted)
{
	ERROR_IF_FROZEN(regs);
	regs->interrupted = interrupted;
	regs->module_cached = false;
	return NULL;
}

bool drgn_register_state_is_known(const struct drgn_register_state *regs,
				  size_t i)
{
	return drgn_bitmap_test_bit(regs->known, i);
}

void drgn_register_state_set_known(struct drgn_register_state *regs, size_t i)
{
	drgn_bitmap_set_bit(regs->known, i);
}

void drgn_register_state_unset_known(struct drgn_register_state *regs, size_t i)
{
	drgn_bitmap_clear_bit(regs->known, i);
}

LIBDRGN_PUBLIC struct drgn_optional_u64
drgn_register_state_pc(const struct drgn_register_state *regs)
{
	return (struct drgn_optional_u64){
		regs->_pc,
		drgn_register_state_is_known(regs, 0),
	};
}

void drgn_register_state_set_pc_internal(struct drgn_register_state *regs,
					 uint64_t pc)
{
	regs->_pc = pc & drgn_platform_address_mask(&regs->prog->platform);
	drgn_register_state_set_known(regs, 0);
	regs->module_cached = false;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_register_state_set_pc(struct drgn_register_state *regs,
					      uint64_t pc)
{
	ERROR_IF_FROZEN(regs);
	drgn_register_state_set_pc_internal(regs, pc);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_register_state_unset_pc(struct drgn_register_state *regs)
{
	ERROR_IF_FROZEN(regs);
	drgn_register_state_unset_known(regs, 0);
	regs->module_cached = false;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_optional_u64
drgn_register_state_cfa(const struct drgn_register_state *regs)
{
	return (struct drgn_optional_u64){
		regs->_cfa,
		drgn_register_state_is_known(regs, 1),
	};
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_register_state_set_cfa(struct drgn_register_state *regs,
					       uint64_t cfa)
{
	ERROR_IF_FROZEN(regs);
	regs->_cfa = cfa & drgn_platform_address_mask(&regs->prog->platform);
	drgn_register_state_set_known(regs, 1);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_register_state_unset_cfa(struct drgn_register_state *regs)
{
	ERROR_IF_FROZEN(regs);
	drgn_register_state_unset_known(regs, 1);
	return NULL;
}

LIBDRGN_PUBLIC bool
drgn_register_state_is_set(const struct drgn_register_state *regs,
			   const struct drgn_register *reg)
{
	return reg->arch == regs->prog->platform.arch
		&& drgn_register_state_is_set_internal(regs, reg->regno);
}

static inline struct drgn_optional_u64
drgn_register_state_get_known_u64(const struct drgn_register_state *regs,
				  size_t reg_offset, size_t reg_size)
{
	struct drgn_optional_u64 ret;
	ret.has_value = true;
	copy_lsbytes(&ret.value, sizeof(ret.value), HOST_LITTLE_ENDIAN,
		     &regs->buf[reg_offset], reg_size,
		     drgn_platform_is_little_endian(&regs->prog->platform));
	return ret;
}

struct drgn_optional_u64
drgn_register_state_get_u64_internal(struct drgn_register_state *regs,
				     drgn_register_number regno,
				     size_t reg_offset, size_t reg_size)
{
	if (!drgn_register_state_is_known(regs, regno + 2))
		return (struct drgn_optional_u64){};
	return drgn_register_state_get_known_u64(regs, reg_offset, reg_size);
}

LIBDRGN_PUBLIC struct drgn_optional_u64
drgn_register_state_get_u64(const struct drgn_register_state *regs,
			    const struct drgn_register *reg)
{
	if (!drgn_register_state_is_set(regs, reg))
		return (struct drgn_optional_u64){};
	const struct drgn_register_layout *layout =
		&reg->arch->register_layout[reg->regno];
	return drgn_register_state_get_known_u64(regs, layout->offset,
						 layout->size);
}

LIBDRGN_PUBLIC
bool drgn_register_state_get_raw(const struct drgn_register_state *regs,
				 const struct drgn_register *reg, void *buf)
{
	if (!drgn_register_state_is_set(regs, reg))
		return false;
	const struct drgn_register_layout *layout =
		&reg->arch->register_layout[reg->regno];
	memcpy(buf, &regs->buf[layout->offset], layout->size);
	return true;
}

void
drgn_register_state_set_register_range_known(struct drgn_register_state *regs,
					     drgn_register_number first_regno,
					     drgn_register_number last_regno)
{
	assert(first_regno <= last_regno);
	for (size_t i = first_regno + 2, j = last_regno + 2; i <= j; i++)
		drgn_register_state_set_known(regs, i);
}

static bool drgn_register_state_reserve(struct drgn_register_state *regs,
					size_t capacity)
{
	if (capacity <= regs->buf_capacity)
		return true;
	capacity = max(capacity,
		       min(regs->buf_capacity * 2,
			   regs->prog->platform.arch->register_layout_size));
	unsigned char *tmp = realloc(regs->buf, capacity);
	if (!tmp)
		return false;
	regs->buf = tmp;
	regs->buf_capacity = capacity;
	return true;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_register_state_set_u64(struct drgn_register_state *regs,
			    const struct drgn_register *reg, uint64_t value)
{
	if (reg->arch != regs->prog->platform.arch) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "register is from wrong architecture");
	}
	ERROR_IF_FROZEN(regs);
	const struct drgn_register_layout *layout =
		&reg->arch->register_layout[reg->regno];
	if (!drgn_register_state_reserve(regs, layout->offset + layout->size))
		return &drgn_enomem;
	drgn_register_state_set_u64_internal(regs, reg->regno, layout->offset,
					     layout->size, value);
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_register_state_set_raw(struct drgn_register_state *regs,
					       const struct drgn_register *reg,
					       const void *buf)
{
	if (reg->arch != regs->prog->platform.arch) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "register is from wrong architecture");
	}
	ERROR_IF_FROZEN(regs);
	const struct drgn_register_layout *layout =
		&reg->arch->register_layout[reg->regno];
	if (!drgn_register_state_reserve(regs, layout->offset + layout->size))
		return &drgn_enomem;
	drgn_register_state_set_raw_internal(regs, reg->regno, layout->offset,
					     layout->size, buf);
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_register_state_unset(struct drgn_register_state *regs,
					     const struct drgn_register *reg)
{
	if (reg->arch != regs->prog->platform.arch) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "register is from wrong architecture");
	}
	ERROR_IF_FROZEN(regs);
	drgn_register_state_unset_internal(regs, reg->regno);
	return NULL;
}

struct drgn_module *
drgn_register_state_module(struct drgn_register_state *regs)
{
	if (!regs->module_cached) {
		if (drgn_register_state_is_known(regs, 0)) {
			regs->_module = drgn_module_find_by_address(regs->prog,
								    regs->_pc
								    - !regs->interrupted);
		} else {
			regs->_module = NULL;
		}
		regs->module_cached = true;
	}
	return regs->_module;
}
