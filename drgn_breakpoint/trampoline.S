/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/linkage.h>
#include <linux/objtool.h>
#include <asm/processor-flags.h>
#include <asm/unwind_hints.h>

/*
 * The kprobe handler makes a thread that hit a breakpoint "return" here
 * instead of to the breakpoint. Unlike the kprobe handler, this runs in the
 * context of whatever hit the breakpoint, so it can sleep.
 *
 * This is entered with interrupts disabled, the same stack pointer as at the
 * breakpoint, and %rdi pointing to a struct drgn_breakpoint_saved in a per-CPU
 * variable.
 */
SYM_CODE_START(drgn_breakpoint_trampoline)
	UNWIND_HINT_UNDEFINED
	ANNOTATE_NOENDBR
	/* Copy the struct pt_regs to the stack from the end. */
	pushq	160(%rdi)
	pushq	152(%rdi)
	pushq	144(%rdi)
	pushq	136(%rdi)
	pushq	128(%rdi)
	pushq	120(%rdi)
	pushq	112(%rdi)
	pushq	104(%rdi)
	pushq	96(%rdi)
	pushq	88(%rdi)
	pushq	80(%rdi)
	pushq	72(%rdi)
	pushq	64(%rdi)
	pushq	56(%rdi)
	pushq	48(%rdi)
	pushq	40(%rdi)
	pushq	32(%rdi)
	pushq	24(%rdi)
	pushq	16(%rdi)
	pushq	8(%rdi)
	pushq	(%rdi)
	UNWIND_HINT_REGS
	/* The rest of struct drgn_breakpoint_saved. */
	movq	168(%rdi), %rsi
	movq	176(%rdi), %rdx
	movq	%rsp, %rdi
	/* Interrupts were only enabled if they are in the saved flags. */
	testl	$X86_EFLAGS_IF, 144(%rsp)
	jz	1f
	sti
1:
	call	drgn_breakpoint_hit
	/*
	 * That returned with interrupts disabled so that this can't be
	 * preempted while the module is being unloaded. Returning restores the
	 * flags from the breakpoint.
	 */
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	popq	%r11
	popq	%r10
	popq	%r9
	popq	%r8
	popq	%rax
	popq	%rcx
	popq	%rdx
	popq	%rsi
	popq	%rdi
	/* Skip orig_ax. */
	addq	$8, %rsp
	UNWIND_HINT_IRET_REGS
	iretq
SYM_CODE_END(drgn_breakpoint_trampoline)
