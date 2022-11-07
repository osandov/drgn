// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-or-later

// Linux kernel module for testing drgn helpers and kernel support. For now,
// this is all in one file for simplicity and to keep the compilation fast
// (since this is compiled for every kernel version in CI).
//
// This is intended to be used with drgn's vmtest framework, but in theory it
// can be used with any kernel that has debug info enabled (at your own risk).

#include <linux/completion.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/rbtree_augmented.h>
#include <linux/slab.h>

// list

LIST_HEAD(drgn_test_empty_list);
LIST_HEAD(drgn_test_full_list);
LIST_HEAD(drgn_test_singular_list);
LIST_HEAD(drgn_test_corrupted_list);

struct drgn_test_list_entry {
	struct list_head node;
	int value;
};

struct drgn_test_list_entry drgn_test_list_entries[3];
struct drgn_test_list_entry drgn_test_singular_list_entry;
struct drgn_test_list_entry drgn_test_corrupted_list_entries[2];

HLIST_HEAD(drgn_test_empty_hlist);
HLIST_HEAD(drgn_test_full_hlist);

struct drgn_test_hlist_entry {
	struct hlist_node node;
	int value;
};

struct drgn_test_hlist_entry drgn_test_hlist_entries[3];

// Emulate a race condition between two threads calling list_add() at the same
// time.
static void init_corrupted_list(void)
{
	struct list_head *prev = &drgn_test_corrupted_list;
	struct list_head *next = drgn_test_corrupted_list.next;
	struct list_head *new1 = &drgn_test_corrupted_list_entries[0].node;
	struct list_head *new2 = &drgn_test_corrupted_list_entries[1].node;

	// Thread 1 starts list_add().
	next->prev = new1;

	// Thread 2 races in and does its own list_add().
	next->prev = new2;
	new2->next = next;
	new2->prev = prev;
	WRITE_ONCE(prev->next, new2);

	// Thread 1 finishes list_add().
	new1->next = next;
	new1->prev = prev;
	WRITE_ONCE(prev->next, new1);
}

static void drgn_test_list_init(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_list_entries); i++) {
		list_add_tail(&drgn_test_list_entries[i].node,
			      &drgn_test_full_list);
	}
	list_add(&drgn_test_singular_list_entry.node, &drgn_test_singular_list);

	for (i = ARRAY_SIZE(drgn_test_hlist_entries); i-- > 0;) {
		hlist_add_head(&drgn_test_hlist_entries[i].node,
			       &drgn_test_full_hlist);
	}

	init_corrupted_list();
}

// llist

LLIST_HEAD(drgn_test_empty_llist);
LLIST_HEAD(drgn_test_full_llist);
LLIST_HEAD(drgn_test_singular_llist);

struct drgn_test_llist_entry {
	struct llist_node node;
	int value;
};

struct drgn_test_llist_entry drgn_test_llist_entries[3];
struct drgn_test_llist_entry drgn_test_singular_llist_entry;

static void drgn_test_llist_init(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_llist_entries); i++) {
		llist_add(&drgn_test_llist_entries[i].node,
			      &drgn_test_full_llist);
	}

	llist_add(&drgn_test_singular_llist_entry.node, &drgn_test_singular_llist);
}

// mm

void *drgn_test_va;
phys_addr_t drgn_test_pa;
unsigned long drgn_test_pfn;
struct page *drgn_test_page;
struct page *drgn_test_compound_page;

static int drgn_test_mm_init(void)
{
	drgn_test_page = alloc_page(GFP_KERNEL);
	if (!drgn_test_page)
		return -ENOMEM;
	drgn_test_compound_page = alloc_pages(GFP_KERNEL | __GFP_COMP, 1);
	if (!drgn_test_compound_page)
		return -ENOMEM;
	drgn_test_va = page_address(drgn_test_page);
	drgn_test_pa = virt_to_phys(drgn_test_va);
	drgn_test_pfn = PHYS_PFN(drgn_test_pa);
	return 0;
}

static void drgn_test_mm_exit(void)
{
	if (drgn_test_compound_page)
		__free_pages(drgn_test_page, 1);
	if (drgn_test_page)
		__free_pages(drgn_test_page, 0);
}


// percpu

DEFINE_PER_CPU(unsigned int, drgn_test_percpu_static);
const unsigned int drgn_test_percpu_static_prime = 0xa45dcfc3U;
unsigned int __percpu *drgn_test_percpu_dynamic;
const unsigned int drgn_test_percpu_dynamic_prime = 0x6d80a613U;

static int drgn_test_percpu_init(void)
{
	int cpu;
	unsigned int static_prime = drgn_test_percpu_static_prime;
	unsigned int dynamic_prime = drgn_test_percpu_dynamic_prime;

	drgn_test_percpu_dynamic = alloc_percpu(unsigned int);
	if (!drgn_test_percpu_dynamic)
		return -ENOMEM;
	// Initialize the per-cpu variables to powers of a random prime number
	// which are extremely unlikely to appear anywhere else.
	for_each_possible_cpu(cpu) {
		static_prime *= drgn_test_percpu_static_prime;
		per_cpu(drgn_test_percpu_static, cpu) = static_prime;
		dynamic_prime *= drgn_test_percpu_dynamic_prime;
		*per_cpu_ptr(drgn_test_percpu_dynamic, cpu) = dynamic_prime;
	}
	return 0;
}

static void drgn_test_percpu_exit(void)
{
	free_percpu(drgn_test_percpu_dynamic);
}

// rbtree

struct rb_root drgn_test_empty_rb_root = RB_ROOT;
struct rb_root drgn_test_rb_root = RB_ROOT;

struct drgn_test_rb_entry {
	struct rb_node node;
	int value;
};

struct drgn_test_rb_entry drgn_test_rb_entries[4];

struct rb_node drgn_test_empty_rb_node;

struct rb_root drgn_test_rbtree_with_equal = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_equal[4];

struct rb_root drgn_test_rbtree_out_of_order = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_out_of_order[4];

struct rb_root drgn_test_rbtree_with_bad_root_parent = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entry_bad_root_parent;

struct rb_root drgn_test_rbtree_with_red_root = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entry_red_root;

struct rb_root drgn_test_rbtree_with_inconsistent_parents = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_inconsistent_parents[2];

struct rb_root drgn_test_rbtree_with_red_violation = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_red_violation[3];

struct rb_root drgn_test_rbtree_with_black_violation = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_black_violation[2];

static void drgn_test_rbtree_insert(struct rb_root *root,
				    struct drgn_test_rb_entry *entry)
{
	struct rb_node **new = &root->rb_node, *parent = NULL;

	while (*new) {
		struct drgn_test_rb_entry *this =
			container_of(*new, struct drgn_test_rb_entry, node);

		parent = *new;
		if (entry->value <= this->value)
			new = &(*new)->rb_left;
		else
			new = &(*new)->rb_right;
	}

	rb_link_node(&entry->node, parent, new);
	rb_insert_color(&entry->node, root);
}

static void drgn_test_rbtree_init(void)
{
	struct rb_node *node;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries); i++) {
		drgn_test_rb_entries[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rb_root,
					&drgn_test_rb_entries[i]);
	}
	RB_CLEAR_NODE(&drgn_test_empty_rb_node);

	// Red-black tree with entries that compare equal to each other.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_equal); i++) {
		drgn_test_rb_entries_with_equal[i].value = i / 2;
		drgn_test_rbtree_insert(&drgn_test_rbtree_with_equal,
					&drgn_test_rb_entries_with_equal[i]);
	}

	// Bad red-black tree whose entries are out of order.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_out_of_order); i++) {
		drgn_test_rb_entries_out_of_order[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rbtree_out_of_order,
					&drgn_test_rb_entries_out_of_order[i]);
	}
	drgn_test_rb_entries_out_of_order[0].value = 99;

	// Bad red-black tree with a root node that has a non-NULL parent.
	drgn_test_rbtree_insert(&drgn_test_rbtree_with_bad_root_parent,
				&drgn_test_rb_entry_bad_root_parent);
	rb_set_parent(&drgn_test_rb_entry_bad_root_parent.node,
		      &drgn_test_empty_rb_node);

	// Bad red-black tree with a red root node.
	rb_link_node(&drgn_test_rb_entry_red_root.node, NULL,
		     &drgn_test_rbtree_with_red_root.rb_node);

	// Bad red-black tree with inconsistent rb_parent.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_inconsistent_parents); i++) {
		drgn_test_rb_entries_with_inconsistent_parents[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rbtree_with_inconsistent_parents,
					&drgn_test_rb_entries_with_inconsistent_parents[i]);
	}
	node = drgn_test_rbtree_with_inconsistent_parents.rb_node;
	rb_set_parent(node->rb_left ? node->rb_left : node->rb_right,
		      &drgn_test_empty_rb_node);

	// Bad red-black tree with red node with red child.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_red_violation); i++)
		drgn_test_rb_entries_with_red_violation[i].value = i;
	drgn_test_rbtree_insert(&drgn_test_rbtree_with_red_violation,
				&drgn_test_rb_entries_with_red_violation[0]);
	rb_link_node(&drgn_test_rb_entries_with_red_violation[1].node,
		     &drgn_test_rb_entries_with_red_violation[0].node,
		     &drgn_test_rb_entries_with_red_violation[0].node.rb_right);
	rb_link_node(&drgn_test_rb_entries_with_red_violation[2].node,
		     &drgn_test_rb_entries_with_red_violation[1].node,
		     &drgn_test_rb_entries_with_red_violation[1].node.rb_right);

	// Bad red-black tree with unequal number of black nodes in paths from
	// root to leaves.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_black_violation); i++)
		drgn_test_rb_entries_with_black_violation[i].value = i;
	drgn_test_rbtree_insert(&drgn_test_rbtree_with_black_violation,
				&drgn_test_rb_entries_with_black_violation[0]);
	rb_link_node(&drgn_test_rb_entries_with_black_violation[1].node,
		     &drgn_test_rb_entries_with_black_violation[0].node,
		     &drgn_test_rb_entries_with_black_violation[0].node.rb_right);
	drgn_test_rb_entries_with_black_violation[1].node.__rb_parent_color |= RB_BLACK;
}

// slab

const int drgn_test_slob = IS_ENABLED(CONFIG_SLOB);
struct kmem_cache *drgn_test_small_kmem_cache;
struct kmem_cache *drgn_test_big_kmem_cache;

struct drgn_test_small_slab_object {
	int padding[11];
	int value;
};

struct drgn_test_big_slab_object {
	unsigned long padding[PAGE_SIZE / 3 * 4 / sizeof(unsigned long) - 1];
	unsigned long value;
};

struct drgn_test_small_slab_object *drgn_test_small_slab_objects[5];
struct drgn_test_big_slab_object *drgn_test_big_slab_objects[5];

static void drgn_test_slab_exit(void)
{
	size_t i;

	if (drgn_test_big_kmem_cache) {
		for (i = 0; i < ARRAY_SIZE(drgn_test_big_slab_objects); i++) {
			if (drgn_test_big_slab_objects[i]) {
				kmem_cache_free(drgn_test_big_kmem_cache,
						drgn_test_big_slab_objects[i]);
			}
		}
		kmem_cache_destroy(drgn_test_big_kmem_cache);
	}
	if (drgn_test_small_kmem_cache) {
		for (i = 0; i < ARRAY_SIZE(drgn_test_small_slab_objects); i++) {
			if (drgn_test_small_slab_objects[i]) {
				kmem_cache_free(drgn_test_small_kmem_cache,
						drgn_test_small_slab_objects[i]);
			}
		}
		kmem_cache_destroy(drgn_test_small_kmem_cache);
	}
}

// Dummy constructor so test slab caches won't get merged.
static void drgn_test_slab_ctor(void *arg)
{
}

static int drgn_test_slab_init(void)
{
	size_t i;

	drgn_test_small_kmem_cache =
		kmem_cache_create("drgn_test_small",
				  sizeof(struct drgn_test_small_slab_object),
				  __alignof__(struct drgn_test_small_slab_object),
				  0, drgn_test_slab_ctor);
	if (!drgn_test_small_kmem_cache)
		return -ENOMEM;
	for (i = 0; i < ARRAY_SIZE(drgn_test_small_slab_objects); i++) {
		drgn_test_small_slab_objects[i] =
			kmem_cache_alloc(drgn_test_small_kmem_cache,
					 GFP_KERNEL);
		if (!drgn_test_small_slab_objects[i])
			return -ENOMEM;
		drgn_test_small_slab_objects[i]->value = i;
	}
	drgn_test_big_kmem_cache =
		kmem_cache_create("drgn_test_big",
				  sizeof(struct drgn_test_big_slab_object),
				  __alignof__(struct drgn_test_big_slab_object),
				  0, drgn_test_slab_ctor);
	if (!drgn_test_big_kmem_cache)
		return -ENOMEM;
	for (i = 0; i < ARRAY_SIZE(drgn_test_big_slab_objects); i++) {
		drgn_test_big_slab_objects[i] =
			kmem_cache_alloc(drgn_test_big_kmem_cache, GFP_KERNEL);
		if (!drgn_test_big_slab_objects[i])
			return -ENOMEM;
		drgn_test_big_slab_objects[i]->value = i;
	}
	return 0;
}

// kthread for stack trace

static struct task_struct *drgn_test_kthread;
// Completion indicating that the kthread has set up its stack frames and is
// ready to be parked.
static DECLARE_COMPLETION(drgn_test_kthread_ready);

 __attribute__((__optimize__("O0")))
static void drgn_test_kthread_fn3(void)
{
	// Create some local variables for the test cases to use. Use volatile
	// to make doubly sure that they aren't optimized out.
	volatile int a, b, c;
	a = 1;
	b = 2;
	c = 3;

	complete(&drgn_test_kthread_ready);
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}
		if (kthread_should_park()) {
			__set_current_state(TASK_RUNNING);
			kthread_parkme();
			continue;
		}
		schedule();
		__set_current_state(TASK_RUNNING);
	}
}

 __attribute__((__optimize__("O0")))
static void drgn_test_kthread_fn2(void)
{
	drgn_test_kthread_fn3();
}

 __attribute__((__optimize__("O0")))
static int drgn_test_kthread_fn(void *arg)
{
	drgn_test_kthread_fn2();
	return 0;
}

static void drgn_test_stack_trace_exit(void)
{
	if (drgn_test_kthread) {
		kthread_stop(drgn_test_kthread);
		drgn_test_kthread = NULL;
	}
}

static int drgn_test_stack_trace_init(void)
{
	drgn_test_kthread = kthread_create(drgn_test_kthread_fn, NULL,
					   "drgn_test_kthread");
	if (!drgn_test_kthread)
		return -1;
	wake_up_process(drgn_test_kthread);
	wait_for_completion(&drgn_test_kthread_ready);
	return kthread_park(drgn_test_kthread);
}

// Dummy function symbol.
int drgn_test_function(int x)
{
	return x + 1;
}

static void drgn_test_exit(void)
{
	drgn_test_slab_exit();
	drgn_test_percpu_exit();
	drgn_test_mm_exit();
	drgn_test_stack_trace_exit();
}

static int __init drgn_test_init(void)
{
	int ret;

	drgn_test_list_init();
	drgn_test_llist_init();
	ret = drgn_test_mm_init();
	if (ret)
		goto out;
	ret = drgn_test_percpu_init();
	if (ret)
		goto out;
	drgn_test_rbtree_init();
	ret = drgn_test_slab_init();
	if (ret)
		goto out;
	ret = drgn_test_stack_trace_init();
out:
	if (ret)
		drgn_test_exit();
	return ret;
}

module_init(drgn_test_init);
module_exit(drgn_test_exit);

MODULE_LICENSE("GPL");
