// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-or-later

// Linux kernel module for testing drgn helpers and kernel support. For now,
// this is all in one file for simplicity and to keep the compilation fast
// (since this is compiled for every kernel version in CI).
//
// This is intended to be used with drgn's vmtest framework, but in theory it
// can be used with any kernel that has debug info enabled (at your own risk).

#include <linux/version.h>

#include <linux/completion.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/llist.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define HAVE_MAPLE_TREE 1
#include <linux/maple_tree.h>
#else
#define HAVE_MAPLE_TREE 0
#endif
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/plist.h>
#include <linux/radix-tree.h>
#include <linux/rbtree.h>
#include <linux/rbtree_augmented.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#ifdef CONFIG_STACKDEPOT
#include <linux/stackdepot.h>
#endif
#include <linux/vmalloc.h>
#include <linux/wait.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
#define HAVE_XARRAY 1
#include <linux/xarray.h>
#else
#define HAVE_XARRAY 0
#endif

// Convert a 4-character string to a seed for drgn_test_prng32().
static inline u32 drgn_test_prng32_seed(const char *s)
{
	BUG_ON(strlen(s) != 4);
	return ((u32)s[0] << 24) | ((u32)s[1] << 16) | ((u32)s[2] << 8) | (u32)s[3];
}

// x must not be 0; the return value is never 0.
static u32 drgn_test_prng32(u32 x)
{
	// Xorshift RNG with a period of 2^32 - 1.
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return x;
}

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

// plist

PLIST_HEAD(drgn_test_empty_plist);
PLIST_HEAD(drgn_test_full_plist);
struct plist_node drgn_test_empty_plist_node =
	PLIST_NODE_INIT(drgn_test_empty_plist_node, 50);

struct drgn_test_plist_entry {
	struct plist_node node;
	char c;
};

struct drgn_test_plist_entry drgn_test_plist_entries[3];

// Copy of plist_add() (minus debugging code) since it's not exported.
static void drgn_plist_add(struct plist_node *node, struct plist_head *head)
{
	struct plist_node *first, *iter, *prev = NULL;
	struct list_head *node_next = &head->node_list;

	WARN_ON(!plist_node_empty(node));
	WARN_ON(!list_empty(&node->prio_list));

	if (plist_head_empty(head))
		goto ins_node;

	first = iter = plist_first(head);

	do {
		if (node->prio < iter->prio) {
			node_next = &iter->node_list;
			break;
		}

		prev = iter;
		iter = list_entry(iter->prio_list.next,
				struct plist_node, prio_list);
	} while (iter != first);

	if (!prev || prev->prio != node->prio)
		list_add_tail(&node->prio_list, &iter->prio_list);
ins_node:
	list_add_tail(&node->node_list, node_next);
}

static void drgn_test_plist_init(void)
{
	plist_node_init(&drgn_test_plist_entries[0].node, 10);
	drgn_test_plist_entries[0].c = 'H';
	plist_node_init(&drgn_test_plist_entries[1].node, 20);
	drgn_test_plist_entries[1].c = 'I';
	plist_node_init(&drgn_test_plist_entries[2].node, 30);
	drgn_test_plist_entries[2].c = '!';

	drgn_plist_add(&drgn_test_plist_entries[1].node, &drgn_test_full_plist);
	drgn_plist_add(&drgn_test_plist_entries[0].node, &drgn_test_full_plist);
	drgn_plist_add(&drgn_test_plist_entries[2].node, &drgn_test_full_plist);
}

// mapletree

const int drgn_test_have_maple_tree = HAVE_MAPLE_TREE;
#if HAVE_MAPLE_TREE
const int drgn_test_maple_range64_slots = MAPLE_RANGE64_SLOTS;
const int drgn_test_maple_arange64_slots = MAPLE_ARANGE64_SLOTS;

#define DRGN_TEST_MAPLE_TREES		\
	X(empty)			\
	X(one)				\
	X(one_range)			\
	X(one_at_zero)			\
	X(one_range_at_zero)		\
	X(zero_entry)			\
	X(zero_entry_at_zero)		\
	X(dense)			\
	X(dense_ranges)			\
	X(sparse)			\
	X(sparse_ranges)		\
	X(three_levels_dense_1)		\
	X(three_levels_dense_2)		\
	X(three_levels_ranges_1)	\
	X(three_levels_ranges_2)

#define X(name)							\
	DEFINE_MTREE(drgn_test_maple_tree_##name);		\
	struct maple_tree drgn_test_maple_tree_arange_##name =	\
	MTREE_INIT(drgn_test_maple_tree_arange_##name,		\
		   MT_FLAGS_ALLOC_RANGE);
DRGN_TEST_MAPLE_TREES
#undef X

static int drgn_test_maple_tree_init(void)
{
	int ret;
	unsigned int arange, i;
	#define X(name) struct maple_tree *name = &drgn_test_maple_tree_##name;
	DRGN_TEST_MAPLE_TREES
	#undef X

	for (arange = 0; arange < 2; arange++) {
		int node_slots = arange ? MAPLE_ARANGE64_SLOTS : MAPLE_RANGE64_SLOTS;

		ret = mtree_insert(one, 666, (void *)0xdeadb00, GFP_KERNEL);
		if (ret)
			return ret;

		ret = mtree_insert_range(one_range, 616, 666,
					 (void *)0xdeadb000, GFP_KERNEL);
		if (ret)
			return ret;

		ret = mtree_insert(one_at_zero, 0, (void *)0x1234, GFP_KERNEL);
		if (ret)
			return ret;

		ret = mtree_insert_range(one_range_at_zero, 0, 0x1337,
					 (void *)0x5678, GFP_KERNEL);
		if (ret)
			return ret;

		ret = mtree_insert(zero_entry, 666, XA_ZERO_ENTRY, GFP_KERNEL);
		if (ret)
			return ret;

		ret = mtree_insert(zero_entry_at_zero, 0, XA_ZERO_ENTRY,
				   GFP_KERNEL);
		if (ret)
			return ret;

		for (i = 0; i < 5; i++) {
			ret = mtree_insert(dense, i,
					   (void *)(uintptr_t)(0xb0ba000 | i),
					   GFP_KERNEL);
			if (ret)
				return ret;
		}

		for (i = 0; i < 5; i++) {
			ret = mtree_insert_range(dense_ranges, i * i,
						 (i + 1) * (i + 1) - 1,
						 (void *)(uintptr_t)(0xb0ba000 | i),
						 GFP_KERNEL);
			if (ret)
				return ret;
		}

		for (i = 0; i < 5; i++) {
			ret = mtree_insert(sparse, (i + 1) * (i + 1),
					   (void *)(uintptr_t)(0xb0ba000 | i),
					   GFP_KERNEL);
			if (ret)
				return ret;
		}

		for (i = 0; i < 5; i++) {
			ret = mtree_insert_range(sparse_ranges,
						 (2 * i + 1) * (2 * i + 1),
						 (2 * i + 2) * (2 * i + 2),
						 (void *)(uintptr_t)(0xb0ba000 | i),
						 GFP_KERNEL);
			if (ret)
				return ret;
		}

		// In theory, a leaf can reference up to MAPLE_RANGE64_SLOTS
		// entries, and a level 1 node can reference up to node_slots *
		// MAPLE_RANGE64_SLOTS entries. In practice, as of Linux 6.6,
		// the maple tree code only fully packs nodes with a maximum of
		// ULONG_MAX. We create and test trees with both the observed
		// and theoretical limits.
		for (i = 0;
		     i < 2 * (node_slots - 1) * (MAPLE_RANGE64_SLOTS - 1) + (MAPLE_RANGE64_SLOTS - 1);
		     i++) {
			ret = mtree_insert(three_levels_dense_1, i,
					   (void *)(uintptr_t)(0xb0ba000 | i),
					   GFP_KERNEL);
			if (ret)
				return ret;
		}

		for (i = 0; i < 2 * node_slots * MAPLE_RANGE64_SLOTS; i++) {
			ret = mtree_insert(three_levels_dense_2, i,
					   (void *)(uintptr_t)(0xb0ba000 | i),
					   GFP_KERNEL);
			if (ret)
				return ret;
		}

		for (i = 0;
		     i < 2 * (node_slots - 1) * (MAPLE_RANGE64_SLOTS - 1) + (MAPLE_RANGE64_SLOTS - 1);
		     i++) {
			ret = mtree_insert_range(three_levels_ranges_1, 2 * i,
						 2 * i + 1,
						 (void *)(uintptr_t)(0xb0ba000 | i),
						 GFP_KERNEL);
			if (ret)
				return ret;
		}
		ret = mtree_insert_range(three_levels_ranges_1, 2 * i,
					 ULONG_MAX,
					 (void *)(uintptr_t)(0xb0ba000 | i),
					 GFP_KERNEL);
		if (ret)
			return ret;

		for (i = 0; i < 2 * node_slots * MAPLE_RANGE64_SLOTS; i++) {
			ret = mtree_insert_range(three_levels_ranges_2, 2 * i,
						 2 * i + 1,
						 (void *)(uintptr_t)(0xb0ba000 | i),
						 GFP_KERNEL);
			if (ret)
				return ret;
		}
		ret = mtree_insert_range(three_levels_ranges_2, 2 * i,
					 ULONG_MAX,
					 (void *)(uintptr_t)(0xb0ba000 | i),
					 GFP_KERNEL);
		if (ret)
			return ret;

		#define X(name) name = &drgn_test_maple_tree_arange_##name;
		DRGN_TEST_MAPLE_TREES
		#undef X
	}
	return 0;
}

static void drgn_test_maple_tree_exit(void)
{
	#define X(name)							\
		mtree_destroy(&drgn_test_maple_tree_##name);		\
		mtree_destroy(&drgn_test_maple_tree_arange_##name);
	DRGN_TEST_MAPLE_TREES
	#undef X
}
#else
static int drgn_test_maple_tree_init(void) { return 0; }
static void drgn_test_maple_tree_exit(void) {}
#endif

// mm

const int drgn_test_vmap_stack_enabled = IS_ENABLED(CONFIG_VMAP_STACK);
void *drgn_test_va;
phys_addr_t drgn_test_pa;
unsigned long drgn_test_pfn;
struct page *drgn_test_page;
struct page *drgn_test_compound_page;
void *drgn_test_vmalloc_va;
unsigned long drgn_test_vmalloc_pfn;
struct page *drgn_test_vmalloc_page;

static int drgn_test_mm_init(void)
{
	u32 fill;
	size_t i;

	drgn_test_page = alloc_page(GFP_KERNEL);
	if (!drgn_test_page)
		return -ENOMEM;
	drgn_test_compound_page = alloc_pages(GFP_KERNEL | __GFP_COMP, 1);
	if (!drgn_test_compound_page)
		return -ENOMEM;
	drgn_test_va = page_address(drgn_test_page);
	// Fill the page with a PRNG sequence.
	fill = drgn_test_prng32_seed("PAGE");
	for (i = 0; i < PAGE_SIZE / sizeof(fill); i++) {
		fill = drgn_test_prng32(fill);
		((u32 *)drgn_test_va)[i] = fill;
	}
	drgn_test_pa = virt_to_phys(drgn_test_va);
	drgn_test_pfn = PHYS_PFN(drgn_test_pa);
	drgn_test_vmalloc_va = vmalloc(PAGE_SIZE);
	if (!drgn_test_vmalloc_va)
		return -ENOMEM;
	drgn_test_vmalloc_pfn = vmalloc_to_pfn(drgn_test_vmalloc_va);
	drgn_test_vmalloc_page = vmalloc_to_page(drgn_test_vmalloc_va);
	return 0;
}

static void drgn_test_mm_exit(void)
{
	vfree(drgn_test_vmalloc_va);
	if (drgn_test_compound_page)
		__free_pages(drgn_test_compound_page, 1);
	if (drgn_test_page)
		__free_pages(drgn_test_page, 0);
}

// net

struct net_device *drgn_test_netdev;
void *drgn_test_netdev_priv;
struct sk_buff *drgn_test_skb;
struct skb_shared_info *drgn_test_skb_shinfo;

static int drgn_test_net_init(void)
{
	drgn_test_netdev = dev_get_by_name(&init_net, "lo");
	if (!drgn_test_netdev)
		return -ENODEV;
	// The loopback device doesn't actually have private data, but we just
	// need to compare the pointer.
	drgn_test_netdev_priv = netdev_priv(drgn_test_netdev);
	drgn_test_skb = alloc_skb(64, GFP_KERNEL);
	if (!drgn_test_skb)
		return -ENOMEM;
	drgn_test_skb_shinfo = skb_shinfo(drgn_test_skb);
	return 0;
}

static void drgn_test_net_exit(void)
{
	kfree_skb(drgn_test_skb);
	dev_put(drgn_test_netdev);
}

// percpu

DEFINE_PER_CPU(u32, drgn_test_percpu_static);
u32 __percpu *drgn_test_percpu_dynamic;

static int drgn_test_percpu_init(void)
{
	int cpu;
	u32 static_seed = drgn_test_prng32_seed("PCPU");
	u32 dynamic_seed = drgn_test_prng32_seed("pcpu");

	drgn_test_percpu_dynamic = alloc_percpu(u32);
	if (!drgn_test_percpu_dynamic)
		return -ENOMEM;
	// Initialize the per-cpu variables with a PRNG sequence.
	for_each_possible_cpu(cpu) {
		static_seed = drgn_test_prng32(static_seed);
		per_cpu(drgn_test_percpu_static, cpu) = static_seed;
		dynamic_seed = drgn_test_prng32(dynamic_seed);
		*per_cpu_ptr(drgn_test_percpu_dynamic, cpu) = dynamic_seed;
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

const int drgn_test_have_stacktrace = IS_ENABLED(CONFIG_STACKTRACE);
#ifdef CONFIG_STACKTRACE
unsigned long drgn_test_stack_entries[16];
unsigned int drgn_test_num_stack_entries;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
// Wrapper providing the newer interface and working around the caller of
// save_stack_trace() not being included in the returned trace.
static noinline unsigned int
stack_trace_save(unsigned long *store, unsigned int size, unsigned int skipnr)
{
	struct stack_trace trace = {
		.entries = store,
		.max_entries = size,
		.skip = skipnr,
	};
	save_stack_trace(&trace);
	return trace.nr_entries;
}
#endif
#endif

const int drgn_test_have_stackdepot = IS_ENABLED(CONFIG_STACKDEPOT);
#ifdef CONFIG_STACKDEPOT
depot_stack_handle_t drgn_test_stack_handle;
#endif

// Completion indicating that the kthread has set up its stack frames and is
// ready to be parked.
static DECLARE_COMPLETION(drgn_test_kthread_ready);
struct pt_regs drgn_test_kthread_pt_regs;
static inline void drgn_test_get_pt_regs(struct pt_regs *regs)
{
#if defined(__aarch64__)
	// Copied from crash_setup_regs() in arch/arm64/include/asm/kexec.h as
	// of Linux v6.1.
	u64 tmp1, tmp2;

	__asm__ __volatile__ (
		"stp	 x0,   x1, [%2, #16 *  0]\n"
		"stp	 x2,   x3, [%2, #16 *  1]\n"
		"stp	 x4,   x5, [%2, #16 *  2]\n"
		"stp	 x6,   x7, [%2, #16 *  3]\n"
		"stp	 x8,   x9, [%2, #16 *  4]\n"
		"stp	x10,  x11, [%2, #16 *  5]\n"
		"stp	x12,  x13, [%2, #16 *  6]\n"
		"stp	x14,  x15, [%2, #16 *  7]\n"
		"stp	x16,  x17, [%2, #16 *  8]\n"
		"stp	x18,  x19, [%2, #16 *  9]\n"
		"stp	x20,  x21, [%2, #16 * 10]\n"
		"stp	x22,  x23, [%2, #16 * 11]\n"
		"stp	x24,  x25, [%2, #16 * 12]\n"
		"stp	x26,  x27, [%2, #16 * 13]\n"
		"stp	x28,  x29, [%2, #16 * 14]\n"
		"mov	 %0,  sp\n"
		"stp	x30,  %0,  [%2, #16 * 15]\n"

		"/* faked current PSTATE */\n"
		"mrs	 %0, CurrentEL\n"
		"mrs	 %1, SPSEL\n"
		"orr	 %0, %0, %1\n"
		"mrs	 %1, DAIF\n"
		"orr	 %0, %0, %1\n"
		"mrs	 %1, NZCV\n"
		"orr	 %0, %0, %1\n"
		/* pc */
		"adr	 %1, 1f\n"
	"1:\n"
		"stp	 %1, %0,   [%2, #16 * 16]\n"
		: "=&r" (tmp1), "=&r" (tmp2)
		: "r" (regs)
		: "memory"
	);
#elif defined(__powerpc64__)
	unsigned long link;
	unsigned long ccr;

	asm volatile("std 0,%0" : "=m"(regs->gpr[0]));
	asm volatile("std 1,%0" : "=m"(regs->gpr[1]));
	asm volatile("std 2,%0" : "=m"(regs->gpr[2]));
	asm volatile("std 3,%0" : "=m"(regs->gpr[3]));
	asm volatile("std 4,%0" : "=m"(regs->gpr[4]));
	asm volatile("std 5,%0" : "=m"(regs->gpr[5]));
	asm volatile("std 6,%0" : "=m"(regs->gpr[6]));
	asm volatile("std 7,%0" : "=m"(regs->gpr[7]));
	asm volatile("std 8,%0" : "=m"(regs->gpr[8]));
	asm volatile("std 9,%0" : "=m"(regs->gpr[9]));
	asm volatile("std 10,%0" : "=m"(regs->gpr[10]));
	asm volatile("std 11,%0" : "=m"(regs->gpr[11]));
	asm volatile("std 12,%0" : "=m"(regs->gpr[12]));
	asm volatile("std 13,%0" : "=m"(regs->gpr[13]));
	asm volatile("std 14,%0" : "=m"(regs->gpr[14]));
	asm volatile("std 15,%0" : "=m"(regs->gpr[15]));
	asm volatile("std 16,%0" : "=m"(regs->gpr[16]));
	asm volatile("std 17,%0" : "=m"(regs->gpr[17]));
	asm volatile("std 18,%0" : "=m"(regs->gpr[18]));
	asm volatile("std 19,%0" : "=m"(regs->gpr[19]));
	asm volatile("std 20,%0" : "=m"(regs->gpr[20]));
	asm volatile("std 21,%0" : "=m"(regs->gpr[21]));
	asm volatile("std 22,%0" : "=m"(regs->gpr[22]));
	asm volatile("std 23,%0" : "=m"(regs->gpr[23]));
	asm volatile("std 24,%0" : "=m"(regs->gpr[24]));
	asm volatile("std 25,%0" : "=m"(regs->gpr[25]));
	asm volatile("std 26,%0" : "=m"(regs->gpr[26]));
	asm volatile("std 27,%0" : "=m"(regs->gpr[27]));
	asm volatile("std 28,%0" : "=m"(regs->gpr[28]));
	asm volatile("std 29,%0" : "=m"(regs->gpr[29]));
	asm volatile("std 30,%0" : "=m"(regs->gpr[30]));
	asm volatile("std 31,%0" : "=m"(regs->gpr[31]));
	asm volatile("mflr %0" : "=r"(link));
	asm volatile("std %1,%0" : "=m"(regs->link) : "r"(link));
	asm volatile("mfcr %0" : "=r"(ccr));
	asm volatile("std %1,%0" : "=m"(regs->ccr) : "r"(ccr));
	regs->nip = _THIS_IP_;
#elif defined(__s390x__)
	regs->psw.mask = __extract_psw();
	regs->psw.addr = _THIS_IP_;
	asm volatile("stmg 0,15,%0\n" : "=S" (regs->gprs) : : "memory");
#elif defined(__x86_64__)
	// Copied from crash_setup_regs() in arch/x86/include/asm/kexec.h as of
	// Linux v6.1.
	asm volatile("movq %%rbx,%0" : "=m"(regs->bx));
	asm volatile("movq %%rcx,%0" : "=m"(regs->cx));
	asm volatile("movq %%rdx,%0" : "=m"(regs->dx));
	asm volatile("movq %%rsi,%0" : "=m"(regs->si));
	asm volatile("movq %%rdi,%0" : "=m"(regs->di));
	asm volatile("movq %%rbp,%0" : "=m"(regs->bp));
	asm volatile("movq %%rax,%0" : "=m"(regs->ax));
	asm volatile("movq %%rsp,%0" : "=m"(regs->sp));
	asm volatile("movq %%r8,%0" : "=m"(regs->r8));
	asm volatile("movq %%r9,%0" : "=m"(regs->r9));
	asm volatile("movq %%r10,%0" : "=m"(regs->r10));
	asm volatile("movq %%r11,%0" : "=m"(regs->r11));
	asm volatile("movq %%r12,%0" : "=m"(regs->r12));
	asm volatile("movq %%r13,%0" : "=m"(regs->r13));
	asm volatile("movq %%r14,%0" : "=m"(regs->r14));
	asm volatile("movq %%r15,%0" : "=m"(regs->r15));
	asm volatile("movl %%ss, %%eax;" :"=a"(regs->ss));
	asm volatile("movl %%cs, %%eax;" :"=a"(regs->cs));
	asm volatile("pushfq; popq %0" :"=m"(regs->flags));
	regs->ip = _THIS_IP_;
#endif
}

 __attribute__((__optimize__("O0")))
static void drgn_test_kthread_fn3(void)
{
	// Create some local variables for the test cases to use. Use volatile
	// to make doubly sure that they aren't optimized out.
	volatile int a, b, c;
	a = 1;
	b = 2;
	c = 3;

#ifdef CONFIG_STACKTRACE
	drgn_test_num_stack_entries = stack_trace_save(drgn_test_stack_entries,
						       ARRAY_SIZE(drgn_test_stack_entries),
						       0);
#endif
#ifdef CONFIG_STACKDEPOT
	stack_depot_init();
	drgn_test_stack_handle = stack_depot_save(drgn_test_stack_entries,
						  drgn_test_num_stack_entries,
						  GFP_KERNEL);
#endif

	complete(&drgn_test_kthread_ready);
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			break;
		}
		if (kthread_should_park()) {
			__set_current_state(TASK_RUNNING);
			drgn_test_get_pt_regs(&drgn_test_kthread_pt_regs);
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

// radixtree

RADIX_TREE(drgn_test_radix_tree_empty, GFP_KERNEL);
RADIX_TREE(drgn_test_radix_tree_one, GFP_KERNEL);
RADIX_TREE(drgn_test_radix_tree_one_at_zero, GFP_KERNEL);
RADIX_TREE(drgn_test_radix_tree_sparse, GFP_KERNEL);
#ifdef CONFIG_RADIX_TREE_MULTIORDER
RADIX_TREE(drgn_test_radix_tree_multi_order, GFP_KERNEL);
#endif

static int drgn_test_radix_tree_init(void)
{
	int ret;

	ret = radix_tree_insert(&drgn_test_radix_tree_one, 666,
				(void *)0xdeadb00);
	if (ret)
		return ret;

	ret = radix_tree_insert(&drgn_test_radix_tree_one_at_zero, 0,
				(void *)0x1234);
	if (ret)
		return ret;

	ret = radix_tree_insert(&drgn_test_radix_tree_sparse, 1,
				(void *)0x1234);
	if (ret)
		return ret;

	ret = radix_tree_insert(&drgn_test_radix_tree_sparse, 0x80808080,
				(void *)0x5678);
	if (ret)
		return ret;

	ret = radix_tree_insert(&drgn_test_radix_tree_sparse, 0xffffffff,
				(void *)0x9abc);
	if (ret)
		return ret;

#ifdef CONFIG_RADIX_TREE_MULTIORDER
	ret = __radix_tree_insert(&drgn_test_radix_tree_multi_order, 0x80808000,
				  9, (void *)0x1234);
	if (ret)
		return ret;
#endif

	return 0;
}

static void drgn_test_radix_tree_destroy(struct radix_tree_root *root)
{
	struct radix_tree_iter iter;
	void __rcu **slot;

	radix_tree_for_each_slot(slot, root, &iter, 0)
		radix_tree_delete(root, iter.index);
}

static void drgn_test_radix_tree_exit(void)
{
	drgn_test_radix_tree_destroy(&drgn_test_radix_tree_one);
	drgn_test_radix_tree_destroy(&drgn_test_radix_tree_one_at_zero);
	drgn_test_radix_tree_destroy(&drgn_test_radix_tree_sparse);
#ifdef CONFIG_RADIX_TREE_MULTIORDER
	drgn_test_radix_tree_destroy(&drgn_test_radix_tree_multi_order);
#endif
}

// xarray
const int drgn_test_have_xarray = HAVE_XARRAY;
#if HAVE_XARRAY
DEFINE_XARRAY(drgn_test_xarray_empty);
DEFINE_XARRAY(drgn_test_xarray_one);
DEFINE_XARRAY(drgn_test_xarray_one_at_zero);
DEFINE_XARRAY(drgn_test_xarray_sparse);
DEFINE_XARRAY(drgn_test_xarray_multi_index);
DEFINE_XARRAY(drgn_test_xarray_zero_entry);
DEFINE_XARRAY(drgn_test_xarray_zero_entry_at_zero);
DEFINE_XARRAY(drgn_test_xarray_value);
void *drgn_test_xa_zero_entry;

static int drgn_test_xa_store_order(struct xarray *xa, unsigned long index,
				    unsigned order, void *entry, gfp_t gfp)
{
	XA_STATE_ORDER(xas, xa, index, order);

	do {
		xas_lock(&xas);
		xas_store(&xas, entry);
		xas_unlock(&xas);
	} while (xas_nomem(&xas, gfp));
	return xas_error(&xas);
}
#endif

static int drgn_test_xarray_init(void)
{
#if HAVE_XARRAY
	void *entry;
	int ret;

	drgn_test_xa_zero_entry = XA_ZERO_ENTRY;

	entry = xa_store(&drgn_test_xarray_one, 666, (void *)0xdeadb00,
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);

	entry = xa_store(&drgn_test_xarray_one_at_zero, 0, (void *)0x1234,
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);

	entry = xa_store(&drgn_test_xarray_sparse, 1, (void *)0x1234,
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);
	entry = xa_store(&drgn_test_xarray_sparse, 0x80808080, (void *)0x5678,
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);
	entry = xa_store(&drgn_test_xarray_sparse, 0xffffffffUL, (void *)0x9abc,
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);

	ret = drgn_test_xa_store_order(&drgn_test_xarray_multi_index,
				       0x80808000, 9, (void *)0x1234,
				       GFP_KERNEL);
	if (ret)
		return ret;

	ret = xa_reserve(&drgn_test_xarray_zero_entry, 666, GFP_KERNEL);
	if (ret)
		return ret;

	ret = xa_reserve(&drgn_test_xarray_zero_entry_at_zero, 0, GFP_KERNEL);
	if (ret)
		return ret;

	entry = xa_store(&drgn_test_xarray_value, 0, xa_mk_value(1337),
			 GFP_KERNEL);
	if (xa_is_err(entry))
		return xa_err(entry);

#endif

	return 0;
}

static void drgn_test_xarray_exit(void)
{
#if HAVE_XARRAY
	xa_destroy(&drgn_test_xarray_one);
	xa_destroy(&drgn_test_xarray_one_at_zero);
	xa_destroy(&drgn_test_xarray_sparse);
	xa_destroy(&drgn_test_xarray_multi_index);
	xa_destroy(&drgn_test_xarray_zero_entry);
	xa_destroy(&drgn_test_xarray_zero_entry_at_zero);
	xa_destroy(&drgn_test_xarray_value);
#endif
}

// idr

DEFINE_IDR(drgn_test_idr_empty);
DEFINE_IDR(drgn_test_idr_one);
DEFINE_IDR(drgn_test_idr_one_at_zero);
DEFINE_IDR(drgn_test_idr_sparse);

static int drgn_test_idr_init(void)
{
	int ret;

	ret = idr_alloc(&drgn_test_idr_one, (void *)0xdeadb00, 66, 67,
			GFP_KERNEL);
	if (ret < 0)
		return ret;

	ret = idr_alloc(&drgn_test_idr_one_at_zero, (void *)0x1234, 0, 1,
			GFP_KERNEL);
	if (ret < 0)
		return ret;

	ret = idr_alloc(&drgn_test_idr_sparse, (void *)0x1234, 1, 2,
			GFP_KERNEL);
	if (ret < 0)
		return ret;

	ret = idr_alloc(&drgn_test_idr_sparse, (void *)0x5678, 0x80, 0x81,
			GFP_KERNEL);
	if (ret < 0)
		return ret;

	ret = idr_alloc(&drgn_test_idr_sparse, (void *)0x9abc, 0xee, 0xef,
			GFP_KERNEL);
	if (ret < 0)
		return ret;

	return 0;
}

static void drgn_test_idr_exit(void)
{
	idr_destroy(&drgn_test_idr_one);
	idr_destroy(&drgn_test_idr_one_at_zero);
	idr_destroy(&drgn_test_idr_sparse);
}

// wait-queue
static struct task_struct *drgn_test_waitq_kthread;
static wait_queue_head_t drgn_test_waitq;
static wait_queue_head_t drgn_test_empty_waitq;

static int drgn_test_waitq_kthread_fn(void *arg)
{
	wait_event_interruptible(drgn_test_waitq, kthread_should_stop());
	return 0;
}

static int drgn_test_waitq_init(void)
{
	init_waitqueue_head(&drgn_test_waitq);
	init_waitqueue_head(&drgn_test_empty_waitq);

	drgn_test_waitq_kthread = kthread_create(drgn_test_waitq_kthread_fn,
						 NULL,
						 "drgn_test_waitq_kthread");
	if (!drgn_test_waitq_kthread)
		return -1;

	wake_up_process(drgn_test_waitq_kthread);
	return 0;
}

static void drgn_test_waitq_exit(void)
{
	if (drgn_test_waitq_kthread) {
		kthread_stop(drgn_test_waitq_kthread);
		drgn_test_waitq_kthread = NULL;
	}
}

// Dummy function symbol.
int drgn_test_function(int x); // Silence -Wmissing-prototypes.
int drgn_test_function(int x)
{
	return x + 1;
}

static void drgn_test_exit(void)
{
	drgn_test_slab_exit();
	drgn_test_percpu_exit();
	drgn_test_maple_tree_exit();
	drgn_test_mm_exit();
	drgn_test_net_exit();
	drgn_test_stack_trace_exit();
	drgn_test_radix_tree_exit();
	drgn_test_xarray_exit();
	drgn_test_waitq_exit();
	drgn_test_idr_exit();
}

static int __init drgn_test_init(void)
{
	int ret;

	drgn_test_list_init();
	drgn_test_llist_init();
	drgn_test_plist_init();
	ret = drgn_test_maple_tree_init();
	if (ret)
		goto out;
	ret = drgn_test_mm_init();
	if (ret)
		goto out;
	ret = drgn_test_net_init();
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
	if (ret)
		goto out;
	ret = drgn_test_radix_tree_init();
	if (ret)
		goto out;
	ret = drgn_test_xarray_init();
	if (ret)
		goto out;

	ret = drgn_test_waitq_init();
	if (ret)
		goto out;
	ret = drgn_test_idr_init();
out:
	if (ret)
		drgn_test_exit();
	return ret;
}

module_init(drgn_test_init);
module_exit(drgn_test_exit);

MODULE_LICENSE("GPL");
