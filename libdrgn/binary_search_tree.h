// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Generic binary search trees.
 *
 * See @ref BinarySearchTrees.
 */

#ifndef DRGN_BINARY_SEARCH_TREE_H
#define DRGN_BINARY_SEARCH_TREE_H

#include <stdbool.h>
#include <stddef.h>

#include "util.h"

/**
 * @ingroup Internals
 *
 * @defgroup BinarySearchTrees Binary search trees
 *
 * Generic binary search trees.
 *
 * This implements a self-balancing binary search tree interface. The interface
 * is generic, strongly typed (entries have a static type, not <tt>void *</tt>),
 * and doesn't have any function pointer overhead. Currently, only splay trees
 * are implemented, but this may be extended to support other variants like
 * red-black trees or AVL trees.
 *
 * Entries are allocated separately from this interface. The interface is
 * intrusive, i.e., entries must embed a @ref binary_tree_node.
 *
 * A binary search tree is defined with @ref DEFINE_BINARY_SEARCH_TREE(). Each
 * generated binary search tree interface is prefixed with a given name; the
 * interface documented here uses the example name @c binary_search_tree, which
 * could be generated with this example code:
 *
 * @code{.c}
 * typedef {
 *     ...
 *     struct binary_tree_node node;
 * } entry_type;
 * key_type entry_to_key(const entry_type *entry);
 * int cmp_func(const key_type *a, const key_type *b);
 * DEFINE_BINARY_SEARCH_TREE(binary_search_tree, entry_type, node, entry_to_key,
 *                           cmp_func, splay)
 * @endcode
 *
 * @sa HashTables
 *
 * @{
 */

#ifdef DOXYGEN
/**
 * @struct binary_search_tree
 *
 * Binary search tree instance.
 *
 * There are no requirements on how this is allocated; it may be global, on the
 * stack, allocated by @c malloc(), embedded in another structure, etc.
 */
struct binary_search_tree;

/**
 * Binary search tree iterator.
 *
 * Several functions return an iterator or take one as an argument. This
 * iterator has a reference to an entry, which can be @c NULL to indicate that
 * there is no such entry. It may also contain private bookkeeping which should
 * not be used.
 *
 * An iterator remains valid as long as the entry is not deleted.
 */
struct binary_search_tree_iterator {
	/** Pointer to the entry. */
	entry_type *entry;
};

/**
 * Initialize a @ref binary_search_tree.
 *
 * The new tree is empty.
 */
void binary_search_tree_init(struct binary_search_tree *tree);

/**
 * Return whether a @ref binary_search_tree has no entries.
 *
 * This is O(1).
 */
bool binary_search_tree_empty(struct binary_search_tree *tree);

/**
 * Insert an entry in a @ref binary_search_tree.
 *
 * If an entry with the same key is already in the tree, the entry is @em not
 * inserted.
 *
 * @param[out] it_ret If not @c NULL, a returned iterator pointing to the newly
 * inserted entry or the existing entry with the same key.
 * @return 1 if the entry was inserted, 0 if the key already existed.
 */
int binary_search_tree_insert(struct binary_search_tree *tree,
			      entry_type *entry,
			      struct binary_search_tree_iterator *it_ret);

/**
 * Search for an entry in a @ref binary_search_tree.
 *
 * This searches for the entry with the given key.
 *
 * @return An iterator pointing to the entry with the given key, or an iterator
 * with <tt>entry == NULL</tt> if the key was not found.
 */
struct binary_search_tree_iterator
binary_search_tree_search(struct binary_search_tree *tree, const key_type *key);

/**
 * Search for the entry with the greatest key less than or equal to the given
 * key.
 */
struct binary_search_tree_iterator
binary_search_tree_search_le(struct binary_search_tree *tree,
			     const key_type *key);


/**
 * Delete an entry in a @ref binary_search_tree.
 *
 * This deletes the entry with the given key.
 *
 * @return @c true if the entry was found and deleted, @c false if not.
 */
bool binary_search_tree_delete(struct binary_search_tree *tree,
			       const key_type *key);

/**
 * Delete an entry given by an iterator in a @ref binary_search_tree.
 *
 * This deletes the entry pointed to by the iterator.
 *
 * @return An iterator pointing to the next entry in the tree. See @ref
 * binary_search_tree_next().
 */
struct binary_search_tree_iterator
binary_search_tree_delete_iterator(struct binary_search_tree *tree,
				   struct binary_search_tree_iterator it);

/**
 * Get an iterator pointing to the first (in-order) entry in a @ref
 * binary_search_tree.
 *
 * The first entry is the one with the lowest key.
 *
 * @return An iterator pointing to the first entry, or an iterator with
 * <tt>entry == NULL</tt> if the tree is empty.
 */
struct binary_search_tree_iterator
binary_search_tree_first(struct binary_search_tree *tree);

/**
 * Get an iterator pointing to the next (in-order) entry in a @ref
 * binary_search_tree.
 *
 * The next entry is the one with the lowest key that is greater than the
 * current key.
 *
 * @return An iterator pointing to the next entry, or an iterator with <tt>entry
 * == NULL</tt> if there are no more entries.
 */
struct binary_search_tree_iterator
binary_search_tree_next(struct binary_search_tree_iterator it);

/**
 * Get an iterator pointing to the first post-order entry in a @ref
 * binary_search_tree.
 *
 * The first post-order entry is any entry which is a leaf in the tree.
 *
 * This is suitable for visiting all entries in a tree in order to free them:
 *
 * @code
 * struct binary_search_tree_iterator it;
 *
 * it = binary_search_tree_first_post_order(tree);
 * while (it.entry) {
 *     entry_type *entry = it.entry;
 *
 *     binary_search_tree_next_post_order(&it);
 *     // Advancing the iterator accesses the current entry, so the entry must
 *     // be freed after the iterator has been advanced.
 *     free(entry);
 * }
 * @endcode
 *
 * @return An iterator pointing to the first entry, or an iterator with
 * <tt>entry == NULL</tt> if the tree is empty.
 */
struct binary_search_tree_iterator
binary_search_tree_first_post_order(struct binary_search_tree *tree);

/**
 * Get an iterator pointing to the next post-order entry in a @ref
 * binary_search_tree.
 *
 * The next post-order entry is any unvisited entry whose children have already
 * been visited.
 *
 * @return An iterator pointing to the next entry, or an iterator with <tt>entry
 * == NULL</tt> if there are no more entries.
 */
struct binary_search_tree_iterator
binary_search_tree_next_post_order(struct binary_search_tree_iterator it);
#endif

/**
 * Node in a binary search tree.
 *
 * This structure must be embedded in the entry type of a binary search tree. It
 * should only be accessed by the binary search tree implementation.
 */
struct binary_tree_node {
	struct binary_tree_node *parent, *left, *right;
};

struct binary_tree_search_result {
	struct binary_tree_node **nodep, *parent;
};

/*
 * Binary search tree variants need to define three functions:
 *
 * drgn_##variant##_tree_insert_fixup(root, node, parent) is called after a node
 * is inserted (as *root, parent->left, or parent->right). It must set the
 * node's parent pointer and rebalance the tree.
 *
 * drgn_##variant##_tree_found(root, node) is called when a duplicate node is
 * found for an insert operation or when a node is found for a search operation
 * (but not for a delete operation). It may rebalance the tree or do nothing.
 *
 * drgn_##variant##_tree_delete(root, node) must delete the node and rebalance
 * the tree.
 */

void drgn_splay_tree_splay(struct binary_tree_node **root,
			   struct binary_tree_node *node,
			   struct binary_tree_node *parent);

static inline void drgn_splay_tree_insert_fixup(struct binary_tree_node **root,
						struct binary_tree_node *node,
						struct binary_tree_node *parent)
{
	if (parent)
		drgn_splay_tree_splay(root, node, parent);
	else
		node->parent = NULL;
}

static inline void drgn_splay_tree_found(struct binary_tree_node **root,
					 struct binary_tree_node *node)
{
	if (node->parent)
		drgn_splay_tree_splay(root, node, node->parent);
}

void drgn_splay_tree_delete(struct binary_tree_node **root,
			    struct binary_tree_node *node);

/**
 * Define a binary search tree type without defining its functions.
 *
 * This is useful when the binary search tree type must be defined in one place
 * (e.g., a header) but the interface is defined elsewhere (e.g., a source file)
 * with @ref DEFINE_BINARY_SEARCH_TREE_FUNCTIONS(). Otherwise, just use @ref
 * DEFINE_BINARY_SEARCH_TREE().
 *
 * @sa DEFINE_BINARY_SEARCH_TREE()
 */
#define DEFINE_BINARY_SEARCH_TREE_TYPE(tree, entry_type, member, entry_to_key)	\
typedef typeof(entry_type) tree##_entry_type;					\
typedef typeof(entry_to_key((tree##_entry_type *)0)) tree##_key_type;		\
										\
static inline struct binary_tree_node *						\
tree##_entry_to_node(tree##_entry_type *entry)					\
{										\
	return &entry->member;							\
}										\
										\
static inline tree##_entry_type *						\
tree##_node_to_entry(struct binary_tree_node *node)				\
{										\
	return container_of(node, tree##_entry_type, member);			\
}										\
										\
static inline tree##_key_type							\
tree##_entry_to_key(const tree##_entry_type *entry)				\
{										\
	return entry_to_key(entry);						\
}										\
										\
struct tree {									\
	struct binary_tree_node *root;						\
};										\
										\
struct tree##_iterator {							\
	tree##_entry_type *entry;						\
};

/**
 * Define the functions for a binary search tree.
 *
 * The binary search tree type must have already been defined with @ref
 * DEFINE_BINARY_SEARCH_TREE_TYPE().
 *
 * Unless the type and function definitions must be in separate places, use @ref
 * DEFINE_BINARY_SEARCH_TREE() instead.
 *
 * @sa DEFINE_BINARY_SEARCH_TREE()
 */
#define DEFINE_BINARY_SEARCH_TREE_FUNCTIONS(tree, cmp_func, variant)		\
__attribute__((__unused__))							\
static void tree##_init(struct tree *tree)					\
{										\
	tree->root = NULL;							\
}										\
										\
__attribute__((__unused__))							\
static bool tree##_empty(struct tree *tree)					\
{										\
	return tree->root == NULL;						\
}										\
										\
static inline struct binary_tree_search_result					\
tree##_search_internal(struct tree *tree, const tree##_key_type *key)		\
{										\
	struct binary_tree_search_result res = { &tree->root, NULL, };		\
										\
	while (*res.nodep) {							\
		tree##_entry_type *other_entry;					\
		tree##_key_type other_key;					\
		int cmp;							\
										\
		other_entry = tree##_node_to_entry(*res.nodep);			\
		other_key = tree##_entry_to_key(other_entry);			\
		cmp = cmp_func(key, &other_key);				\
		if (cmp < 0) {							\
			res.parent = *res.nodep;				\
			res.nodep = &(*res.nodep)->left;			\
		} else if (cmp > 0) {						\
			res.parent = *res.nodep;				\
			res.nodep = &(*res.nodep)->right;			\
		} else {							\
			break;							\
		}								\
	}									\
	return res;								\
}										\
										\
__attribute__((__unused__))							\
static int tree##_insert(struct tree *tree, tree##_entry_type *entry,		\
			 struct tree##_iterator *it_ret)			\
{										\
	tree##_key_type key = tree##_entry_to_key(entry);			\
	struct binary_tree_search_result res;					\
	struct binary_tree_node *node;						\
										\
	res = tree##_search_internal(tree, &key);				\
	if (*res.nodep) {							\
		if (it_ret)							\
			it_ret->entry = tree##_node_to_entry(*res.nodep);	\
		drgn_##variant##_tree_found(&tree->root, *res.nodep);		\
		return 0;							\
	}									\
										\
	node = tree##_entry_to_node(entry);					\
	node->left = node->right = NULL;					\
	*res.nodep = node;							\
	drgn_##variant##_tree_insert_fixup(&tree->root, node, res.parent);	\
	return 1;								\
}										\
										\
__attribute__((__unused__))							\
static struct tree##_iterator tree##_search(struct tree *tree,			\
					    const tree##_key_type *key)		\
{										\
	struct binary_tree_node *node;						\
										\
	node = *tree##_search_internal(tree, key).nodep;			\
	if (!node)								\
		return (struct tree##_iterator){};				\
	drgn_##variant##_tree_found(&tree->root, node);				\
	return (struct tree##_iterator){ tree##_node_to_entry(node), };		\
}										\
										\
__attribute__((__unused__))							\
static struct tree##_iterator tree##_search_le(struct tree *tree,		\
					       const tree##_key_type *key)	\
{										\
	struct binary_tree_node *node = tree->root;				\
	tree##_entry_type *entry = NULL;					\
										\
	while (node) {								\
		tree##_entry_type *other_entry;					\
		tree##_key_type other_key;					\
		int cmp;							\
										\
		other_entry = tree##_node_to_entry(node);			\
		other_key = tree##_entry_to_key(other_entry);			\
		cmp = cmp_func(key, &other_key);				\
		if (cmp < 0) {							\
			node = node->left;					\
		} else if (cmp > 0) {						\
			entry = other_entry;					\
			node = node->right;					\
		} else {							\
			entry = other_entry;					\
			break;							\
		}								\
	}									\
	if (entry)								\
		drgn_##variant##_tree_found(&tree->root,			\
					    tree##_entry_to_node(entry));	\
	return (struct tree##_iterator){ entry, };				\
}										\
										\
__attribute__((__unused__))							\
static bool tree##_delete(struct tree *tree, const tree##_key_type *key)	\
{										\
	struct binary_tree_node *node;						\
										\
	node = *tree##_search_internal(tree, key).nodep;			\
	if (!node)								\
		return false;							\
	drgn_##variant##_tree_delete(&tree->root, node);			\
	return true;								\
}										\
										\
/*										\
 * We want this inlined so that the whole function call can be optimized away	\
 * if the return value is not used.						\
 */										\
__attribute__((__always_inline__))						\
static inline struct tree##_iterator						\
tree##_next_impl(struct tree##_iterator it)					\
{										\
	struct binary_tree_node *node = tree##_entry_to_node(it.entry);		\
	long i;									\
										\
	if (node->right) {							\
		node = node->right;						\
		/*								\
		 * This hack (inspired by a similar hack in the F14 hash table	\
		 * code) convinces the compiler that the loop always terminates	\
		 * (otherwise the counter would overflow, which is undefined	\
		 * behavior).							\
		 */								\
		for (i = 0;; i++) {						\
			if (!node->left)					\
				break;						\
			node = node->left;					\
		}								\
		return (struct tree##_iterator){ tree##_node_to_entry(node), };	\
	}									\
										\
	for (i = 0;; i++) {							\
		if (!node->parent || node != node->parent->right)		\
			break;							\
		node = node->parent;						\
	}									\
	if (node->parent) {							\
		return (struct tree##_iterator){				\
			tree##_node_to_entry(node->parent),			\
		};								\
	}									\
	return (struct tree##_iterator){};					\
}										\
										\
__attribute__((__always_inline__))						\
static inline struct tree##_iterator						\
tree##_delete_iterator(struct tree *tree, struct tree##_iterator it)		\
{										\
	struct binary_tree_node *node;						\
										\
	node = tree##_entry_to_node(it.entry);					\
	it = tree##_next_impl(it);						\
	drgn_##variant##_tree_delete(&tree->root, node);			\
	return it;								\
}										\
										\
__attribute__((__unused__))							\
static struct tree##_iterator tree##_first(struct tree *tree)			\
{										\
	struct binary_tree_node *node = tree->root;				\
										\
	if (!node)								\
		return (struct tree##_iterator){};				\
										\
	while (node->left)							\
		node = node->left;						\
	return (struct tree##_iterator){ tree##_node_to_entry(node), };		\
}										\
										\
__attribute__((__unused__))							\
static struct tree##_iterator tree##_next(struct tree##_iterator it)		\
{										\
	return tree##_next_impl(it);						\
}										\
										\
__attribute__((__unused__))							\
static struct tree##_iterator tree##_first_post_order(struct tree *tree)	\
{										\
	struct binary_tree_node *node = tree->root;				\
										\
	if (!node)								\
		return (struct tree##_iterator){};				\
										\
	for (;;) {								\
		if (node->left) {						\
			node = node->left;					\
		} else if (node->right) {					\
			node = node->right;					\
		} else {							\
			return (struct tree##_iterator){			\
				tree##_node_to_entry(node),			\
			};							\
		}								\
										\
	}									\
}										\
										\
__attribute__((__unused__))							\
static struct tree##_iterator tree##_next_post_order(struct tree##_iterator it)	\
{										\
	struct binary_tree_node *node = tree##_entry_to_node(it.entry);		\
										\
	if (!node->parent) {							\
		return (struct tree##_iterator){};				\
	} else if (node == node->parent->left && node->parent->right) {		\
		node = node->parent->right;					\
		for (;;) {							\
			if (node->left) {					\
				node = node->left;				\
			} else if (node->right) {				\
				node = node->right;				\
			} else {						\
				return (struct tree##_iterator){		\
					tree##_node_to_entry(node),		\
				};						\
			}							\
		}								\
	} else {								\
		return (struct tree##_iterator){				\
			tree##_node_to_entry(node->parent),			\
		};								\
	}									\
}

/**
 * Define a binary search tree interface.
 *
 * This macro defines a binary search tree type along with its functions.
 *
 * @param[in] tree Name of the type to define. This is prefixed to all of the
 * types and functions defined for that type.
 * @param[in] entry_type Type of entries in the tree.
 * @param[in] member Name of the @ref binary_tree_node member in @p entry_type.
 * @param[in] entry_to_key Name of function or macro which is passed a <tt>const
 * entry_type *</tt> and returns the key for that entry. The return type is the
 * @c key_type of the tree. The passed entry is never @c NULL.
 * @param[in] cmp_func Comparison function which takes two <tt>const key_type
 * *</tt> and returns an @c int. The return value must be negative if the first
 * key is less than the second key, positive if the first key is greater than
 * the second key, and zero if they are equal.
 * @param[in] variant The binary search tree implementation to use. Currently
 * this can only be @c splay.
 */
#define DEFINE_BINARY_SEARCH_TREE(tree, entry_type, member, entry_to_key,	\
				  cmp_func, variant)				\
DEFINE_BINARY_SEARCH_TREE_TYPE(tree, entry_type, member, entry_to_key)		\
DEFINE_BINARY_SEARCH_TREE_FUNCTIONS(tree, cmp_func, variant)

#ifdef DOXYGEN
/** Compare two scalar keys. */
bool binary_search_tree_scalar_cmp(const T *a, const T *b);
#else
#define binary_search_tree_scalar_cmp(a, b) ({	\
	__auto_type _a = *(a);			\
	__auto_type _b = *(b);			\
						\
	_a < _b ? -1 : _a > _b ? 1 : 0;		\
})
#endif

/** @} */

#endif /* DRGN_BINARY_SEARCH_TREE_H */
