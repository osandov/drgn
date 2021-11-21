// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "binary_search_tree.h" // IWYU pragma: associated

/*
 * Binary search tree splay operation based on the original paper [1]. Rotations
 * are inlined to avoid redundant pointer assignments. We still do redundant
 * assignments to great_grandparent->{left,right} and node->{left,right}; this
 * was faster in microbenchmarks than doing the extra tracking to avoid the
 * reassignments.
 *
 * This assumes that the node is not already the root.
 *
 * 1: "Self-Adjusting Binary Search Trees" (Sleator & Tarjan, 1985):
 * http://www.cs.cmu.edu/~sleator/papers/self-adjusting.pdf
 */
void drgn_splay_tree_splay(struct binary_tree_node **root,
			   struct binary_tree_node *node,
			   struct binary_tree_node *parent)
{
	for (;;) {
		struct binary_tree_node *grandparent, *great_grandparent;

		grandparent = parent->parent;
		if (node == parent->left) {
			if (!grandparent) {
				/*
				 * Zig step: rotate_right(parent). The node
				 * takes the place of its parent, which is the
				 * root.
				 */
				parent->left = node->right;
				node->right = parent;

				if (parent->left)
					parent->left->parent = parent;
				parent->parent = node;
				break;
			} else {
				great_grandparent = grandparent->parent;
				if (parent == grandparent->left) {
					/*
					 * Zig-zig step:
					 * rotate_right(grandparent),
					 * rotate_right(parent).
					 */
					grandparent->left = parent->right;
					parent->left = node->right;
					parent->right = grandparent;
					node->right = parent;

					if (grandparent->left)
						grandparent->left->parent = grandparent;
					grandparent->parent = parent;
					if (parent->left)
						parent->left->parent = parent;
					parent->parent = node;
				} else {
					/*
					 * Zig-zag step: rotate_right(parent),
					 * rotate_left(grandparent).
					 */
					grandparent->right = node->left;
					parent->left = node->right;
					node->left = grandparent;
					node->right = parent;

					if (grandparent->right)
						grandparent->right->parent = grandparent;
					if (parent->left)
						parent->left->parent = parent;
					grandparent->parent = node;
					parent->parent = node;
				}
			}
		} else {
			if (!grandparent) {
				/*
				 * Zig step: rotate_left(parent). The node
				 * takes the place of its parent, which is the
				 * root.
				 */
				parent->right = node->left;
				node->left = parent;

				if (parent->right)
					parent->right->parent = parent;
				parent->parent = node;
				break;
			} else {
				great_grandparent = grandparent->parent;
				if (parent == grandparent->right) {
					/*
					 * Zig-zig step:
					 * rotate_left(grandparent),
					 * rotate_left(parent).
					 */
					grandparent->right = parent->left;
					parent->right = node->left;
					parent->left = grandparent;
					node->left = parent;

					if (grandparent->right)
						grandparent->right->parent = grandparent;
					grandparent->parent = parent;
					if (parent->right)
						parent->right->parent = parent;
					parent->parent = node;
				} else {
					/*
					 * Zig-zag step: rotate_left(parent),
					 * rotate_right(grandparent).
					 */
					grandparent->left = node->right;
					parent->right = node->left;
					node->right = grandparent;
					node->left = parent;

					if (grandparent->left)
						grandparent->left->parent = grandparent;
					if (parent->right)
						parent->right->parent = parent;
					grandparent->parent = node;
					parent->parent = node;
				}
			}
		}
		/*
		 * Common code for zig-zig and zig-zag steps, both left and
		 * right. The node took the place of its grandparent, which may
		 * have been the root. We don't need to update the node's parent
		 * pointer because it is always NULL in the end.
		 */
		if (!great_grandparent)
			break;
		if (grandparent == great_grandparent->left)
			great_grandparent->left = node;
		else
			great_grandparent->right = node;
		parent = great_grandparent;
	}

	/* The node reached the root. */
	*root = node;
	node->parent = NULL;
}

static inline void drgn_splay_tree_transplant(struct binary_tree_node **root,
					      struct binary_tree_node *old,
					      struct binary_tree_node *new)
{
	if (!old->parent)
		*root = new;
	else if (old == old->parent->left)
		old->parent->left = new;
	else
		old->parent->right = new;
	if (new)
		new->parent = old->parent;
}

void drgn_splay_tree_delete(struct binary_tree_node **root,
			    struct binary_tree_node *node)
{
	if (node->left == NULL) {
		drgn_splay_tree_transplant(root, node, node->right);
	} else if (node->right == NULL) {
		drgn_splay_tree_transplant(root, node, node->left);
	} else {
		struct binary_tree_node *successor;

		successor = node->right;
		if (successor->left) {
			do {
				successor = successor->left;
			} while (successor->left);
			drgn_splay_tree_transplant(root, successor, successor->right);
			successor->right = node->right;
			successor->right->parent = successor;
		}
		drgn_splay_tree_transplant(root, node, successor);
		successor->left = node->left;
		successor->left->parent = successor;
	}
	if (node->parent && node->parent->parent)
		drgn_splay_tree_splay(root, node->parent, node->parent->parent);
}
