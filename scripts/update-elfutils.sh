#!/bin/sh
# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

# drgn depends heavily on elfutils. In particular, we need a recent version,
# potentially with some patches that may not be released or even merged yet. We
# can't depend on the distribution's elfutils package, so instead we include
# our own.
#
# This script imports elfutils from another repository as a subtree. This is
# similar to git-subtree(1), except that we always replace the subtree instead
# of merging it. The upstream commit and additional commit subjects are
# recorded in the commit message. The additional patches are saved in
# elfutils/PATCHES for posterity.
#
# Note that we should strive not to have a hard fork of elfutils; everything in
# here should be on its way upstream, and the patches should be rebased/pruned
# frequently.

set -e

# The upstream elfutils repository. This can be set as an environment variable
# to override the default.
: ${ELFUTILS_REPO:="git://sourceware.org/git/elfutils.git"}
ELFUTILS_PATH=libdrgn/elfutils

if [ $# -ne 1 -a $# -ne 2 ]; then
	echo "usage: $0 repository [refspec]" >&2
	exit 1
fi

GIT_DIR="$(git rev-parse --absolute-git-dir)"
cdup="$(git rev-parse --show-cdup)"
cd "$cdup"

# Fetch the upstream elfutils repository to compare against.
git fetch -- "$ELFUTILS_REPO" master
# Fetch the commit.
git fetch --append -- "$@"
# Now, the first line of FETCH_HEAD is $ELFUTILS_REPO/master and the second
# line is the commit.
commit="$(sed -n '2s/	.*$//p' "$GIT_DIR/FETCH_HEAD")"

# Find which elfutils commit the commit is based on.
if ! base="$(git merge-base FETCH_HEAD "$commit")"; then
	echo "\"$(git rev-list --oneline -1 "$commit")\" is not based on elfutils" >&2
	exit 1
fi

# Import the commit as a subtree.
git rm -q --ignore-unmatch -r "$ELFUTILS_PATH/"
git read-tree -u --prefix="$ELFUTILS_PATH/" "$commit"

# Generate the log file. This is basically git log -p, but with plumbing
# commands so that the format is consistent.
git rev-list "$base".."$commit" | while read -r commit; do
	git diff-tree --pretty=medium -p "$commit"
done > "$ELFUTILS_PATH/PATCHES"
git add "$ELFUTILS_PATH/PATCHES"

# Commit the change.
commit_message="Update elfutils

Based on:

$(git rev-list --oneline -1 "$base")"
if [ "$commit" = "$base" ]; then
	commit_message="$commit_message

With no patches."
else
	commit_message="$commit_message

With the following patches:

$(git rev-list --oneline --reverse "$base".."$commit" |
  cut -d ' ' -f 1 --complement)"
fi
git commit -e -m "$commit_message" "$ELFUTILS_PATH/"
