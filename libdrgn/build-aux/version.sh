#!/bin/sh

major="$(sed -rn 's/^#define DRGN_VERSION_MAJOR ([0-9])+$/\1/p' drgn.h.in)"
minor="$(sed -rn 's/^#define DRGN_VERSION_MINOR ([0-9])+$/\1/p' drgn.h.in)"
patch="$(sed -rn 's/^#define DRGN_VERSION_PATCH ([0-9])+$/\1/p' drgn.h.in)"
if [ -z "$major" -o -z "$minor" -o -z "$patch" ]; then
	echo "Could not find version number in drgn.h.in" >&2
	exit 1
fi
echo "$major.$minor.$patch"
