#!/bin/sh
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: LGPL-2.1-or-later

# Build pahole from the source directory $1 and install it to $2/bin.

set -eux

apt-get update
apt-get install -y --no-install-recommends binutils cmake gcc libc6-dev libdw-dev libelf-dev make zlib1g-dev

cmake -S "$1" -B "$1/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
cmake --build "$1/build" --target pahole -j "$(nproc)"

mkdir -p "$2/bin"
strip -o "$2/bin/pahole" "$1/build/pahole"
"$2/bin/pahole" --version
