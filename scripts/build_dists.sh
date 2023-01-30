#!/bin/sh
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux

: "${PYTHON=python3}"
"$PYTHON" setup.py sdist
SDIST=dist/drgn-"$("$PYTHON" setup.py --version)".tar.gz

${DOCKER=docker} run -it \
	--env PLAT=manylinux2014_x86_64 \
	--env SDIST="$SDIST" \
	--env OWNER="$(id -u):$(id -g)" \
	--volume "$(pwd)":/io:ro \
	--volume "$(pwd)/dist":/io/dist \
	--workdir /io \
	--hostname drgn \
	--rm \
	--pull always \
	quay.io/pypa/manylinux2014_x86_64 \
	./scripts/build_manylinux_in_docker.sh "${1:-}"
