#!/bin/sh

set -eux

: "${PYTHON=python3}"
"$PYTHON" setup.py sdist
SDIST=dist/drgn-"$("$PYTHON" setup.py --version)".tar.gz

: "${DOCKER=docker}"
$DOCKER pull quay.io/pypa/manylinux2010_x86_64
$DOCKER run -it \
	--env PLAT=manylinux2010_x86_64 \
	--env SDIST="$SDIST" \
	--env OWNER="$(id -u):$(id -g)" \
	--volume "$(pwd)":/io:ro \
	--volume "$(pwd)/dist":/io/dist \
	--workdir /io \
	--hostname drgn \
	--rm \
	quay.io/pypa/manylinux2010_x86_64 \
	./scripts/build_manylinux_in_docker.sh
