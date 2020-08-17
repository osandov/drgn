#!/bin/bash
# Build a drgn wheel for the manylinux2010 platform.
#
# This script simply prepares sources and then executes a script within the
# "manylinux" docker image to actually build the necessary components.

if [ -z "$1" ]; then
	echo "usage: ./build_drgn.sh PYSHORTVER"
	echo "PYSHORTVER may be, e.g.: 36, 37, 38, 39"
	echo "PYSHORTVER may contain multiple versions; they must be quoted:"
	echo " e.g.: ./build_drgn.sh \"36 37 38\""
	exit 1
fi

set -x
set -e

PYTHON_VERSIONS="$1"

LIBKDUMPFILE_COMMIT=a83a6e528a779a8b85f55a12e6488b48f13d9abd
LIBKDUMPFILE=libkdumpfile-$LIBKDUMPFILE_COMMIT
LIBKDUMPFILEF=$LIBKDUMPFILE.tar.gz
LIBKDUMPFILE_URL=https://github.com/ptesarik/libkdumpfile/archive/$LIBKDUMPFILE_COMMIT/$LIBKDUMPFILEF
LIBKDUMPFILE_LOCAL=$LIBKDUMPFILEF
if [ ! -f "$LIBKDUMPFILE_LOCAL" ]; then
	curl -L "$LIBKDUMPFILE_URL" -o "$LIBKDUMPFILE_LOCAL"
fi
LIBKDUMPFILE_SHA256=51e269f96a0cec43b7bc91b15fd97cacde33e5f26dcedf2ddaf138def2d49bef
echo "$LIBKDUMPFILE_SHA256 $LIBKDUMPFILE_LOCAL" | sha256sum -c -

# See build_drgn_in_docker.sh for details on why this is necessary :/
GAWK=gawk-4.2.1
GAWKF=$GAWK.tar.xz
GAWK_URL=https://ftp.gnu.org/gnu/gawk/$GAWKF
GAWK_LOCAL=$GAWKF
if [ ! -f "$GAWK_LOCAL" ]; then
	curl "$GAWK_URL" -o "$GAWK_LOCAL"
fi
GAWK_SHA256=d1119785e746d46a8209d28b2de404a57f983aa48670f4e225531d3bdc175551
echo "$GAWK_SHA256 $GAWK_LOCAL" | sha256sum -c -

# Use the "sdist" created by setup.py
pushd ..
DRGN=drgn-$(./setup.py --version)
DRGNF=$DRGN.tar.gz
if [ ! -f "dist/$DRGNF" ]; then
	./setup.py sdist
fi
popd
cp ../dist/$DRGNF .
DRGN_LOCAL=$DRGNF

# Allow users to do DOCKER="sudo docker" ./build_drgn.sh if necessary.
DOCKER=${DOCKER:-docker}
$DOCKER pull quay.io/pypa/manylinux2010_x86_64
$DOCKER run -it \
	-v $(pwd):/mnt/io \
	-h DOCKER \
	-w /mnt/io \
	--rm \
	quay.io/pypa/manylinux2010_x86_64 \
	./build_drgn_in_docker.sh \
	$LIBKDUMPFILE_LOCAL \
	$GAWK_LOCAL \
	$DRGN_LOCAL \
	"$PYTHON_VERSIONS" \
	"$(id -u):$(id -g)"
