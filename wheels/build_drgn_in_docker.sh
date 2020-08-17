#!/bin/bash
# Build a drgn wheel - intended to be run within the manylinux2010 docker image.
#
# This script first installs system dependencies. Then it extracts, compiles,
# and installs dependencies. For each specified Python version, we create a
# virtual environment and build a wheel. Finally, for each version, we use the
# auditwheel tool to vendor any non-standard libraries (such as libkdumpfile).
set -x
set -e

TOP=$(pwd)
# Extract env vars which got stuck into the commandline
LIBKDUMPFILE_LOCAL=$TOP/$1
LIBKDUMPFILE=$(echo "$1" | sed 's/\.tar.*//')
GAWK_LOCAL=$TOP/$2
GAWK=$(echo "$2" | sed 's/\.tar.*//')
DRGN_LOCAL=$TOP/$3
DRGN=$(echo "$3" | sed 's/\.tar.*//')
PYTHON_VERSIONS="$4"
OWNER=$5

mkdir -p /tmp/build
cd /tmp/build

# Install dependencies.
yum install -y bzip2-devel lzo-devel snappy-devel xz xz-devel zlib-devel \
	flex bison autoconf automake libtool pkgconfig

# The manylinux image contains an upgraded autotools, but the pkg-config macros
# are not present for this upgraded package.
# https://github.com/pypa/manylinux/issues/731
# Copy them in:
cp /usr/share/aclocal/pkg.m4 /usr/local/share/aclocal-1.16/

# Save original CFLAGS var (although it is probably empty) since we'll be
# mucking with it.
OLD_CFLAGS="$CFLAGS"

# Compile and install libkdumpfile.
tar xf $LIBKDUMPFILE_LOCAL
cd $LIBKDUMPFILE
# In newer zlib, the z_const symbol is defined to const, we provide this here to
# prevent the build from failing.
export CFLAGS="$OLD_CFLAGS -Dz_const=const"
# Since this is not a "release version" of libkdumpfile, we need to generate the
# configure script ourselves.
autoreconf -fiv
./configure --with-lzo --with-snappy --with-zlib --without-python
make -j9
make install
cd ..


# Unfortunately, drgn's build scripts rely on gawk >= 4.0, due to their use of
# BEGINFILE. Thankfully, gawk is pretty fast and easy to compile. We use the
# latest 4.x release here to avoid any incompatibilities with an "overly new"
# version.
tar xf $GAWK_LOCAL
cd $GAWK
export CFLAGS="$OLD_CFLAGS"
./configure
make -j9
make install
cd ..

for pyver in $PYTHON_VERSIONS; do
	if [ "$pyver" -ge "38" ]; then
		verstring=cp$pyver-cp$pyver
	else
		verstring=cp$pyver-cp${pyver}m
	fi
	python=/opt/python/$verstring/bin/python

	# Create a virtual environment in which we will build drgn. Make sure we
	# include the most recent pip and wheel.
	$python -m venv venv$pyver
	source venv$pyver/bin/activate
	pip install --upgrade pip wheel auditwheel

	# For some reason, compile fails on these "static_assert()" calls in
	# drgn. The docker image uses the devtoolset-8, which is sufficiently
	# recent to use the C11 _Static_assert function, so we #define it here.
	export CFLAGS="$OLD_CFLAGS -Dstatic_assert=_Static_assert"

	tar xf $DRGN_LOCAL
	cd $DRGN
	# Finally, do the build!
	python setup.py bdist_wheel --verbose

	# At this point, we've built a linux wheel. To support the full
	# "manylinux2010" standard, we must now run "auditwheel fix", which will
	# vendor in any libraries which the Python standard doesn't mandate to
	# be present. The biggest one here would be the libkdumpfile lib.
	wheelfile=$(ls dist/*.whl | head -n 1)
	auditwheel repair --plat manylinux2010_x86_64 $wheelfile
	finalwheel=$(ls wheelhouse/*.whl | head -n 1)
	finalwheel=$(basename $finalwheel)
	mv wheelhouse/$finalwheel /mnt/io/$finalwheel
	chown $OWNER /mnt/io/$finalwheel

	cd ..
	deactivate
	rm -rf venv$pyver
	rm -rf $DRGN
done
