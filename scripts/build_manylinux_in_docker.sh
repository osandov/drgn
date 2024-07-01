#!/bin/sh
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux

# Drop into a shell if something fails.
trap 'if [ $? -ne 0 ]; then exec bash -i; fi' EXIT

sed -i -e 's/mirrorlist/#mirrorlist/g' \
	-e 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' \
	/etc/yum.repos.d/CentOS-*

yum install -y \
	bzip2-devel \
	libzstd-devel \
	lzo-devel \
	snappy-devel \
	xz-devel \
	zlib-devel \
	zstd

# The manylinux image contains an upgraded autotools in /usr/local, but the
# pkg-config macros are not present for this upgraded package. See
# https://github.com/pypa/manylinux/issues/731.
ln -s /usr/share/aclocal/pkg.m4 /usr/local/share/aclocal/

BUILD_ONLY_PYTHON=""
if [ -n "${1:-}" ]; then
	# Translate, e.g. 3.10 -> (3, 10)
	BUILD_ONLY_PYTHON="$(echo "$1" | perl -pe 's/(\d+)\.(\d+)/(\1, \2)/')"
fi

# Install a recent version of elfutils instead of whatever is in the manylinux
# image.
elfutils_version=0.191
elfutils_url=https://sourceware.org/elfutils/ftp/$elfutils_version/elfutils-$elfutils_version.tar.bz2
mkdir /tmp/elfutils
cd /tmp/elfutils
curl -L "$elfutils_url" | tar -xj --strip-components=1
# We don't bother with debuginfod support for a few reasons:
#
# 1. It depends on libcurl, which would pull in a bunch of transitive
#    dependencies.
# 2. libdw loads libdebuginfod with dlopen(), which auditwheel misses.
# 3. drgn hasn't been tested with debuginfod.
./configure --disable-libdebuginfod --disable-debuginfod
make -j$(($(nproc) + 1))
make install

libkdumpfile_version=0.5.4
libkdumpfile_url=https://github.com/ptesarik/libkdumpfile/releases/download/v$libkdumpfile_version/libkdumpfile-$libkdumpfile_version.tar.gz
mkdir /tmp/libkdumpfile
cd /tmp/libkdumpfile
curl -L "$libkdumpfile_url" | tar -xz --strip-components=1
./configure --with-libzstd --with-lzo2 --with-snappy --with-zlib --without-python
make -j$(($(nproc) + 1))
make install

# CentOS 7 has check 0.9.9, which is too old.
check_version=0.15.2
check_url=https://github.com/libcheck/check/releases/download/$check_version/check-$check_version.tar.gz
mkdir /tmp/check
cd /tmp/check
curl -L "$check_url" | tar -xz --strip-components=1
./configure --disable-build-docs
make -j$(($(nproc) + 1))
make install

ldconfig

mkdir /tmp/drgn
cd /tmp/drgn
tar -xf "/io/$SDIST" --strip-components=1

build_for_python() {
	if [ -n "$BUILD_ONLY_PYTHON" ]; then
		# Build for selected Python release only
		"$1" -c "import sys; sys.exit(sys.version_info[:2] != $BUILD_ONLY_PYTHON)"
	else
		# Build for all supported Pythons
		"$1" -c 'import sys; sys.exit(sys.version_info < (3, 6))'
	fi
}

for pybin in /opt/python/cp*/bin; do
	if build_for_python "$pybin/python"; then
		"$pybin/pip" wheel . --no-deps -w /tmp/wheels/
	fi
done

for wheel in /tmp/wheels/*.whl; do
	if auditwheel show "$wheel"; then
		auditwheel repair "$wheel" --plat "$PLAT" -w /tmp/manylinux_wheels/
	else
		echo "Skipping non-platform wheel $wheel"
	fi
done

for pybin in /opt/python/cp*/bin; do
	if build_for_python "$pybin/python"; then
		"$pybin/pip" install drgn --no-index -f /tmp/manylinux_wheels/
		"$pybin/drgn" --version
		"$pybin/pip" install pytest
		"$pybin/pytest"
	fi
done

if [ "${OWNER+set}" = set ]; then
	chown "$OWNER" /tmp/manylinux_wheels/*
fi
mv /tmp/manylinux_wheels/* /io/dist/
