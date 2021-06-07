#!/bin/sh

set -eux

# Drop into a shell if something fails.
trap 'if [ $? -ne 0 ]; then exec bash -i; fi' EXIT

yum install -y \
	bzip2-devel \
	libzstd-devel \
	lzo-devel \
	snappy-devel \
	xz-devel \
	zlib-devel

# The manylinux image contains an upgraded autotools in /usr/local, but the
# pkg-config macros are not present for this upgraded package. See
# https://github.com/pypa/manylinux/issues/731.
ln -s /usr/share/aclocal/pkg.m4 /usr/local/share/aclocal/

# Install a recent version of elfutils instead of whatever is in the manylinux
# image.
elfutils_version=0.183
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

libkdumpfile_commit=v0.4.0
libkdumpfile_url=https://github.com/ptesarik/libkdumpfile/archive/$libkdumpfile_commit/libkdumpfile-$libkdumpfile_commit.tar.gz
mkdir /tmp/libkdumpfile
cd /tmp/libkdumpfile
curl -L "$libkdumpfile_url" | tar -xz --strip-components=1
autoreconf -fiv
# z_const was added in zlib 1.2.5.2, but CentOS 6 has 1.2.3.
CPPFLAGS="-Dz_const=const" ./configure --with-lzo --with-snappy --with-zlib --without-python
make -j$(($(nproc) + 1))
make install

ldconfig

mkdir /tmp/drgn
cd /tmp/drgn
tar -xf "/io/$SDIST" --strip-components=1

python_supported() {
	"$1" -c 'import sys; sys.exit(sys.version_info < (3, 6))'
}

for pybin in /opt/python/cp*/bin; do
	if python_supported "$pybin/python"; then
		# static_assert was added to assert.h in glibc 2.16, but CentOS
		# 6 has 2.12.
		CPPFLAGS="-Dstatic_assert=_Static_assert" "$pybin/pip" wheel . --no-deps -w /tmp/wheels/
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
	if python_supported "$pybin/python"; then
		"$pybin/pip" install drgn --no-index -f /tmp/manylinux_wheels/
		"$pybin/drgn" --version
	fi
done

chown "$OWNER" /tmp/manylinux_wheels/*
mv /tmp/manylinux_wheels/* /io/dist/
