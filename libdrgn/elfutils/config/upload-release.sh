#!/bin/bash

# Must be run in the source directory.
# Should have passed make distcheck.
# And all final changes should already have been pushed.
# Backup copy will be created in $HOME/elfutils-$VERSION

# Any error is fatal
set -e

# We take one arguent, the version (e.g. 0.173)
if [ $# -ne 1 ]; then
  echo "$0 <version> (e.g. 0.169)"
  exit 1
fi

VERSION="$1"

echo Make sure the git repo is tagged, signed and pushed
echo git tag -s -m \"elfutils $VERSION release\" elfutils-$VERSION
echo git push --tags

# Create a temporary directoy and make sure it is cleaned up.
tempdir=$(mktemp -d) || exit
trap "rm -rf -- ${tempdir}" EXIT

pushd "${tempdir}"

# Checkout
git clone git://sourceware.org/git/elfutils.git
cd elfutils
git tag --verify "elfutils-${VERSION}"
git checkout -b "$VERSION" "elfutils-${VERSION}"

# Create dist
autoreconf -v -f -i
./configure --enable-maintainer-mode
make -j$(nproc) && make dist

# Sign
mkdir $VERSION
cp elfutils-$VERSION.tar.bz2 $VERSION/
cd $VERSION/
gpg -b elfutils-$VERSION.tar.bz2
cd ..

# Backup copy
cp -r $VERSION $HOME/elfutils-$VERSION

# Upload
scp -r $VERSION sourceware.org:/sourceware/ftp/pub/elfutils/
ssh sourceware.org "(cd /sourceware/ftp/pub/elfutils \
  && ln -sf $VERSION/elfutils-$VERSION.tar.bz2 elfutils-latest.tar.bz2 \
  && ln -sf $VERSION/elfutils-$VERSION.tar.bz2.sig elfutils-latest.tar.bz2.sig \
  && ls -lah elfutils-latest*)"

# Cleanup
popd
trap - EXIT
exit
